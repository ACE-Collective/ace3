"""SVS test hosts service for ACE API v2 (docs/SVS_RUNS.md, *Test hosts*; docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread. saq.svs.hosts owns the table
and its normalization, and saq.svs.maintenance the hosts' maintenance windows; this pages them and
maps their errors to HTTP.
"""

from datetime import datetime
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import decode_cursor, encode_cursor, rows_to_csv
from aceapi_v2.svs.preconditions import stale_write
from aceapi_v2.svs.runs.service import host_busy_error
from aceapi_v2.svs.test_hosts.schemas import (
    TEST_HOST_CSV_FIELDS,
    MaintenancePage,
    MaintenanceRequest,
    MaintenanceWindow,
    TestHost,
    TestHostRequest,
)
from saq.database.model import SVSMaintenanceWindow, SVSTestHost, User
from saq.database.pool import get_db
from saq.svs import hosts, maintenance
from saq.svs.refusals import Caller
from saq.svs.runs import HostBusy
from saq.svs.preconditions import NONE, Precondition, StaleWrite
from saq.svs.samples import to_utc_naive


def _row(host: SVSTestHost, username: Optional[str]) -> TestHost:
    return TestHost(
        id=host.id, hostname=host.hostname, fqdn=host.fqdn, usernames=hosts.host_usernames(host),
        ips=hosts.host_ips(host), platform=host.platform, notes=host.notes, created_by=username,
        created_at=host.created_at, updated_at=host.updated_at)


def _username(host: SVSTestHost) -> Optional[str]:
    return host.created_by_user.username if host.created_by_user is not None else None


def _parse_key(payload: dict) -> str:
    (hostname,) = payload["k"]
    return str(hostname)


def fetch_page(changed_since: datetime | None, cursor: str | None, limit: int) -> tuple[list[TestHost], str | None]:
    """One page of the test hosts in hostname order after `cursor`, and the next page's cursor.
    Raises InvalidCursor."""
    statement = select(SVSTestHost, User.username).outerjoin(User, User.id == SVSTestHost.created_by)
    if changed_since is not None:
        statement = statement.where(SVSTestHost.updated_at >= to_utc_naive(changed_since))
    if cursor is not None:
        statement = statement.where(SVSTestHost.hostname > decode_cursor(cursor, _parse_key))

    rows = get_db().execute(statement.order_by(SVSTestHost.hostname).limit(limit + 1)).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(k=[rows[-1][0].hostname])

    return [_row(host, username) for host, username in rows], next_cursor


def hosts_to_csv(rows: list[TestHost], *, header: bool) -> str:
    def flatten(values: dict) -> None:
        values["usernames"] = ",".join(values["usernames"])
        values["ips"] = ",".join(values["ips"])

    return rows_to_csv(rows, TEST_HOST_CSV_FIELDS, header=header, flatten=flatten)


def get_test_host(host_id: int) -> TestHost:
    try:
        host = hosts.get_host(host_id)
    except hosts.UnknownTestHost as e:
        raise HTTPException(status_code=404, detail=str(e))
    return _row(host, _username(host))


def _spec(body: TestHostRequest) -> hosts.HostSpec:
    try:
        return hosts.build_spec(body.hostname, fqdn=body.fqdn, usernames=body.usernames, ips=body.ips,
                                platform=body.platform, notes=body.notes)
    except hosts.InvalidTestHost as e:
        raise HTTPException(status_code=422, detail=str(e))


def create_test_host(body: TestHostRequest, auth: ApiAuthResult) -> TestHost:
    spec = _spec(body)
    try:
        host = hosts.create_host(spec, auth)
    except hosts.DuplicateTestHost as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _row(host, _username(host))


def _current_host(host_id: int) -> Optional[TestHost]:
    try:
        host = hosts.get_host(host_id)
    except hosts.UnknownTestHost:
        return None
    return _row(host, _username(host))


def update_test_host(host_id: int, body: TestHostRequest, auth: ApiAuthResult,
                     precondition: Precondition = NONE) -> TestHost:
    spec = _spec(body)
    try:
        host = hosts.update_host(host_id, spec, auth, precondition)
    except hosts.UnknownTestHost as e:
        raise HTTPException(status_code=404, detail=str(e))
    except StaleWrite as e:
        raise stale_write(e, lambda: _current_host(host_id))
    except hosts.DuplicateTestHost as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _row(host, _username(host))


def delete_test_host(host_id: int, auth: ApiAuthResult) -> None:
    try:
        hosts.delete_host(host_id, auth)
    except hosts.UnknownTestHost as e:
        raise HTTPException(status_code=404, detail=str(e))


#
# maintenance windows
#

def _window(window: SVSMaintenanceWindow) -> MaintenanceWindow:
    return MaintenanceWindow(
        id=window.uuid, host=window.host, fqdn=window.fqdn, reason=window.reason, opened_by=window.opened_by,
        opened_at=window.opened_at, ends_at=window.ends_at, ended_at=window.ended_at, ended_by=window.ended_by,
        end_reason=window.end_reason, open=window.ended_at is None and window.ends_at >= datetime.now())


def _maintenance(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except maintenance.MaintenanceRefused as e:
        raise HTTPException(status_code=403, detail={"message": "maintenance window refused", "reasons": e.reasons})
    except maintenance.UnknownMaintenance as e:
        raise HTTPException(status_code=404, detail=str(e))
    except maintenance.InvalidMaintenance as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HostBusy as e:
        raise host_busy_error(e)


def open_maintenance(host: str, body: MaintenanceRequest, caller: Caller) -> MaintenanceWindow:
    return _window(_maintenance(maintenance.open_window, host, body.minutes, body.reason, caller))


def end_maintenance(host: str, caller: Caller) -> MaintenanceWindow:
    return _window(_maintenance(maintenance.end_window, host, caller))


def _parse_window_key(payload: dict) -> int:
    (window_id,) = payload["k"]
    return int(window_id)


def list_maintenance(host: str, cursor: str | None, limit: int) -> MaintenancePage:
    """The test host's windows, latest first. Raises InvalidCursor."""
    before_id = decode_cursor(cursor, _parse_window_key) if cursor is not None else None
    rows = _maintenance(maintenance.list_windows, host, limit + 1, before_id)
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(k=[rows[-1].id])
    return MaintenancePage(data=[_window(row) for row in rows], next_cursor=next_cursor)
