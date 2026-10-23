"""Test host maintenance windows (docs/SVS_RUNS.md, *Maintenance windows*).

A launcher opens a window on a test host before it stages a test's prerequisites or updates its own
bundle there, and ends it afterwards; the timers expire a window it never ends. A window and a run
never hold one host at once (saq.svs.runs.host_holders), so what happens in a window is nobody's
test. An alert without a marker that involves the host, with its event time inside the window, is
routed to the test queue by the svs_marker router, which records it in svs_maintenance_alerts and
confirms it on the alert's last pass; the timers then close it as IGNORE, with a comment
naming the window. It is kept, never dropped. An alert with a marker is judged as any other, so a
marker mismatch stays in triage.

Opening, ending and expiring a window are AUDIT records, and each alert closed for one is an INFO
record with the window's id (svs_maintenance).
"""

import logging
import uuid
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import exists, or_, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.configuration.config import get_config
from saq.constants import DISPOSITION_IGNORE, DISPOSITION_OPEN
from saq.database.model import Alert, SVSAttribution, SVSMaintenanceAlert, SVSMaintenanceWindow, SVSTestHost
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import set_dispositions
from saq.error.reporting import log_loop_exception
from saq.svs.hosts import InvalidTestHost, get_host, match_target, split_hostname
from saq.svs.refusals import Caller, refuse
from saq.svs.runs import TIMER_ACTOR, HostBusy, host_holders, lock_hosts

# how many windows one timer pass expires, and how many alerts it closes, at most; the next pass
# does the rest
EXPIRE_BATCH = 500
CLOSE_ALERTS_BATCH = 1000

END_REASON_ENDED = "ended"
END_REASON_EXPIRED = "expired"


class UnknownMaintenance(LookupError):
    """No test host has that id, or the host has no open window."""


class InvalidMaintenance(ValueError):
    """The request can't be accepted as sent; the message says why."""


class MaintenanceRefused(PermissionError):
    """The host is not a test host. Recorded and alerted like a refused registration."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reasons = [reason]


def _log_fields(window: SVSMaintenanceWindow) -> dict:
    return {"svs_maintenance": window.uuid, "host": window.host, "reason": window.reason}


def _audit(message: str, window: SVSMaintenanceWindow, actor: str, **fields) -> None:
    logging.info("AUDIT: %s: %s on test host %s by %s", message, window.uuid, window.host, actor,
                 extra={**_log_fields(window), "actor": actor, "opened_at": window.opened_at.isoformat(),
                        "ends_at": window.ends_at.isoformat(), **fields})


def _resolve(host_ref: str, caller: Caller, what: str, payload: dict, now: datetime) -> SVSTestHost:
    """The test host host_ref names: its id, or its short or fully qualified name. A name that is
    not a test host's is refused and alerts, as a registration against it would (saq.svs.refusals).
    Raises UnknownMaintenance for an unknown id, MaintenanceRefused."""
    host_ref = host_ref.strip()
    if host_ref.isdigit():
        try:
            return get_host(int(host_ref))
        except LookupError:
            raise UnknownMaintenance(f"test host {host_ref} not found") from None

    # a host that lists its users matches without one: a window is on the host, not a user
    match = match_target(host_ref)
    if match.host is not None:
        return match.host

    refuse(caller, host_ref, None, f"{what}: {match.reason}", payload=payload, now=now)
    raise MaintenanceRefused(match.reason)


def open_window(host_ref: str, minutes: int, reason: str, caller: Caller,
                now: Optional[datetime] = None) -> SVSMaintenanceWindow:
    """Opens a maintenance window on a test host for minutes, up to svs.runs.max_maintenance_minutes.
    Raises InvalidMaintenance, UnknownMaintenance, MaintenanceRefused, and HostBusy when a run or
    another window holds the host."""
    # stored to the second; a window that starts at the whole second never starts after the call
    now = (now or datetime.now()).replace(microsecond=0)
    reason = (reason or "").strip()
    cap = get_config().svs.runs.max_maintenance_minutes
    if not reason:
        raise InvalidMaintenance("a maintenance window needs a reason")
    if not isinstance(minutes, int) or not 1 <= minutes <= cap:
        raise InvalidMaintenance(f"minutes must be from 1 to {cap} (svs.runs.max_maintenance_minutes)")

    host = _resolve(host_ref, caller, "maintenance window refused",
                    {"maintenance": {"host": host_ref, "minutes": minutes, "reason": reason}}, now)

    db = get_db()
    lock_hosts([host.id])
    busy = host_holders([host.hostname], now)
    if busy:
        db.rollback()
        logging.info("svs maintenance window on test host %s refused: %s", host.hostname, "; ".join(
            holder.run_uuid or holder.maintenance_uuid for holder in busy),
            extra={"host": host.hostname, "caller": caller.name,
                   "holding_runs": [holder.run_uuid for holder in busy if holder.run_uuid],
                   "holding_maintenance": [holder.maintenance_uuid for holder in busy if holder.maintenance_uuid]})
        raise HostBusy(busy)

    window = SVSMaintenanceWindow(
        uuid=str(uuid.uuid4()), test_host_id=host.id, host=host.hostname, fqdn=host.fqdn, reason=reason,
        opened_by=caller.name[:256], opened_by_user_id=caller.user_id, opened_at=now,
        ends_at=now + timedelta(minutes=minutes))
    db.add(window)
    db.commit()
    _audit("svs maintenance window opened", window, caller.name, minutes=minutes, caller_address=caller.address)
    return window


def end_window(host_ref: str, caller: Caller, now: Optional[datetime] = None) -> SVSMaintenanceWindow:
    """Ends the test host's open maintenance window now. Raises UnknownMaintenance (no such host,
    or no open window), MaintenanceRefused."""
    now = now or datetime.now()
    host = _resolve(host_ref, caller, "maintenance window end refused", {"maintenance": {"host": host_ref}}, now)

    db = get_db()
    window = db.execute(
        select(SVSMaintenanceWindow)
        .where(SVSMaintenanceWindow.host == host.hostname, SVSMaintenanceWindow.ended_at.is_(None),
               SVSMaintenanceWindow.ends_at >= now)
        .order_by(SVSMaintenanceWindow.id)
        .with_for_update()).scalars().first()
    if window is None:
        db.rollback()
        raise UnknownMaintenance(f"test host {host.hostname} has no open maintenance window")

    _end(window, caller.name, now)
    db.commit()
    _audit("svs maintenance window ended", window, caller.name, ended_at=window.ended_at.isoformat())
    return window


def _end(window: SVSMaintenanceWindow, actor: str, now: datetime) -> None:
    """Ends the window early, at now."""
    # stored to the second, as open_window does: MySQL rounds, which could end it after now
    window.ended_at = now.replace(microsecond=0)
    window.ended_by = actor[:256]
    window.end_reason = END_REASON_ENDED


@contextmanager
def ending_host_windows(host: SVSTestHost, actor: str, now: Optional[datetime] = None) -> Iterator[list[SVSMaintenanceWindow]]:
    """Ends the test host's open windows on the caller's session, for hosts.delete_host, which
    removes the host and commits inside the block while it holds the host's row lock. A window
    outliving its host would go on closing the alerts of a host nobody tests, and nothing could end
    it (end_window refuses a host that is not a test host). The windows are audited once the block
    leaves without an exception."""
    now = now or datetime.now()
    db = get_db()
    windows = list(db.execute(
        select(SVSMaintenanceWindow)
        .where(SVSMaintenanceWindow.test_host_id == host.id, SVSMaintenanceWindow.ended_at.is_(None),
               SVSMaintenanceWindow.ends_at >= now)
        .order_by(SVSMaintenanceWindow.id)
        .with_for_update()).scalars())
    for window in windows:
        _end(window, actor, now)
    yield windows
    for window in windows:
        _audit("svs maintenance window ended", window, actor, ended_at=window.ended_at.isoformat(),
               ended_because="test host removed")


def list_windows(host_ref: str, limit: int, before_id: Optional[int] = None) -> list[SVSMaintenanceWindow]:
    """The test host's windows, latest first, those with an id below before_id. Raises
    UnknownMaintenance for a host that is not a test host (reading never alerts)."""
    host_ref = host_ref.strip()
    if host_ref.isdigit():
        try:
            hostname = get_host(int(host_ref)).hostname
        except LookupError:
            raise UnknownMaintenance(f"test host {host_ref} not found") from None
    else:
        try:
            hostname = split_hostname(host_ref)[0]
        except InvalidTestHost:
            raise UnknownMaintenance(f"{host_ref!r} is not a host name") from None
    statement = select(SVSMaintenanceWindow).where(SVSMaintenanceWindow.host == hostname)
    if before_id is not None:
        statement = statement.where(SVSMaintenanceWindow.id < before_id)
    return list(get_db().execute(statement.order_by(SVSMaintenanceWindow.id.desc()).limit(limit)).scalars())


#
# the router's records
#

def record_alert(alert_uuid: str, window_id: Optional[int], *, confirmed: bool, now: Optional[datetime] = None) -> None:
    """Brings the alert's maintenance record in line with the router's judgement: recorded for the
    window (window_id) while it is judged maintenance (confirmed on the alert's last pass, after
    which the timers may close it), else (None) removed so the timers leave it alone. A record the timers closed is never
    changed."""
    now = now or datetime.now()
    with private_transaction() as session:
        if window_id is None:
            removed = session.execute(
                update(SVSMaintenanceAlert)
                .where(SVSMaintenanceAlert.alert_uuid == alert_uuid, SVSMaintenanceAlert.removed_at.is_(None),
                       SVSMaintenanceAlert.closed_at.is_(None))
                .values(removed_at=now)).rowcount
            if removed:
                logging.info("svs alert %s is no longer in a maintenance window", alert_uuid,
                             extra={"alert_uuid": alert_uuid})
            return

        session.execute(mysql_insert(SVSMaintenanceAlert).prefix_with("IGNORE").values(
            window_id=window_id, alert_uuid=alert_uuid, created_at=now))
        values = {"removed_at": None}
        if confirmed:
            values["confirmed_at"] = now
        session.execute(
            update(SVSMaintenanceAlert)
            .where(SVSMaintenanceAlert.window_id == window_id, SVSMaintenanceAlert.alert_uuid == alert_uuid,
                   SVSMaintenanceAlert.closed_at.is_(None),
                   or_(SVSMaintenanceAlert.confirmed_at.is_(None), SVSMaintenanceAlert.removed_at.isnot(None)))
            .values(**values))


#
# the timers (service_svs, on the primary node)
#

def expire_windows(now: Optional[datetime] = None) -> int:
    """Ends the windows whose time has passed. Returns how many."""
    now = now or datetime.now()
    db = get_db()
    count = 0
    for window in db.execute(
            select(SVSMaintenanceWindow)
            .where(SVSMaintenanceWindow.ended_at.is_(None), SVSMaintenanceWindow.ends_at < now)
            .order_by(SVSMaintenanceWindow.id).limit(EXPIRE_BATCH)).scalars().all():
        # conditional: a call ending it meanwhile wins
        if db.execute(
                update(SVSMaintenanceWindow)
                .where(SVSMaintenanceWindow.id == window.id, SVSMaintenanceWindow.ended_at.is_(None))
                .values(ended_at=window.ends_at, ended_by=TIMER_ACTOR, end_reason=END_REASON_EXPIRED)
                .execution_options(synchronize_session=False)).rowcount != 1:
            db.rollback()
            continue
        db.commit()
        count += 1
        _audit("svs maintenance window expired", window, TIMER_ACTOR)
    return count


def close_alerts() -> int:
    """Closes, as IGNORE, the open alerts nobody has taken that the router confirmed for a
    maintenance window. An alert an analyst took, dispositioned or associated with a run meanwhile
    is left alone. Either way its record is closed, so it isn't looked at again. Returns how many alerts it closed."""
    db = get_db()
    automation_user_id = get_config().global_settings.automation_user_id
    rows = db.execute(
        select(SVSMaintenanceAlert.id, SVSMaintenanceAlert.alert_uuid, SVSMaintenanceWindow)
        .join(SVSMaintenanceWindow, SVSMaintenanceWindow.id == SVSMaintenanceAlert.window_id)
        .join(Alert, Alert.uuid == SVSMaintenanceAlert.alert_uuid)
        .where(SVSMaintenanceAlert.confirmed_at.isnot(None), SVSMaintenanceAlert.removed_at.is_(None),
               SVSMaintenanceAlert.closed_at.is_(None))
        .order_by(SVSMaintenanceAlert.id)
        .limit(CLOSE_ALERTS_BATCH)).all()

    windows: dict[int, SVSMaintenanceWindow] = {}
    records: dict[int, list[tuple[int, str]]] = defaultdict(list)
    for row_id, alert_uuid, window in rows:
        windows[window.id] = window
        records[window.id].append((row_id, alert_uuid))

    count = 0
    for window_id, window in windows.items():
        try:
            count += _close_window_alerts(window, records[window_id], automation_user_id)
        except Exception as e:
            db.rollback()
            log_loop_exception(e, f"unable to close the alerts of svs maintenance window {window.uuid}")
    return count


def _still_in_maintenance(alert_uuids: list[str]) -> set[str]:
    """Those of the alerts whose record still stands (confirmed, neither removed nor closed) and
    that no person associated with a run. A private transaction, so it reads what is committed now:
    set_dispositions calls it under the alerts' row locks, which associating takes too."""
    with private_transaction() as session:
        return set(session.execute(
            select(SVSMaintenanceAlert.alert_uuid)
            .where(SVSMaintenanceAlert.alert_uuid.in_(alert_uuids), SVSMaintenanceAlert.confirmed_at.isnot(None),
                   SVSMaintenanceAlert.removed_at.is_(None), SVSMaintenanceAlert.closed_at.is_(None),
                   ~exists().where(SVSAttribution.alert_uuid == SVSMaintenanceAlert.alert_uuid,
                                   SVSAttribution.removed_at.is_(None)))).scalars())


def _close_window_alerts(window: SVSMaintenanceWindow, records: list[tuple[int, str]], automation_user_id) -> int:
    db = get_db()
    alert_uuids = [alert_uuid for _, alert_uuid in records]
    result = set_dispositions(
        alert_uuids, DISPOSITION_IGNORE, automation_user_id, system=True,
        expected_dispositions={DISPOSITION_OPEN}, eligible=_still_in_maintenance,
        user_comment=f"closed: SVS maintenance window {window.uuid} on test host {window.host}: {window.reason}")
    closed = result.permitted

    # a record the router removed meanwhile stays open to it
    db.execute(update(SVSMaintenanceAlert)
               .where(SVSMaintenanceAlert.id.in_([row_id for row_id, _ in records]),
                      SVSMaintenanceAlert.removed_at.is_(None))
               .values(closed_at=datetime.now()))
    db.commit()

    for alert_uuid in closed:
        logging.info("svs maintenance window %s: alert %s closed as %s", window.uuid, alert_uuid, DISPOSITION_IGNORE,
                     extra={**_log_fields(window), "alert_uuid": alert_uuid})
    left_alone = sorted(set(result.skipped) | set(result.unexpected) | set(result.ineligible))
    if left_alone:
        logging.info("svs maintenance window %s: %d alerts left alone (taken, dispositioned or associated with a "
                     "run by an analyst, or no longer judged maintenance)", window.uuid, len(left_alone),
                     extra={**_log_fields(window), "alert_uuids": left_alone})
    return len(closed)


def run_timers(now: Optional[datetime] = None) -> tuple[int, int]:
    """Expires the windows whose time has passed and closes their confirmed alerts. Returns how many
    of each."""
    return expire_windows(now), close_alerts()
