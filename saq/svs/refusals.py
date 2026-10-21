"""Refused run registrations (docs/SVS_RUNS.md, *Refused registrations*).

A registration that targets a host which is not a test host, or a user the host doesn't list, is
refused with 403 and creates an alert in the default queue, through the normal submission path,
with the SVS_REGISTRATION_REFUSED built-in detection and the caller's identity as observables
[ART-9]. A launcher retrying in a loop must not flood the queue, so refusals are collapsed to one
alert per (caller, host) per hour: svs_registration_refusals has one row per (caller, host, hour),
and only the request that inserts it creates the alert, which holds across API workers. Every
refusal, the first or not, is logged at WARNING [FR-15].

The table is written here only.
"""

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_HOSTNAME, F_IPV4, F_USER, QUEUE_DEFAULT
from saq.database.model import SVSRegistrationRefusal
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.environment import get_local_timezone
from saq.signatures.builtin import SVS_REGISTRATION_REFUSED, get_builtin_signature_version
from saq.svs.hosts import InvalidTestHost, split_hostname
from saq.util.uuid import storage_dir_from_uuid

ALERT_TYPE = "svs - registration refused"
TOOL = "svs"

# refusal rows are only needed for the hour they collapse; older ones are pruned by the run timer
RETENTION = timedelta(days=1)

# the columns' sizes
MAX_CALLER = 256
MAX_HOST = 255


@dataclass(frozen=True)
class Caller:
    """Who called the run API: the user or API key, and where from."""

    name: str
    user_id: Optional[int] = None
    key_id: Optional[int] = None
    address: Optional[str] = None


def _host_key(hostname: str) -> str:
    """The refused host as the caller named it, normalized: its fully qualified name when it has one.
    Not the short name a test host matches on: a production host that shares a test host's short
    name in another domain is another host, and gets its own alert."""
    try:
        short, fqdn = split_hostname(hostname)
        return (fqdn or short)[:MAX_HOST]
    except InvalidTestHost:
        return (hostname or "").strip().lower()[:MAX_HOST]


def _is_ipv4(value: Optional[str]) -> bool:
    try:
        return value is not None and ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def _create_alert(caller: Caller, hostname: str, username: Optional[str], reason: str, launcher: Optional[str],
                  test_guid: Optional[str], payload: dict) -> str:
    """Creates the refusal alert and returns its uuid."""
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=storage_dir_from_uuid(root_uuid),
        desc=f"SVS test run registration refused: {caller.name} targeted {hostname}",
        analysis_mode=ANALYSIS_MODE_CORRELATION,
        tool=TOOL,
        tool_instance=get_config().global_settings.instance_name,
        alert_type=ALERT_TYPE,
        event_time=get_local_timezone().localize(datetime.now()),
        queue=QUEUE_DEFAULT,
        details={
            "reason": reason,
            "caller": caller.name,
            "caller_key_id": caller.key_id,
            "caller_address": caller.address,
            "launcher": launcher,
            "test_guid": test_guid,
            "request": payload,
        })
    root.initialize_storage()

    root.add_observable_by_spec(F_HOSTNAME, hostname)
    if username:
        root.add_observable_by_spec(F_USER, username)
    root.add_observable_by_spec(F_USER, caller.name)
    if _is_ipv4(caller.address):
        root.add_observable_by_spec(F_IPV4, caller.address)

    root.add_detection_point(
        f"SVS test run registration refused: {reason}",
        signature_uuid=SVS_REGISTRATION_REFUSED.uuid,
        signature_version=get_builtin_signature_version())

    root.save()
    ALERT(root)
    root.schedule()
    return root_uuid


def refuse(caller: Caller, hostname: str, username: Optional[str], reason: str, *, launcher: Optional[str] = None,
           test_guid: Optional[str] = None, payload: Optional[dict] = None, now: Optional[datetime] = None) -> Optional[str]:
    """Records a refused target and, for the first refusal of (caller, host) in this hour, creates
    the alert. Returns the alert's uuid when this call created one. Never raises for a failure to
    create the alert: the registration is refused either way."""
    now = now or datetime.now()
    hour = now.replace(minute=0, second=0, microsecond=0)
    host = _host_key(hostname)
    caller_key = caller.name[:MAX_CALLER]
    extra = {"caller": caller.name, "caller_address": caller.address, "host": host, "username": username,
             "reason": reason, "launcher": launcher, "svs_test": test_guid}

    db = get_db()
    row = SVSRegistrationRefusal(caller=caller_key, host=host, hour=hour, count=1, first_at=now, last_at=now)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        # another refusal of (caller, host) this hour already alerted
        db.rollback()
        db.execute(
            update(SVSRegistrationRefusal)
            .where(SVSRegistrationRefusal.caller == caller_key,
                   SVSRegistrationRefusal.host == host,
                   SVSRegistrationRefusal.hour == hour)
            .values(count=SVSRegistrationRefusal.count + 1, last_at=now))
        db.commit()
        logging.warning("svs run registration refused: %s targeted %s (%s); already alerted this hour",
                        caller.name, hostname, reason, extra={**extra, "alerted": False})
        return None

    alert_uuid = None
    try:
        alert_uuid = _create_alert(caller, hostname, username, reason, launcher, test_guid, payload or {})
    except Exception as e:
        logging.exception("unable to create the alert for a refused svs run registration by %s: %s", caller.name, e)
        db.rollback()

    if alert_uuid is not None:
        db.execute(
            update(SVSRegistrationRefusal)
            .where(SVSRegistrationRefusal.id == row.id)
            .values(alert_uuid=alert_uuid))
        db.commit()

    logging.warning("svs run registration refused: %s targeted %s (%s)", caller.name, hostname, reason,
                    extra={**extra, "alerted": alert_uuid is not None, "alert_uuid": alert_uuid})
    return alert_uuid


def prune_refusals(now: Optional[datetime] = None) -> int:
    """Removes refusal rows older than RETENTION. Returns how many."""
    cutoff = (now or datetime.now()) - RETENTION
    db = get_db()
    result = db.execute(delete(SVSRegistrationRefusal).where(SVSRegistrationRefusal.hour < cutoff))
    db.commit()
    return result.rowcount
