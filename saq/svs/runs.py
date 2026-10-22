"""SVS test runs (docs/SVS_RUNS.md): registration, the launcher's lifecycle calls and the timers.

A launcher outside ACE registers a run for one catalog test against one or more test hosts, gets
its marker, starts it, may report how the test executed, and may cancel it. service_svs moves runs
on by time: a run never started goes to Error and is closed, a started run ends when its
observation window passes, and a canceled or failed run is closed when its attribution window
passes. An Ended run waits for a person.

Every state change is a conditional update on the state the caller saw (`… WHERE id=? AND
state=?`), so a timer firing twice, or a launcher call racing a timer, changes the run once
[FR-13]. Each one appends a row to the run's event log in the same transaction, and every log
record carries the run's svs_run, svs_test and svs_marker fields (docs/SVS.md, *Logging contract*).

Closing a run gives its fully attributed alerts the disposition SIMULATED, and the timers close
the alerts attributed to a closed run afterwards the same way.

A run holds its test hosts from registration until its claim on them ends, and registration and
start refuse a host another run holds, so context attribution never has two runs to choose from
(host_holders).

A launcher can also validate a registration: decide() works out everything registering would
decide, and only reads, so a dry run creates no run, refusal or alert.

A person cancels and closes runs through saq/svs/review.py, which also takes runs and reviews them.

svs_runs, svs_run_targets and svs_run_events are written here, except for what attribution writes
(saq/svs/attribution.py: its own events, and the changed-since-review flag of a reviewed run), what
a person's association changes write (saq/svs/association.py), and ownership and review
(saq/svs/review.py).
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy import and_, case, null, or_, select, update

from saq.configuration.config import get_config
from saq.constants import DISPOSITION_OPEN, DISPOSITION_SIMULATED
from saq.database.model import Alert, SVSAttribution, SVSCatalogTest, SVSRun, SVSRunTarget, SVSTestHost
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import set_dispositions
from saq.error.reporting import log_loop_exception
from saq.svs.alert_status import fully_attributed_condition
from saq.svs.catalog import platform_slugs, supported_platforms
from saq.svs.expectations import observation_for_test, test_holds_host
from saq.svs.constants import ObservationSource, RunEventKind, RunState
from saq.svs.hosts import InvalidTestHost, TargetMatch, match_target, normalize_username, split_hostname
from saq.svs.markers import new_marker
from saq.svs.refusals import Caller, prune_refusals, refuse
from saq.svs.result_state import mark_runs_stale
from saq.svs.results import compute_result, recompute_stale_results
from saq.svs.run_events import new_run_event, run_log_fields
from saq.svs.windows import attribution_window

# the actor of a timer's transitions
TIMER_ACTOR = "svs"

# how many runs one timer pass moves per kind of transition
TIMER_BATCH = 500

# how many alerts closing a run, or one pass of the late-alert sweep, closes at most; the next pass
# closes the rest
CLOSE_ALERTS_BATCH = 1000

CLOSE_REASON_START_TIMEOUT = "start timeout"
CLOSE_REASON_CANCELED_BEFORE_START = "canceled before start"
CLOSE_REASON_ATTRIBUTION_ENDED = "attribution window ended"
CLOSE_REASON_BY_PERSON = "closed by hand"

# the launcher's calls, as they are logged and recorded
CALL_REGISTER = "register"
CALL_VALIDATE = "validate"
CALL_START = "start"
CALL_EXECUTED = "executed"
CALL_CLEANUP = "cleanup"
CALL_CANCEL = "cancel"

# the outcome of a registration or start refused because another run holds a target's host
OUTCOME_HOST_BUSY = "host busy"


class InvalidRegistration(ValueError):
    """The registration can't be accepted as sent; the message says why."""


class RegistrationRefused(PermissionError):
    """A target is not a test host, or not a user the host lists. Each refused target is recorded
    (saq.svs.refusals)."""

    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


class UnknownRun(LookupError):
    pass


@dataclass(frozen=True)
class HostHolder:
    """A run holding a test host: registered and not started, or started and inside its claim on the
    host (docs/SVS_RUNS.md, *One run per test host*)."""
    host: str
    run_uuid: str
    state: str
    # when its claim ends, None while it hasn't started
    until: Optional[datetime]


class HostBusy(Exception):
    """A target's test host is held by another run. A lifecycle conflict, not a refusal: nothing
    alerts."""

    def __init__(self, holders: list[HostHolder]):
        super().__init__("; ".join(
            f"test host {holder.host} is held by run {holder.run_uuid} ({holder.state}"
            + (f", until {holder.until}" if holder.until is not None else ", not started") + ")"
            for holder in holders))
        self.holders = holders


class ReasonRequired(ValueError):
    """Closing an ended run needs a reason."""


class RunStateConflict(Exception):
    """The run is not in a state the call applies to."""

    def __init__(self, run_uuid: str, state: str, call: str):
        super().__init__(f"run {run_uuid} is {state}; {call} does not apply")
        self.run_uuid = run_uuid
        self.state = state
        self.call = call


@dataclass(frozen=True)
class TargetSpec:
    hostname: str
    username: Optional[str] = None


@dataclass
class Registration:
    test_guid: str
    targets: list[TargetSpec]
    launcher: str
    batch_id: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict:
        return {
            "test_guid": self.test_guid,
            "targets": [{"hostname": t.hostname, "username": t.username} for t in self.targets],
            "launcher": self.launcher,
            "batch_id": self.batch_id,
            "extra": self.extra,
        }


#
# logging and the event log
#

def _add_event(run: SVSRun, kind: RunEventKind, actor: str, *, actor_user_id: Optional[int] = None,
               from_state: Optional[str] = None, to_state: Optional[str] = None, details: Optional[dict] = None,
               now: Optional[datetime] = None) -> None:
    get_db().add(new_run_event(run.id, kind, actor, actor_user_id=actor_user_id, from_state=from_state,
                               to_state=to_state, details=details, now=now))


def log_transition(run: SVSRun, from_state: Optional[str], to_state: str, actor: str, reason: Optional[str] = None):
    logging.info("svs run %s: %s -> %s by %s%s", run.uuid, from_state, to_state, actor,
                 f" ({reason})" if reason else "",
                 extra={**run_log_fields(run), "from_state": from_state, "to_state": to_state, "actor": actor,
                        "reason": reason})


def _log_call(run: Optional[SVSRun], call: str, launcher: Optional[str], outcome: str, caller: Caller,
              level: int = logging.INFO, **fields):
    extra = {**(run_log_fields(run) if run is not None else {}), "launcher": launcher, "call": call,
             "outcome": outcome, "caller": caller.name, **fields}
    if run is None:
        logging.log(level, "svs launcher call %s: %s", call, outcome, extra=extra)
    else:
        logging.log(level, "svs launcher call %s on run %s: %s", call, run.uuid, outcome, extra=extra)


#
# reading
#

def get_run(run_uuid: str) -> SVSRun:
    run = get_db().execute(select(SVSRun).where(SVSRun.uuid == run_uuid)).scalar_one_or_none()
    if run is None:
        raise UnknownRun(f"run {run_uuid} not found")
    return run


#
# transitions
#

def _transition(run: SVSRun, from_state: RunState, to_state: RunState, actor: str, *,
                actor_user_id: Optional[int] = None, values: Optional[dict] = None, reason: Optional[str] = None,
                now: Optional[datetime] = None) -> bool:
    """Moves the run from from_state to to_state, with values, and appends the transition to its
    event log, in the caller's transaction. Returns False, changing nothing, when the run is not in
    from_state (anymore). The state is the caller's to name, never read back from the run, which a
    commit may have refreshed."""
    result = get_db().execute(
        update(SVSRun)
        .where(SVSRun.id == run.id, SVSRun.state == from_state.value)
        .values(state=to_state.value, **(values or {}))
        .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        return False

    _add_event(run, RunEventKind.TRANSITION, actor, actor_user_id=actor_user_id, from_state=from_state.value,
               to_state=to_state.value, details={"reason": reason} if reason else None, now=now)
    run.state = to_state.value
    for key, value in (values or {}).items():
        setattr(run, key, value)
    return True


def _close(run: SVSRun, from_state: RunState, actor: str, reason: str, *, actor_user_id: Optional[int] = None,
           now: Optional[datetime] = None) -> bool:
    """Closes the run; the caller commits and then calls _after_close."""
    now = now or datetime.now()
    return _transition(run, from_state, RunState.CLOSED, actor, actor_user_id=actor_user_id, reason=reason, now=now,
                       values={"closed_at": now, "close_reason": reason})


def _closable_alerts(*conditions) -> list[tuple[int, str]]:
    """(run id, alert uuid) of the open alerts nobody has taken that are fully attributed and
    attributed to a run matching conditions."""
    automation_user_id = get_config().global_settings.automation_user_id
    statement = (
        select(SVSAttribution.run_id, Alert.uuid).distinct()
        .join(Alert, Alert.uuid == SVSAttribution.alert_uuid)
        .join(SVSRun, SVSRun.id == SVSAttribution.run_id)
        .where(SVSAttribution.removed_at.is_(None),
               Alert.disposition == DISPOSITION_OPEN,
               or_(Alert.owner_id.is_(None), Alert.owner_id == automation_user_id),
               fully_attributed_condition(),
               *conditions)
        .order_by(SVSAttribution.run_id, Alert.uuid)
        .limit(CLOSE_ALERTS_BATCH))
    return [(run_id, alert_uuid) for run_id, alert_uuid in get_db().execute(statement)]


def _still_fully_attributed(alert_uuids: list[str]) -> set[str]:
    """Those of the alerts whose every detection is still attributed to a run. A private transaction,
    so it reads what is committed now rather than what the caller's transaction saw when it chose
    the alerts."""
    with private_transaction() as session:
        return set(session.execute(
            select(Alert.uuid).where(Alert.uuid.in_(alert_uuids), fully_attributed_condition())).scalars())


def _close_alerts(run: SVSRun, alert_uuids: list[str], actor: str, late: bool, *, comment: Optional[str] = None,
                  reviewed: bool = False) -> int:
    """Gives the alerts SIMULATED, through the disposition writer analysts use, as the automation
    user. An alert dispositioned or taken by an analyst in the meantime is left alone, and so is
    one no longer fully attributed: checked again under the alert's row lock, which disassociating
    takes too, so an alert disassociated while its run closes is never frozen without a run."""
    if not alert_uuids:
        return 0

    result = set_dispositions(
        alert_uuids, DISPOSITION_SIMULATED, get_config().global_settings.automation_user_id,
        user_comment=comment or f"closed with SVS test run {run.uuid}", system=True,
        expected_dispositions={DISPOSITION_OPEN}, eligible=_still_fully_attributed)
    closed = result.permitted
    left_alone = sorted(set(result.skipped) | set(result.unexpected) | set(result.ineligible))
    if closed:
        get_db().add(new_run_event(run.id, RunEventKind.ALERTS_CLOSED, actor, details={
            "alerts": closed, "disposition": DISPOSITION_SIMULATED, "late": late, "reviewed": reviewed}))
        get_db().commit()

    logging.info("svs run %s: %d %salerts closed as %s, %d left alone", run.uuid, len(closed),
                 "late " if late else "", DISPOSITION_SIMULATED, len(left_alone),
                 extra={**run_log_fields(run), "alert_uuids": closed, "left_alone": left_alone, "late": late,
                        "actor": actor})
    return len(closed)


def close_run_alerts(run: SVSRun, actor: str = TIMER_ACTOR) -> int:
    """Gives SIMULATED to the alerts of a run that was just closed: those fully attributed, open
    and not taken by an analyst (docs/SVS.md, Part 3, *Test alerts downstream*). Nothing is learned
    from them: an alert attributed to a run that is not reviewed has no verdicts and no capture.
    An alert attributed after this is closed by the timers' sweep (close_late_alerts). Returns how
    many it closed."""
    return _close_alerts(run, [alert_uuid for _, alert_uuid in _closable_alerts(SVSAttribution.run_id == run.id)],
                         actor, late=False)


def close_reviewed_run_alerts(run: SVSRun, actor: str) -> int:
    """Gives SIMULATED to the alerts of a run that was just reviewed (saq/svs/review.py), as closing
    it would, with a comment naming the review. Their YARA hits are captured now that the run is
    reviewed, so the review must be committed first. Returns how many it closed."""
    return _close_alerts(run, [alert_uuid for _, alert_uuid in _closable_alerts(SVSAttribution.run_id == run.id)],
                         actor, late=False, comment=f"reviewed with SVS test run {run.uuid} by {actor}", reviewed=True)


def close_late_alerts() -> int:
    """Closes the alerts attributed to runs that were closed before they arrived, as closing the
    run would have. Returns how many it closed."""
    by_run: dict[int, list[str]] = {}
    seen = set()
    for run_id, alert_uuid in _closable_alerts(SVSRun.state == RunState.CLOSED.value):
        # an alert attributed to two closed runs is closed once, with the older run
        if alert_uuid not in seen:
            seen.add(alert_uuid)
            by_run.setdefault(run_id, []).append(alert_uuid)

    count = 0
    db = get_db()
    for run in db.execute(select(SVSRun).where(SVSRun.id.in_(list(by_run))).order_by(SVSRun.id)).scalars():
        try:
            count += _close_alerts(run, by_run[run.id], TIMER_ACTOR, late=True)
        except Exception as e:
            db.rollback()
            log_loop_exception(e, f"unable to close the late alerts of svs run {run.uuid}")
    return count


def on_run_ended(run: SVSRun) -> None:
    """Computes the result of a run that just ended (docs/SVS_RUNS.md, *Results*). A failure never
    undoes the end: the run's result stays stale, and the timers compute it on their next pass."""
    try:
        compute_result(run.id)
    except Exception as e:
        logging.exception("unable to compute the result of svs run %s: %s", run.uuid, e, extra=run_log_fields(run))


def _after_close(run: SVSRun, actor: str = TIMER_ACTOR) -> None:
    """Closes the alerts of a run whose close was committed. A failure never undoes the close: the
    timers' late-alert sweep closes those alerts on its next pass."""
    try:
        close_run_alerts(run, actor)
    except Exception as e:
        get_db().rollback()
        logging.exception("unable to close the alerts of svs run %s: %s", run.uuid, e, extra=run_log_fields(run))


#
# one run per test host
#

def claim_ends_at():
    """When a started run's claim on its hosts ends: its observation window, or its attribution
    window when its test holds the host."""
    return case((SVSRun.holds_host, SVSRun.attribution_ends_at), else_=SVSRun.observation_ends_at)


def host_holders(hosts: Iterable[str], now: datetime, exclude_run_id: Optional[int] = None) -> list[HostHolder]:
    """The runs holding any of the test hosts (short names) at now, other than exclude_run_id: a run
    not started yet holds its hosts until it starts, times out or is canceled; a started run, in any
    state, until its claim ends. Claims judge by time, like attribution, so a run closed early still
    holds its hosts until its claim ends."""
    hosts = sorted(set(hosts))
    if not hosts:
        return []
    claim_end = claim_ends_at()
    statement = (
        select(SVSRunTarget.host, SVSRun.uuid, SVSRun.state, case(
            (SVSRun.started_at.is_(None), null()), else_=claim_end)).distinct()
        .join(SVSRun, SVSRun.id == SVSRunTarget.run_id)
        .where(SVSRunTarget.host.in_(hosts),
               or_(SVSRun.state == RunState.CREATED.value,
                   # the attribution window bounds every claim, and is indexed
                   and_(SVSRun.started_at.isnot(None), SVSRun.attribution_ends_at >= now, claim_end >= now)))
        .order_by(SVSRunTarget.host, SVSRun.uuid))
    if exclude_run_id is not None:
        statement = statement.where(SVSRun.id != exclude_run_id)
    return [HostHolder(host, run_uuid, state, until) for host, run_uuid, state, until in get_db().execute(statement)]


def _lock_hosts(host_ids: Iterable[int]) -> None:
    """Locks the test hosts' rows, in id order, so registrations and starts on a host are decided one
    at a time. The session is READ COMMITTED, so host_holders after this sees every run another
    registration committed while it held them."""
    host_ids = sorted({host_id for host_id in host_ids if host_id is not None})
    if host_ids:
        get_db().execute(select(SVSTestHost.id).where(SVSTestHost.id.in_(host_ids)).order_by(SVSTestHost.id)
                         .with_for_update()).all()


#
# registration
#

def _validate(registration: Registration) -> tuple[SVSCatalogTest, str]:
    """Checks what doesn't depend on the test hosts. Returns the catalog test and the serialized
    extra. Raises InvalidRegistration."""
    config = get_config().svs.runs

    test = get_db().execute(
        select(SVSCatalogTest).where(SVSCatalogTest.guid == registration.test_guid.strip().lower())
    ).scalar_one_or_none()
    if test is None:
        raise InvalidRegistration(f"test {registration.test_guid} is not in the catalog")
    if test.removed_at is not None:
        raise InvalidRegistration(f"test {registration.test_guid} was removed from the catalog at {test.removed_at}")

    if not registration.targets:
        raise InvalidRegistration("a run needs at least one target")
    if len(registration.targets) > config.max_targets:
        raise InvalidRegistration(f"a run may have at most {config.max_targets} targets")

    if not isinstance(registration.extra, dict):
        raise InvalidRegistration("extra must be a JSON object")
    extra = json.dumps(registration.extra, sort_keys=True)
    if len(extra.encode("utf-8")) > config.max_extra_bytes:
        raise InvalidRegistration(f"extra is larger than {config.max_extra_bytes} bytes")

    for target in registration.targets:
        try:
            split_hostname(target.hostname)
            if target.username is not None:
                normalize_username(target.username)
        except InvalidTestHost as e:
            raise InvalidRegistration(str(e)) from None

    return test, extra


def _run_platform(test: SVSCatalogTest, matches) -> str:
    """The one platform a run is on: the platform of its targets' test hosts, which have to agree (a
    host without one is taken to be on it too), else the test's only supported platform. Raises
    InvalidRegistration when a host's platform isn't one the test supports, or neither says."""
    platforms = supported_platforms(test)
    for _, match in matches:
        if match.host.platform is not None and match.host.platform not in platforms:
            raise InvalidRegistration(
                f"test {test.guid} supports {', '.join(platforms) or 'no platform'}; "
                f"test host {match.host.hostname} is {match.host.platform}")

    host_platforms = sorted({match.host.platform for _, match in matches if match.host.platform is not None})
    if len(host_platforms) > 1:
        raise InvalidRegistration(
            f"the targets' test hosts are on different platforms ({', '.join(host_platforms)}); "
            "a run is on one platform")
    if host_platforms:
        return host_platforms[0]

    test_platforms = platform_slugs(test)
    if len(test_platforms) == 1:
        return test_platforms[0]

    raise InvalidRegistration(
        f"can't tell which platform the run is on: test {test.guid} supports "
        f"{', '.join(test_platforms) or 'no platform'} and no target's test host has a platform; "
        "set the test hosts' platform")


@dataclass
class RegistrationDecision:
    """What registering would decide, worked out without changing anything: invalid (422), refused
    (403, a reason per refused target), or accepted, with the run's platform and windows."""

    test: Optional[SVSCatalogTest] = None
    extra: Optional[str] = None
    # every target with how it matched the test hosts; empty when the registration is invalid before
    # its targets are judged
    matches: list[tuple[TargetSpec, TargetMatch]] = field(default_factory=list)
    invalid: Optional[str] = None
    platform: Optional[str] = None
    observation: Optional[timedelta] = None
    observation_source: Optional[ObservationSource] = None
    attribution: Optional[timedelta] = None
    holds_host: bool = False
    # the runs holding the targets' test hosts: registering would answer 409
    busy: list[HostHolder] = field(default_factory=list)

    @property
    def refused(self) -> list[tuple[TargetSpec, str]]:
        return [(target, match.reason or "not a test host") for target, match in self.matches if not match.matched]


def decide(registration: Registration, now: Optional[datetime] = None) -> RegistrationDecision:
    """Decides a registration as register would, in the same order, and only reads."""
    try:
        test, extra = _validate(registration)
    except InvalidRegistration as e:
        return RegistrationDecision(invalid=str(e))

    decision = RegistrationDecision(test=test, extra=extra, matches=[
        (target, match_target(target.hostname, target.username)) for target in registration.targets])
    if decision.refused:
        return decision

    try:
        decision.platform = _run_platform(test, decision.matches)
    except InvalidRegistration as e:
        decision.invalid = str(e)
        return decision

    decision.busy = host_holders([match.host.hostname for _, match in decision.matches], now or datetime.now())
    if decision.busy:
        return decision

    decision.observation, decision.observation_source = observation_for_test(test.guid, decision.platform)
    decision.attribution = attribution_window(decision.observation)
    decision.holds_host = test_holds_host(test.guid)
    return decision


def validate(registration: Registration, caller: Caller) -> RegistrationDecision:
    """A launcher's dry run: what registering would decide, with no run, event, refusal or alert."""
    decision = decide(registration)
    outcome = ("invalid" if decision.invalid else "refused" if decision.refused else
               OUTCOME_HOST_BUSY if decision.busy else "accepted")
    _log_call(None, CALL_VALIDATE, registration.launcher, outcome, caller, svs_test=registration.test_guid,
              invalid=decision.invalid, reasons=[reason for _, reason in decision.refused],
              platform=decision.platform, holding_runs=[holder.run_uuid for holder in decision.busy])
    return decision


def register(registration: Registration, caller: Caller, now: Optional[datetime] = None) -> SVSRun:
    """Registers a run in state Created and returns it, with its marker. Raises
    InvalidRegistration, and RegistrationRefused after recording each refused target."""
    now = now or datetime.now()
    decision = decide(registration, now)
    if decision.invalid:
        raise InvalidRegistration(decision.invalid)

    test = decision.test
    payload = registration.payload()
    refused = decision.refused
    if refused:
        for target, reason in refused:
            refuse(caller, target.hostname, target.username, reason, launcher=registration.launcher,
                   test_guid=test.guid, payload=payload, now=now)
        _log_call(None, CALL_REGISTER, registration.launcher, "refused", caller, level=logging.WARNING,
                  svs_test=test.guid, reasons=[reason for _, reason in refused])
        raise RegistrationRefused([reason for _, reason in refused])

    # checked again under the hosts' locks: another registration may have taken a host since
    busy = decision.busy
    if not busy:
        _lock_hosts(match.host.id for _, match in decision.matches)
        busy = host_holders([match.host.hostname for _, match in decision.matches], now)
    if busy:
        get_db().rollback()
        _log_call(None, CALL_REGISTER, registration.launcher, OUTCOME_HOST_BUSY, caller, svs_test=test.guid,
                  holding_runs=[holder.run_uuid for holder in busy])
        raise HostBusy(busy)

    run = SVSRun(
        uuid=str(uuid.uuid4()),
        test_guid=test.guid,
        test_content_hash=test.content_hash,
        catalog_commit=test.commit,
        platform=decision.platform,
        state=RunState.CREATED.value,
        marker=new_marker(),
        launcher=registration.launcher,
        batch_id=registration.batch_id,
        extra=decision.extra,
        registered_by=caller.user_id,
        created_at=now,
        observation_seconds=int(decision.observation.total_seconds()),
        attribution_seconds=int(decision.attribution.total_seconds()),
        holds_host=decision.holds_host)

    seen = set()
    for target, match in decision.matches:
        host, fqdn = split_hostname(target.hostname)
        user = normalize_username(target.username) if target.username is not None else None
        if (host, fqdn, user) in seen:
            continue
        seen.add((host, fqdn, user))
        run.targets.append(SVSRunTarget(
            hostname=target.hostname.strip(), username=target.username.strip() if target.username else None,
            host=host, fqdn=fqdn or match.host.fqdn, user=user, test_host_id=match.host.id))

    db = get_db()
    db.add(run)
    db.flush()
    _add_event(run, RunEventKind.REGISTERED, caller.name, actor_user_id=caller.user_id, to_state=run.state,
               details={**payload, "platform": run.platform, "observation_source": decision.observation_source.value,
                        "holds_host": run.holds_host},
               now=now)
    db.commit()

    log_transition(run, None, run.state, caller.name)
    _log_call(run, CALL_REGISTER, run.launcher, "created", caller, platform=run.platform)
    return run


#
# the launcher's calls
#

def _launcher_call(run: SVSRun, call: str, caller: Caller, outcome: str, payload: Optional[dict] = None,
                   now: Optional[datetime] = None) -> None:
    _add_event(run, RunEventKind.LAUNCHER_CALL, caller.name, actor_user_id=caller.user_id,
               details={"call": call, "outcome": outcome, "payload": payload or {}}, now=now)


def _conflict(run: SVSRun, call: str, caller: Caller, payload: Optional[dict] = None) -> RunStateConflict:
    """Records a call that doesn't apply to the run's state and returns the error to raise."""
    db = get_db()
    db.rollback()
    run = get_run(run.uuid)
    _launcher_call(run, call, caller, "conflict", payload)
    db.commit()
    _log_call(run, call, run.launcher, "conflict", caller, state=run.state)
    return RunStateConflict(run.uuid, run.state, call)


def _host_busy(run: SVSRun, caller: Caller, busy: list[HostHolder]) -> HostBusy:
    """Records a start refused because another run holds a target's host and returns the error to
    raise."""
    db = get_db()
    db.rollback()
    run = get_run(run.uuid)
    holding_runs = [holder.run_uuid for holder in busy]
    _launcher_call(run, CALL_START, caller, OUTCOME_HOST_BUSY, {"holding_runs": holding_runs})
    db.commit()
    _log_call(run, CALL_START, run.launcher, OUTCOME_HOST_BUSY, caller, holding_runs=holding_runs)
    return HostBusy(busy)


def start(run_uuid: str, caller: Caller, now: Optional[datetime] = None) -> SVSRun:
    """Created -> Started; the windows start now. Raises UnknownRun, RunStateConflict, and HostBusy
    when another run holds one of its hosts."""
    # the windows are stored to the second, and MySQL rounds a fraction half up: a window stored
    # from the exact time could start after the test fired, so it starts at the whole second instead
    now = (now or datetime.now()).replace(microsecond=0)
    run = get_run(run_uuid)
    if run.state == RunState.CREATED:
        _lock_hosts(target.test_host_id for target in run.targets)
        busy = host_holders([target.host for target in run.targets], now, exclude_run_id=run.id)
        if busy:
            raise _host_busy(run, caller, busy)

    if run.state != RunState.CREATED or not _transition(
            run, RunState.CREATED, RunState.STARTED, caller.name, actor_user_id=caller.user_id, now=now,
            values={"started_at": now,
                    "observation_ends_at": now + timedelta(seconds=run.observation_seconds),
                    "attribution_ends_at": now + timedelta(seconds=run.attribution_seconds)}):
        raise _conflict(run, CALL_START, caller)

    _launcher_call(run, CALL_START, caller, "started", now=now)
    get_db().commit()
    log_transition(run, RunState.CREATED.value, run.state, caller.name)
    _log_call(run, CALL_START, run.launcher, "started", caller)
    return run


def executed(run_uuid: str, caller: Caller, exit_code: int, error: Optional[str] = None,
             now: Optional[datetime] = None) -> SVSRun:
    """Records how the test executed on a Started run. A non-zero exit code or an error is a
    launcher-reported failure, which moves the run to Error. Raises UnknownRun, RunStateConflict."""
    now = now or datetime.now()
    payload = {"exit_code": exit_code, "error": error}
    run = get_run(run_uuid)
    values = {"executed_at": now, "exit_code": exit_code, "launcher_error": error}
    failed = exit_code != 0 or bool(error)

    if run.state != RunState.STARTED:
        raise _conflict(run, CALL_EXECUTED, caller, payload)

    if failed:
        reason = f"the launcher reported a failure (exit code {exit_code}{f': {error}' if error else ''})"
        values["error_reason"] = reason
        moved = _transition(run, RunState.STARTED, RunState.ERROR, caller.name, actor_user_id=caller.user_id,
                            values=values, reason=reason, now=now)
    else:
        moved = get_db().execute(
            update(SVSRun)
            .where(SVSRun.id == run.id, SVSRun.state == RunState.STARTED.value)
            .values(**values)
            .execution_options(synchronize_session=False)).rowcount == 1
        if moved:
            for key, value in values.items():
                setattr(run, key, value)

    if not moved:
        raise _conflict(run, CALL_EXECUTED, caller, payload)

    outcome = "error" if failed else "recorded"
    _launcher_call(run, CALL_EXECUTED, caller, outcome, payload, now=now)
    get_db().commit()
    if failed:
        log_transition(run, RunState.STARTED.value, run.state, caller.name, run.error_reason)
    _log_call(run, CALL_EXECUTED, run.launcher, outcome, caller, exit_code=exit_code)
    return run


def cleanup(run_uuid: str, caller: Caller, now: Optional[datetime] = None) -> SVSRun:
    """Records, once, that the test's cleanup begins now on a Started run: detections whose event
    time is at or after it are the cleanup's, still the run's alerts but left out of what it
    teaches (docs/SVS_RUNS.md, *Cleanup*). Raises UnknownRun, RunStateConflict."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    if run.state != RunState.STARTED or run.cleanup_at is not None or get_db().execute(
            update(SVSRun)
            .where(SVSRun.id == run.id, SVSRun.state == RunState.STARTED.value, SVSRun.cleanup_at.is_(None))
            .values(cleanup_at=now)
            .execution_options(synchronize_session=False)).rowcount != 1:
        raise _conflict(run, CALL_CLEANUP, caller, {"cleanup_at": run.cleanup_at.isoformat()} if run.cleanup_at else None)

    run.cleanup_at = now
    _launcher_call(run, CALL_CLEANUP, caller, "recorded", {"cleanup_at": now.isoformat()}, now=now)
    get_db().commit()
    _log_call(run, CALL_CLEANUP, run.launcher, "recorded", caller, cleanup_at=now.isoformat())
    return run


def _cancel(run: SVSRun, actor: str, user_id: Optional[int], now: datetime) -> Optional[tuple[RunState, bool]]:
    """Created or Started -> Canceled, in the caller's transaction; a run canceled before it
    started is also closed. Returns the state it was canceled from and whether it was closed, or
    None when it is in neither state (anymore)."""
    if run.state not in (RunState.CREATED, RunState.STARTED):
        return None
    from_state = RunState(run.state)
    if not _transition(run, from_state, RunState.CANCELED, actor, actor_user_id=user_id, now=now,
                       values={"canceled_at": now}):
        return None

    closed = from_state == RunState.CREATED and _close(
        run, RunState.CANCELED, actor, CLOSE_REASON_CANCELED_BEFORE_START, actor_user_id=user_id, now=now)
    return from_state, closed


def _log_cancel(run: SVSRun, from_state: RunState, closed: bool, actor: str) -> None:
    log_transition(run, from_state.value, RunState.CANCELED.value, actor)
    if closed:
        log_transition(run, RunState.CANCELED.value, RunState.CLOSED.value, actor, CLOSE_REASON_CANCELED_BEFORE_START)
        _after_close(run, actor)


def cancel(run_uuid: str, caller: Caller, now: Optional[datetime] = None) -> SVSRun:
    """The launcher's cancel: Created or Started -> Canceled. A canceled run keeps attributing until
    its attribution window ends, because the test may have run anyway. A run canceled before it
    started has no windows, so it is closed at once. Raises UnknownRun, RunStateConflict."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    canceled = _cancel(run, caller.name, caller.user_id, now)
    if canceled is None:
        raise _conflict(run, CALL_CANCEL, caller)

    _launcher_call(run, CALL_CANCEL, caller, "canceled", now=now)
    get_db().commit()
    _log_cancel(run, *canceled, caller.name)
    _log_call(run, CALL_CANCEL, run.launcher, "canceled", caller)
    return run


def cancel_by_person(run_uuid: str, actor: str, user_id: int, now: Optional[datetime] = None) -> SVSRun:
    """A person's cancel (saq/svs/review.py), the same as the launcher's. Raises UnknownRun,
    RunStateConflict."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    canceled = _cancel(run, actor, user_id, now)
    if canceled is None:
        get_db().rollback()
        raise RunStateConflict(run.uuid, run.state, "cancel")

    get_db().commit()
    _log_cancel(run, *canceled, actor)
    return run


def close_by_person(run_uuid: str, actor: str, user_id: int, reason: Optional[str] = None,
                    now: Optional[datetime] = None) -> SVSRun:
    """A person discards a run (saq/svs/review.py): Ended, Canceled or Error -> Closed, and its
    alerts are closed as SIMULATED. Nothing is learned from it. An Ended run needs a reason, since
    it waited for a review [MGT-3]. Raises UnknownRun, RunStateConflict, ReasonRequired."""
    now = now or datetime.now()
    run = get_run(run_uuid)
    if run.state not in (RunState.ENDED, RunState.CANCELED, RunState.ERROR):
        raise RunStateConflict(run.uuid, run.state, "close")
    from_state = RunState(run.state)
    reason = (reason or "").strip() or None
    if from_state == RunState.ENDED and reason is None:
        raise ReasonRequired(f"run {run.uuid} ended and waits for a review: closing it instead needs a reason")

    if not _close(run, from_state, actor, reason or CLOSE_REASON_BY_PERSON, actor_user_id=user_id, now=now):
        get_db().rollback()
        raise RunStateConflict(run.uuid, run.state, "close")
    get_db().commit()
    log_transition(run, from_state.value, RunState.CLOSED.value, actor, run.close_reason)
    _after_close(run, actor)
    return run


#
# the timers (service_svs, on the primary node)
#

@dataclass
class TimerResult:
    timed_out: int = 0
    ended: int = 0
    closed: int = 0
    late_alerts_closed: int = 0
    results_computed: int = 0
    pruned_refusals: int = 0


def _due(*condition) -> list[tuple[SVSRun, RunState]]:
    """The runs a timer moves, each with the state it was read in: a commit refreshes the run, so
    its state attribute may already be what another timer moved it to."""
    statement = select(SVSRun).where(*condition).order_by(SVSRun.id).limit(TIMER_BATCH)
    return [(run, RunState(run.state)) for run in get_db().execute(statement).scalars()]


def _each(due: list[tuple[SVSRun, RunState]], move) -> int:
    """Applies move to each run in its own transaction; a run that fails is logged and skipped."""
    count = 0
    db = get_db()
    for run, state in due:
        try:
            if move(run, state):
                count += 1
        except Exception as e:
            db.rollback()
            log_loop_exception(e, f"unable to move svs run {run.uuid}")
    return count


def _time_out(run: SVSRun, now: datetime) -> bool:
    """Created -> Error -> Closed."""
    minutes = get_config().svs.runs.start_timeout_minutes
    reason = f"start was not called within {minutes} minutes"
    if not _transition(run, RunState.CREATED, RunState.ERROR, TIMER_ACTOR, values={"error_reason": reason},
                       reason=reason, now=now):
        get_db().rollback()
        return False
    _close(run, RunState.ERROR, TIMER_ACTOR, CLOSE_REASON_START_TIMEOUT, now=now)
    get_db().commit()
    log_transition(run, RunState.CREATED.value, RunState.ERROR.value, TIMER_ACTOR, reason)
    log_transition(run, RunState.ERROR.value, RunState.CLOSED.value, TIMER_ACTOR, CLOSE_REASON_START_TIMEOUT)
    _after_close(run)
    return True


def _end(run: SVSRun, now: datetime) -> bool:
    if not _transition(run, RunState.STARTED, RunState.ENDED, TIMER_ACTOR, values={"ended_at": now}, now=now):
        get_db().rollback()
        return False
    mark_runs_stale(get_db(), run_ids=[run.id])
    get_db().commit()
    log_transition(run, RunState.STARTED.value, RunState.ENDED.value, TIMER_ACTOR)
    on_run_ended(run)
    return True


def _close_after_attribution(run: SVSRun, from_state: RunState, now: datetime) -> bool:
    if not _close(run, from_state, TIMER_ACTOR, CLOSE_REASON_ATTRIBUTION_ENDED, now=now):
        get_db().rollback()
        return False
    get_db().commit()
    log_transition(run, from_state.value, RunState.CLOSED.value, TIMER_ACTOR, CLOSE_REASON_ATTRIBUTION_ENDED)
    _after_close(run)
    return True


def run_timers(now: Optional[datetime] = None) -> TimerResult:
    """Moves every run whose start timeout or window has passed. Safe to run twice: each move is
    conditional on the state it was read in."""
    now = now or datetime.now()
    result = TimerResult()
    timeout = timedelta(minutes=get_config().svs.runs.start_timeout_minutes)

    result.timed_out = _each(
        _due(SVSRun.state == RunState.CREATED.value, SVSRun.created_at <= now - timeout),
        lambda run, state: _time_out(run, now))
    result.ended = _each(
        _due(SVSRun.state == RunState.STARTED.value, SVSRun.observation_ends_at <= now),
        lambda run, state: _end(run, now))
    result.closed = _each(
        _due(SVSRun.state.in_((RunState.CANCELED.value, RunState.ERROR.value)),
             or_(SVSRun.attribution_ends_at.is_(None), SVSRun.attribution_ends_at <= now)),
        lambda run, state: _close_after_attribution(run, state, now))
    result.late_alerts_closed = close_late_alerts()
    result.results_computed = recompute_stale_results(now)
    result.pruned_refusals = prune_refusals(now)
    return result
