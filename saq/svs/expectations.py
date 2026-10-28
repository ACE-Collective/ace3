"""What has been decided about a test's signatures (docs/SVS_RUNS.md, *Expectations and ignores*,
*Windows*): its expectations, the ignores that apply to its runs, and its settings.

- An **expectation** is a signature a run of the test on one platform should fire (expected), or
  one that fires there but is not what the test is about (rejected, and not proposed again). A run
  is judged by its own platform's decisions only. Anything else a run fires is a candidate in that
  run's result. Only a person decides, and removing a decision makes the signature a candidate
  again the next time it fires.
- An **ignore** marks a signature as launcher noise, for one test on every platform
  (svs:run_manage) or for every test (global, svs:admin). An ignored signature is never a candidate
  and never missing.
- A test's **settings** hold an observation window that replaces the computed one.

Every change marks the affected runs' results stale (saq/svs/result_state.py), so the timers
recompute them, and is logged as an AUDIT record. svs_expectations, svs_ignores and
svs_test_settings are written here only.
"""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from saq.auth import ApiAuthResult
from saq.configuration.config import get_config
from saq.database.model import (
    SVSAttribution,
    SVSCatalogTest,
    SVSExpectation,
    SVSIgnore,
    SVSRun,
    SVSRunResult,
    SVSTestSettings,
)
from saq.database.pool import get_db
from saq.logging import log_audit
from saq.svs.catalog import platform_slugs
from saq.svs.constants import GLOBAL_SCOPE_KEY, ExpectationState, IgnoreScope, ObservationSource, RunEventKind
from saq.svs.preconditions import NONE, Precondition, StaleWrite
from saq.svs.result_state import mark_runs_stale
from saq.svs.run_events import new_run_event, run_log_fields
from saq.svs.windows import observation_window
from saq.util.uuid import is_uuid


class UnknownTest(LookupError):
    pass


class UnknownDecision(LookupError):
    """There is no such expectation, ignore or setting."""


class InvalidDecision(ValueError):
    """The decision can't be accepted as sent; the message says why."""


def _test(test_guid: str) -> SVSCatalogTest:
    test = get_db().execute(select(SVSCatalogTest).where(SVSCatalogTest.guid == test_guid)).scalar_one_or_none()
    if test is None:
        raise UnknownTest(f"test {test_guid} not found")
    return test


def _signature_uuid(value: str) -> str:
    value = (value or "").strip()
    if not is_uuid(value):
        raise InvalidDecision(f"{value!r} is not a signature uuid")
    return value


def _last_known(signature_uuid: str, run_id: Optional[int] = None) -> tuple[Optional[str], Optional[str]]:
    """The signature's family and name as the latest run result that has it says (the run's own,
    when given), or its family as an attribution recorded it."""
    db = get_db()
    statement = select(SVSRunResult.signature_family, SVSRunResult.signature_name).where(
        SVSRunResult.signature_uuid == signature_uuid)
    if run_id is not None:
        row = db.execute(statement.where(SVSRunResult.run_id == run_id)).first()
        if row is not None:
            return row[0], row[1]
    row = db.execute(statement.order_by(SVSRunResult.updated_at.desc(), SVSRunResult.id.desc()).limit(1)).first()
    if row is not None:
        return row[0], row[1]
    family = db.execute(select(SVSAttribution.signature_family).where(
        SVSAttribution.signature_uuid == signature_uuid, SVSAttribution.signature_family.is_not(None)).limit(1)).scalar()
    return family, None


def _audit(message: str, auth: Optional[ApiAuthResult], **fields) -> None:
    # fields name the actor and actor_user_id too, for a caller that passes no auth
    log_audit(message, auth=auth, **fields)


#
# expectations (svs:run_manage)
#

def _platform(test: SVSCatalogTest, platform: Optional[str]) -> str:
    """The platform, which has to be one of the test's. Raises InvalidDecision."""
    platform = (platform or "").strip().lower()
    platforms = platform_slugs(test)
    if platform not in platforms:
        raise InvalidDecision(f"platform {platform!r} is not one of test {test.guid}'s "
                              f"({', '.join(platforms) or 'it supports none'})")
    return platform


def _upsert(db, model, keys: dict, values: dict, update: dict, precondition: Precondition, what: str) -> None:
    """Inserts the row, or updates it with update, as the precondition allows (saq.svs.preconditions):
    a row the client saw none of is inserted only while there still is none, and one it read is
    changed only while it is unchanged since, read under its row lock. Raises StaleWrite, having
    rolled back."""
    insert = mysql_insert(model).values(**keys, **values)
    if precondition.absent:
        if db.execute(insert.prefix_with("IGNORE")).rowcount != 1:
            db.rollback()
            raise StaleWrite(f"{what} was decided by someone else since you loaded it")
        return

    if precondition.updated_at is not None:
        existing = db.execute(select(model).filter_by(**keys).with_for_update()
                              .execution_options(populate_existing=True)).scalar_one_or_none()
        try:
            precondition.check(existing, what)
        except StaleWrite:
            db.rollback()
            raise
    db.execute(insert.on_duplicate_key_update(**update))


def get_expectation(test_guid: str, platform: str, signature_uuid: str) -> SVSExpectation:
    expectation = get_db().execute(select(SVSExpectation).where(
        SVSExpectation.test_guid == test_guid, SVSExpectation.platform == platform,
        SVSExpectation.signature_uuid == signature_uuid)).scalar_one_or_none()
    if expectation is None:
        raise UnknownDecision(f"no decision about signature {signature_uuid} for test {test_guid} on {platform}")
    return expectation


def set_expectation(test_guid: str, signature_uuid: str, state: str, user_id: int, *,
                    platform: Optional[str] = None, reason: Optional[str] = None, run_uuid: Optional[str] = None,
                    actor: Optional[str] = None, precondition: Precondition = NONE,
                    now: Optional[datetime] = None, auth: Optional[ApiAuthResult] = None) -> SVSExpectation:
    """Decides a signature for a test on a platform: expected or rejected. With run_uuid (a run of
    the test), the decision was made from that run's result, it is about the run's platform, and the
    run's event log records it; without one, platform names one of the test's platforms. Raises
    UnknownTest, InvalidDecision, StaleWrite."""
    now = now or datetime.now()
    test = _test(test_guid)
    signature_uuid = _signature_uuid(signature_uuid)
    try:
        state = ExpectationState(state)
    except ValueError:
        raise InvalidDecision(f"state must be one of {', '.join(s.value for s in ExpectationState)}") from None

    db = get_db()
    run = None
    if run_uuid is not None:
        run = db.execute(select(SVSRun).where(SVSRun.uuid == run_uuid)).scalar_one_or_none()
        if run is None or run.test_guid != test.guid:
            raise InvalidDecision(f"run {run_uuid} is not a run of test {test.guid}")
        if platform is not None and platform.strip().lower() != run.platform:
            raise InvalidDecision(f"run {run_uuid} is on {run.platform or 'no platform'}, not {platform}")
        platform = run.platform
    platform = _platform(test, platform)

    family, name = _last_known(signature_uuid, run.id if run else None)
    values = {"state": state.value, "signature_family": family, "signature_name": name, "reason": reason,
              "decided_from_run_id": run.id if run else None, "decided_by_user_id": user_id, "decided_at": now}
    _upsert(db, SVSExpectation, {"test_guid": test.guid, "platform": platform, "signature_uuid": signature_uuid},
            values, values, precondition, f"the decision about {name or signature_uuid} on {platform}")
    if run is not None:
        db.add(new_run_event(run.id, RunEventKind.CANDIDATE_DECISION, actor or str(user_id), actor_user_id=user_id,
                             now=now, details={"signature_uuid": signature_uuid, "platform": platform,
                                               "state": state.value, "reason": reason}))
    mark_runs_stale(db, SVSRun.test_guid == test.guid, SVSRun.platform == platform)
    db.commit()

    _audit("svs expectation decided", auth, **{
        **(run_log_fields(run) if run is not None else {}), "svs_test": test.guid, "platform": platform,
        "signature_uuid": signature_uuid, "state": state.value, "reason": reason, "actor": actor,
        "actor_user_id": user_id})
    return get_expectation(test.guid, platform, signature_uuid)


def remove_expectation(test_guid: str, platform: str, signature_uuid: str, user_id: int, *,
                       actor: Optional[str] = None, auth: Optional[ApiAuthResult] = None) -> None:
    """Removes a decision: the signature is a candidate again the next time a run on the platform
    fires it. Raises UnknownTest, UnknownDecision, InvalidDecision."""
    test = _test(test_guid)
    platform = (platform or "").strip().lower()
    expectation = get_expectation(test.guid, platform, _signature_uuid(signature_uuid))
    state = expectation.state
    db = get_db()
    db.delete(expectation)
    mark_runs_stale(db, SVSRun.test_guid == test.guid, SVSRun.platform == platform)
    db.commit()
    _audit("svs expectation removed", auth, svs_test=test.guid, platform=platform,
           signature_uuid=expectation.signature_uuid, state=state, actor=actor, actor_user_id=user_id)


#
# ignores (a test's: svs:run_manage; global: svs:admin)
#

def _scope_key(test_guid: Optional[str]) -> str:
    return test_guid if test_guid is not None else GLOBAL_SCOPE_KEY


def get_ignore(signature_uuid: str, test_guid: Optional[str] = None) -> SVSIgnore:
    ignore = get_db().execute(select(SVSIgnore).where(
        SVSIgnore.scope_key == _scope_key(test_guid), SVSIgnore.signature_uuid == signature_uuid)).scalar_one_or_none()
    if ignore is None:
        raise UnknownDecision(f"signature {signature_uuid} is not ignored "
                              f"{'for test ' + test_guid if test_guid else 'globally'}")
    return ignore


def _ignored_runs(test_guid: Optional[str]) -> tuple:
    return (SVSRun.test_guid == test_guid,) if test_guid is not None else ()


def set_ignore(signature_uuid: str, user_id: int, *, test_guid: Optional[str] = None, reason: Optional[str] = None,
               actor: Optional[str] = None, precondition: Precondition = NONE,
               now: Optional[datetime] = None, auth: Optional[ApiAuthResult] = None) -> SVSIgnore:
    """Ignores a signature during the test's runs, or every test's (test_guid None). Setting it
    again replaces its reason. Raises UnknownTest, InvalidDecision, StaleWrite."""
    now = now or datetime.now()
    if test_guid is not None:
        test_guid = _test(test_guid).guid
    signature_uuid = _signature_uuid(signature_uuid)
    family, name = _last_known(signature_uuid)

    db = get_db()
    _upsert(db, SVSIgnore, {"scope_key": _scope_key(test_guid), "signature_uuid": signature_uuid},
            {"scope": (IgnoreScope.TEST if test_guid else IgnoreScope.GLOBAL).value, "test_guid": test_guid,
             "signature_family": family, "signature_name": name, "reason": reason, "created_by_user_id": user_id,
             "created_at": now},
            {"reason": reason}, precondition,
            f"the ignore of {name or signature_uuid} {'for this test' if test_guid else 'for every test'}")
    mark_runs_stale(db, *_ignored_runs(test_guid))
    db.commit()

    _audit("svs signature ignored", auth, svs_test=test_guid, signature_uuid=signature_uuid,
           scope=(IgnoreScope.TEST if test_guid else IgnoreScope.GLOBAL).value, reason=reason, actor=actor,
           actor_user_id=user_id)
    return get_ignore(signature_uuid, test_guid)


def remove_ignore(signature_uuid: str, user_id: int, *, test_guid: Optional[str] = None,
                  actor: Optional[str] = None, auth: Optional[ApiAuthResult] = None) -> None:
    """Stops ignoring a signature. Raises UnknownTest, UnknownDecision."""
    if test_guid is not None:
        test_guid = _test(test_guid).guid
    ignore = get_ignore(_signature_uuid(signature_uuid), test_guid)
    db = get_db()
    db.delete(ignore)
    mark_runs_stale(db, *_ignored_runs(test_guid))
    db.commit()
    _audit("svs signature no longer ignored", auth, svs_test=test_guid, signature_uuid=ignore.signature_uuid,
           scope=ignore.scope, actor=actor, actor_user_id=user_id)


#
# settings (svs:run_manage)
#

def max_observation_minutes() -> int:
    return get_config().svs.runs.observation_window.ceiling_hours * 60


def get_test_settings(test_guid: str) -> Optional[SVSTestSettings]:
    """The test's settings, None when it has none. Raises UnknownTest."""
    test = _test(test_guid)
    return get_db().execute(select(SVSTestSettings).where(SVSTestSettings.test_guid == test.guid)).scalar_one_or_none()


def set_test_settings(test_guid: str, user_id: int, *, observation_minutes: Optional[int] = None,
                      holds_host: bool = False, actor: Optional[str] = None,
                      auth: Optional[ApiAuthResult] = None) -> SVSTestSettings:
    """Sets the settings of the test's runs registered from now on, replacing what was set: an
    observation window used as it is, with no slack and no floor, up to the configured ceiling (None
    for the computed one), and whether a run holds its hosts for its whole attribution window.
    Raises UnknownTest, InvalidDecision."""
    test = _test(test_guid)
    ceiling = max_observation_minutes()
    if observation_minutes is not None and (
            not isinstance(observation_minutes, int) or not 1 <= observation_minutes <= ceiling):
        raise InvalidDecision(f"observation_minutes must be from 1 to {ceiling} (svs.runs.observation_window."
                              "ceiling_hours)")

    db = get_db()
    values = {"observation_minutes": observation_minutes, "holds_host": bool(holds_host), "set_by_user_id": user_id}
    db.execute(mysql_insert(SVSTestSettings).values(test_guid=test.guid, **values).on_duplicate_key_update(**values))
    db.commit()
    _audit("svs test settings changed", auth, svs_test=test.guid, observation_minutes=observation_minutes,
           holds_host=bool(holds_host), actor=actor, actor_user_id=user_id)
    return get_test_settings(test.guid)


def remove_test_settings(test_guid: str, user_id: int, *, actor: Optional[str] = None,
                         auth: Optional[ApiAuthResult] = None) -> None:
    """Back to the computed window, and runs that hold their hosts only for their observation window.
    Raises UnknownTest, UnknownDecision."""
    test = _test(test_guid)
    db = get_db()
    removed = db.execute(delete(SVSTestSettings).where(SVSTestSettings.test_guid == test.guid))
    if removed.rowcount == 0:
        db.rollback()
        raise UnknownDecision(f"test {test.guid} has no settings")
    db.commit()
    _audit("svs test settings removed", auth, svs_test=test.guid, actor=actor, actor_user_id=user_id)


#
# windows
#

def expected_signatures(test_guid: str, platform: str) -> set[str]:
    """The test's expected signatures on the platform that no ignore applies to."""
    db = get_db()
    expected = set(db.execute(select(SVSExpectation.signature_uuid).where(
        SVSExpectation.test_guid == test_guid, SVSExpectation.platform == platform,
        SVSExpectation.state == ExpectationState.EXPECTED.value)).scalars())
    if not expected:
        return expected
    ignored = set(db.execute(select(SVSIgnore.signature_uuid).where(
        SVSIgnore.scope_key.in_([GLOBAL_SCOPE_KEY, test_guid]))).scalars())
    return expected - ignored


def test_holds_host(test_guid: str) -> bool:
    """Whether a run of the test registered now holds its hosts for its whole attribution window."""
    return bool(get_db().execute(
        select(SVSTestSettings.holds_host).where(SVSTestSettings.test_guid == test_guid)).scalar())


def observation_for_test(test_guid: str, platform: str) -> tuple[timedelta, ObservationSource]:
    """The observation window of a run of the test on the platform registered now, and where it
    comes from: the test's settings, else the latency of its expected signatures on the platform,
    else the slowest enabled hunt."""
    settings = get_db().execute(
        select(SVSTestSettings.observation_minutes).where(SVSTestSettings.test_guid == test_guid)).scalar()
    if settings:
        return timedelta(minutes=settings), ObservationSource.OVERRIDE

    expected = expected_signatures(test_guid, platform)
    if expected:
        return observation_window(expected), ObservationSource.EXPECTED
    return observation_window(), ObservationSource.ALL_HUNTS
