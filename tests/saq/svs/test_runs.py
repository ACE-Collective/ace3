"""SVS test runs (saq.svs.runs, docs/SVS_RUNS.md): registration, the launcher's calls, the timers."""

import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy import inspect, select

from saq.configuration.config import get_config
from saq.constants import ENV_ACE_IS_PRIMARY_NODE
from saq.database.model import Alert, SVSRegistrationRefusal, SVSRun, SVSRunEvent, User
from saq.database.pool import get_db
from saq.svs import runs
from saq.svs import service as svs_service
from saq.svs.constants import ObservationSource, RunEventKind, RunState
from saq.svs.hosts import build_spec, create_host
from saq.svs.markers import MARKER_REGEX
from saq.svs.refusals import Caller
from saq.svs.expectations import set_test_settings
from saq.svs.runs import (
    HostBusy,
    HostHolder,
    InvalidRegistration,
    Registration,
    RegistrationRefused,
    RunStateConflict,
    TargetSpec,
    UnknownRun,
    cancel,
    cleanup,
    executed,
    register,
    run_timers,
    start,
    validate,
)
from saq.svs.service import SVSService
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LINUX_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
REMOVED_GUID = "cccccccc-3333-4333-8333-333333333333"
IAAS_GUID = "eeeeeeee-5555-4555-8555-555555555555"

LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")

T0 = datetime(2026, 10, 14, 12, 0, 0)


@pytest.fixture(autouse=True)
def setup(no_hunts, monkeypatch):
    add_catalog_test(GUID)
    add_catalog_test(LINUX_GUID, platforms=("linux", "macos"))
    add_catalog_test(REMOVED_GUID, removed=True)
    add_catalog_test(IAAS_GUID, platforms=("iaas:aws", "iaas:azure"))
    create_host(build_spec("win10-01.lab.example", usernames=["LAB\\svc_art"], platform="windows"), None)
    create_host(build_spec("anyuser-01"), None)
    create_host(build_spec("ubuntu-01", platform="linux"), None)
    create_host(build_spec("mac-01", platform="macos"), None)
    monkeypatch.setattr(runs, "close_run_alerts", _record("closed", runs.close_run_alerts))
    monkeypatch.setattr(runs, "on_run_ended", _record("ended", runs.on_run_ended))
    HOOKS.clear()


HOOKS: list[tuple[str, str]] = []


def _record(name: str, hook):
    def record(run, *args, **kwargs):
        HOOKS.append((name, run.uuid))
        return hook(run, *args, **kwargs)
    return record


def _registration(**values) -> Registration:
    return Registration(**{"test_guid": GUID, "targets": [TargetSpec("WIN10-01", "svc_art@lab.example")],
                           "launcher": "art", "batch_id": "batch-1", "extra": {"ticket": 42}, **values})


def _events(run_uuid: str) -> list[SVSRunEvent]:
    db = get_db()
    db.expire_all()
    run_id = db.execute(select(SVSRun.id).where(SVSRun.uuid == run_uuid)).scalar_one()
    return list(db.execute(select(SVSRunEvent).where(SVSRunEvent.run_id == run_id).order_by(SVSRunEvent.id)).scalars())


def _state(run_uuid: str) -> SVSRun:
    db = get_db()
    db.expire_all()
    return runs.get_run(run_uuid)


#
# registration
#

def test_register():
    run = register(_registration(), LAUNCHER, now=T0)

    run = _state(run.uuid)
    assert run.state == RunState.CREATED
    assert MARKER_REGEX.fullmatch(run.marker)
    assert (run.test_guid, run.catalog_commit, run.launcher, run.batch_id) == (GUID, "a" * 40, "art", "batch-1")
    assert run.platform == "windows"
    assert json.loads(run.extra) == {"ticket": 42}
    assert (run.observation_seconds, run.attribution_seconds) == (3600, 25 * 3600)
    assert run.started_at is None and run.observation_ends_at is None

    (target,) = run.targets
    assert (target.hostname, target.username, target.host, target.fqdn, target.user) == (
        "WIN10-01", "svc_art@lab.example", "win10-01", "win10-01.lab.example", "svc_art")

    (event,) = _events(run.uuid)
    assert (event.kind, event.from_state, event.to_state, event.actor) == (
        RunEventKind.REGISTERED, None, RunState.CREATED, "art-launcher")
    assert json.loads(event.details)["targets"] == [{"hostname": "WIN10-01", "username": "svc_art@lab.example"}]
    assert json.loads(event.details)["platform"] == "windows"


@pytest.mark.parametrize("test_guid, targets, platform", [
    # the test hosts' platform
    (LINUX_GUID, ["ubuntu-01"], "linux"),
    (LINUX_GUID, ["mac-01"], "macos"),
    # a host without one is taken to be on the others'
    (LINUX_GUID, ["anyuser-01", "mac-01"], "macos"),
    # no host says: the test's only platform, as ATT&CK names it
    (GUID, ["anyuser-01"], "windows"),
    (IAAS_GUID, ["anyuser-01"], "iaas"),
])
def test_a_run_has_one_platform(test_guid, targets, platform):
    run = register(_registration(test_guid=test_guid, targets=[TargetSpec(name) for name in targets]), LAUNCHER)
    assert _state(run.uuid).platform == platform


def test_register_dedupes_targets_and_accepts_any_user():
    run = register(_registration(targets=[TargetSpec("anyuser-01"), TargetSpec("ANYUSER-01"),
                                          TargetSpec("anyuser-01", "bob")]), LAUNCHER)
    assert [(t.host, t.user) for t in _state(run.uuid).targets] == [("anyuser-01", None), ("anyuser-01", "bob")]


@pytest.mark.parametrize("values, message", [
    ({"test_guid": "dddddddd-4444-4444-8444-444444444444"}, "is not in the catalog"),
    ({"test_guid": REMOVED_GUID}, "was removed from the catalog"),
    ({"targets": []}, "at least one target"),
    ({"targets": [TargetSpec("anyuser-01", f"u{n}") for n in range(17)]}, "at most 16 targets"),
    ({"extra": {"blob": "x" * 20000}}, "larger than 16384 bytes"),
    ({"extra": ["not", "an", "object"]}, "must be a JSON object"),
    ({"targets": [TargetSpec("bad host")]}, "is not a host name"),
    ({"test_guid": LINUX_GUID}, "test host win10-01 is windows"),
    # a run is on one platform: hosts that disagree, or nothing that says which
    ({"test_guid": LINUX_GUID, "targets": [TargetSpec("ubuntu-01"), TargetSpec("mac-01")]},
     r"different platforms \(linux, macos\)"),
    ({"test_guid": LINUX_GUID, "targets": [TargetSpec("anyuser-01")]},
     "can't tell which platform the run is on: test .* supports linux, macos"),
])
def test_register_rejects(values, message):
    with pytest.raises(InvalidRegistration, match=message):
        register(_registration(**values), LAUNCHER)
    assert get_db().execute(select(SVSRun)).first() is None
    assert get_db().execute(select(SVSRegistrationRefusal)).first() is None


@pytest.mark.parametrize("target, reason", [
    (TargetSpec("prod-dc-01"), "prod-dc-01 is not a test host"),
    (TargetSpec("win10-01", "administrator"), "administrator is not a user of test host win10-01"),
    (TargetSpec("win10-01"), "lists its users and no user was given"),
    (TargetSpec("win10-01.prod.example", "svc_art"), "is not test host win10-01.lab.example"),
])
def test_register_refuses_a_target_that_is_not_a_test_host(target, reason):
    with pytest.raises(RegistrationRefused) as error:
        register(_registration(targets=[TargetSpec("anyuser-01"), target]), LAUNCHER)

    assert len(error.value.reasons) == 1 and reason in error.value.reasons[0]
    assert get_db().execute(select(SVSRun)).first() is None
    assert get_db().execute(select(SVSRegistrationRefusal.host)).scalars().all() == [target.hostname.lower()]


def _nothing_written():
    db = get_db()
    db.expire_all()
    assert db.execute(select(SVSRun)).first() is None
    assert db.execute(select(SVSRunEvent)).first() is None
    assert db.execute(select(SVSRegistrationRefusal)).first() is None
    assert db.execute(select(Alert)).first() is None


def test_validate_decides_an_accepted_registration_as_register_would(caplog):
    caplog.set_level(logging.INFO)
    decision = validate(_registration(), LAUNCHER)

    assert decision.invalid is None and decision.refused == []
    assert (decision.platform, decision.observation_source) == ("windows", ObservationSource.ALL_HUNTS)
    assert (decision.observation, decision.attribution) == (timedelta(hours=1), timedelta(hours=25))
    ((target, match),) = decision.matches
    assert target == TargetSpec("WIN10-01", "svc_art@lab.example") and match.host.hostname == "win10-01"
    _nothing_written()

    (record,) = [r for r in caplog.records if getattr(r, "call", None) == "validate"]
    assert (record.levelno, record.outcome, record.caller, record.svs_test) == (
        logging.INFO, "accepted", "art-launcher", GUID)

    run = _state(register(_registration(), LAUNCHER).uuid)
    assert (run.platform, run.observation_seconds, run.attribution_seconds) == ("windows", 3600, 25 * 3600)


def test_validate_refuses_without_recording_or_alerting(caplog):
    caplog.set_level(logging.INFO)
    decision = validate(_registration(targets=[TargetSpec("anyuser-01"), TargetSpec("prod-dc-01"),
                                               TargetSpec("win10-01", "administrator")]), LAUNCHER)

    assert decision.invalid is None and decision.platform is None
    assert [reason for _, reason in decision.refused] == [
        "prod-dc-01 is not a test host", "administrator is not a user of test host win10-01"]
    assert [match.matched for _, match in decision.matches] == [True, False, False]
    _nothing_written()

    (record,) = [r for r in caplog.records if getattr(r, "call", None) == "validate"]
    assert (record.levelno, record.outcome) == (logging.INFO, "refused")
    assert record.reasons == ["prod-dc-01 is not a test host", "administrator is not a user of test host win10-01"]


@pytest.mark.parametrize("values, message, judged", [
    # invalid before the targets are judged
    ({"test_guid": "dddddddd-4444-4444-8444-444444444444"}, "is not in the catalog", False),
    ({"extra": {"blob": "x" * 20000}}, "larger than 16384 bytes", False),
    # invalid after
    ({"test_guid": LINUX_GUID}, "test host win10-01 is windows", True),
    ({"test_guid": LINUX_GUID, "targets": [TargetSpec("ubuntu-01"), TargetSpec("mac-01")]},
     r"different platforms \(linux, macos\)", True),
])
def test_validate_an_invalid_registration(values, message, judged):
    decision = validate(_registration(**values), LAUNCHER)
    assert re.search(message, decision.invalid)
    assert bool(decision.matches) == judged and decision.refused == []
    _nothing_written()

    with pytest.raises(InvalidRegistration, match=message):
        register(_registration(**values), LAUNCHER)


#
# one run per test host
#

def test_a_run_not_started_holds_its_hosts():
    first = register(_registration(), LAUNCHER, now=T0)

    with pytest.raises(HostBusy) as error:
        register(_registration(), LAUNCHER, now=T0 + timedelta(minutes=5))
    assert error.value.holders == [HostHolder("win10-01", first.uuid, RunState.CREATED, None)]
    assert f"test host win10-01 is held by run {first.uuid} (created, not started)" in str(error.value)
    # a lifecycle conflict: no run, no refusal, no alert
    assert [run.uuid for run in get_db().execute(select(SVSRun)).scalars()] == [first.uuid]
    assert get_db().execute(select(SVSRegistrationRefusal)).first() is None
    assert get_db().execute(select(Alert)).first() is None

    # another host is free, and a run canceled before it started never held one
    register(_registration(targets=[TargetSpec("anyuser-01")]), LAUNCHER, now=T0)
    cancel(first.uuid, LAUNCHER, now=T0 + timedelta(minutes=6))
    register(_registration(), LAUNCHER, now=T0 + timedelta(minutes=7))


def test_a_started_run_holds_its_hosts_until_its_observation_window_ends():
    first = register(_registration(), LAUNCHER, now=T0)
    start(first.uuid, LAUNCHER, now=T0)
    # in any state: it may have fired
    executed(first.uuid, LAUNCHER, 1, now=T0 + timedelta(minutes=1))

    for now in (T0 + timedelta(minutes=59), T0 + timedelta(hours=1)):
        with pytest.raises(HostBusy) as error:
            register(_registration(), LAUNCHER, now=now)
        assert error.value.holders == [HostHolder("win10-01", first.uuid, RunState.ERROR, T0 + timedelta(hours=1))]

    second = register(_registration(), LAUNCHER, now=T0 + timedelta(hours=1, seconds=1))
    start(second.uuid, LAUNCHER, now=T0 + timedelta(hours=1, seconds=1))
    assert not _state(second.uuid).holds_host


def test_a_test_that_holds_the_host_holds_it_for_the_attribution_window():
    set_test_settings(GUID, None, holds_host=True)
    first = register(_registration(), LAUNCHER, now=T0)
    assert _state(first.uuid).holds_host
    start(first.uuid, LAUNCHER, now=T0)

    with pytest.raises(HostBusy) as error:
        register(_registration(), LAUNCHER, now=T0 + timedelta(hours=2))
    assert error.value.holders[0].until == T0 + timedelta(hours=25)

    # a test's settings apply to runs registered after them: this run doesn't hold the host
    set_test_settings(GUID, None, holds_host=False)
    second = register(_registration(), LAUNCHER, now=T0 + timedelta(hours=25, seconds=1))
    assert not _state(second.uuid).holds_host
    assert json.loads(_events(second.uuid)[0].details)["holds_host"] is False


def test_start_refuses_a_run_whose_host_another_run_holds(monkeypatch, caplog):
    # runs registered before one run per host was enforced
    monkeypatch.setattr(runs, "host_holders", lambda *args, **kwargs: [])
    first = register(_registration(), LAUNCHER, now=T0)
    start(first.uuid, LAUNCHER, now=T0)
    second = register(_registration(), LAUNCHER, now=T0)
    monkeypatch.undo()

    caplog.set_level(logging.INFO)
    with pytest.raises(HostBusy) as error:
        start(second.uuid, LAUNCHER, now=T0 + timedelta(minutes=1))
    assert [holder.run_uuid for holder in error.value.holders] == [first.uuid]

    assert _state(second.uuid).state == RunState.CREATED
    event = _events(second.uuid)[-1]
    assert event.kind == RunEventKind.LAUNCHER_CALL
    assert json.loads(event.details) == {"call": "start", "outcome": "host busy",
                                         "payload": {"holding_runs": [first.uuid]}}
    (record,) = [r for r in caplog.records if getattr(r, "outcome", None) == "host busy"]
    assert (record.svs_run, record.holding_runs) == (second.uuid, [first.uuid])


def test_validate_reports_the_host_busy():
    first = register(_registration(), LAUNCHER, now=T0)
    decision = validate(_registration(), LAUNCHER)
    assert decision.invalid is None and decision.refused == []
    assert [holder.run_uuid for holder in decision.busy] == [first.uuid]


def test_concurrent_registrations_take_a_host_once():
    barrier = threading.Barrier(2)
    outcomes = []

    def register_one():
        barrier.wait(10)
        try:
            outcomes.append(register(_registration(), LAUNCHER).uuid)
        except HostBusy:
            outcomes.append("busy")
        finally:
            get_db().remove()

    threads = [threading.Thread(target=register_one) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(outcome == "busy" for outcome in outcomes) == [False, True]
    get_db().expire_all()
    assert len(get_db().execute(select(SVSRun)).all()) == 1


#
# the launcher's calls
#

def test_start():
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=5))

    run = _state(run.uuid)
    assert run.state == RunState.STARTED
    assert run.started_at == T0 + timedelta(minutes=5)
    assert run.observation_ends_at == T0 + timedelta(minutes=65)
    assert run.attribution_ends_at == T0 + timedelta(hours=25, minutes=5)
    assert [(e.kind, e.from_state, e.to_state) for e in _events(run.uuid)] == [
        (RunEventKind.REGISTERED, None, RunState.CREATED),
        (RunEventKind.TRANSITION, RunState.CREATED, RunState.STARTED),
        (RunEventKind.LAUNCHER_CALL, None, None),
    ]


def test_the_windows_start_at_the_whole_second_of_start():
    # stored to the second, a window from the exact time would round up past an alert of that second
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=5, milliseconds=600))

    run = _state(run.uuid)
    assert run.started_at == T0 + timedelta(minutes=5)
    assert run.observation_ends_at == T0 + timedelta(minutes=65)
    assert run.attribution_ends_at == T0 + timedelta(hours=25, minutes=5)


def test_a_call_that_does_not_apply_is_a_conflict_and_is_recorded():
    run = register(_registration(), LAUNCHER)
    start(run.uuid, LAUNCHER)

    with pytest.raises(RunStateConflict) as error:
        start(run.uuid, LAUNCHER)
    assert error.value.state == RunState.STARTED

    *_, event = _events(run.uuid)
    assert event.kind == RunEventKind.LAUNCHER_CALL
    assert json.loads(event.details) == {"call": "start", "outcome": "conflict", "payload": {}}
    assert _state(run.uuid).state == RunState.STARTED


def test_unknown_run():
    for call in (start, cancel):
        with pytest.raises(UnknownRun):
            call("00000000-0000-4000-8000-000000000000", LAUNCHER)


def test_executed_records_a_success():
    run = register(_registration(), LAUNCHER)
    start(run.uuid, LAUNCHER)
    executed(run.uuid, LAUNCHER, 0, now=T0)

    run = _state(run.uuid)
    assert (run.state, run.exit_code, run.executed_at, run.launcher_error) == (RunState.STARTED, 0, T0, None)
    assert json.loads(_events(run.uuid)[-1].details) == {
        "call": "executed", "outcome": "recorded", "payload": {"exit_code": 0, "error": None}}


def test_executed_keeps_what_the_test_printed(caplog):
    run = register(_registration(), LAUNCHER)
    start(run.uuid, LAUNCHER)
    caplog.set_level(logging.INFO)
    executed(run.uuid, LAUNCHER, 1, output="Executing test: T1059.001-1\nAccess is denied.\n", now=T0)

    run = _state(run.uuid)
    # loading a run doesn't load its output, only reading it does
    assert "launcher_output" in inspect(run).unloaded
    assert (run.state, run.launcher_output) == (RunState.ERROR, "Executing test: T1059.001-1\nAccess is denied.\n")
    # the event log and the log record say how much, not what
    assert json.loads(_events(run.uuid)[-1].details)["payload"] == {
        "exit_code": 1, "error": None, "output_bytes": 46, "output_truncated": False}
    (record,) = [r for r in caplog.records if getattr(r, "call", None) == "executed"]
    assert (record.svs_run, record.output_bytes, record.output_truncated) == (run.uuid, 46, False)


def test_long_output_keeps_its_start_and_its_end():
    output = "a" * 100_000 + "é" + "z" * 20_000 + "the error"
    kept, size, truncated = runs.truncate_output(output)
    assert truncated and size == len(output.encode("utf-8"))
    assert len(kept.encode("utf-8")) <= runs.MAX_OUTPUT_BYTES
    assert kept.startswith("a" * 1000) and kept.endswith("z" * 1000 + "the error")
    assert re.search(r"\[\.\.\. svs: \d+ bytes of output left out \.\.\.\]", kept)

    # a cut inside a multibyte character drops that character: both cuts split a 3-byte "€"
    kept, size, truncated = runs.truncate_output("€" * 30_000)
    assert truncated and size == 90_000 and len(kept.encode("utf-8")) <= runs.MAX_OUTPUT_BYTES
    assert kept.startswith("€") and kept.endswith("€")

    # whole when it fits, and only valid text is kept
    assert runs.truncate_output("ok\n") == ("ok\n", 3, False)
    assert runs.truncate_output("bad \ud800 surrogate")[0] == "bad ? surrogate"


@pytest.mark.parametrize("exit_code, error", [(1, None), (0, "Invoke-AtomicTest failed")])
def test_executed_with_a_failure_moves_the_run_to_error(exit_code, error):
    run = register(_registration(), LAUNCHER)
    start(run.uuid, LAUNCHER)
    executed(run.uuid, LAUNCHER, exit_code, error)

    run = _state(run.uuid)
    assert run.state == RunState.ERROR and run.launcher_error == error
    assert "the launcher reported a failure" in run.error_reason
    assert (RunState.STARTED, RunState.ERROR) in [(e.from_state, e.to_state) for e in _events(run.uuid)]


def test_executed_before_start_is_a_conflict():
    run = register(_registration(), LAUNCHER)
    with pytest.raises(RunStateConflict):
        executed(run.uuid, LAUNCHER, 0)
    assert _state(run.uuid).executed_at is None


def test_cleanup_is_recorded_once_on_a_started_run(caplog):
    run = register(_registration(), LAUNCHER, now=T0)
    with pytest.raises(RunStateConflict):
        cleanup(run.uuid, LAUNCHER, now=T0)

    start(run.uuid, LAUNCHER, now=T0)
    caplog.set_level(logging.INFO)
    cleanup(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=3))
    assert _state(run.uuid).cleanup_at == T0 + timedelta(minutes=3)
    event = _events(run.uuid)[-1]
    assert (event.kind, json.loads(event.details)) == (RunEventKind.LAUNCHER_CALL, {
        "call": "cleanup", "outcome": "recorded", "payload": {"cleanup_at": (T0 + timedelta(minutes=3)).isoformat()}})
    (record,) = [r for r in caplog.records if getattr(r, "call", None) == "cleanup" and r.outcome == "recorded"]
    assert record.svs_run == run.uuid

    # once: the second call is a conflict, recorded, and changes nothing
    with pytest.raises(RunStateConflict):
        cleanup(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=4))
    assert _state(run.uuid).cleanup_at == T0 + timedelta(minutes=3)
    assert json.loads(_events(run.uuid)[-1].details)["outcome"] == "conflict"


def test_cleanup_begins_at_the_whole_second_of_the_call():
    # stored from the exact time, it would round up past a cleanup detection of that second
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)
    returned = cleanup(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=3, milliseconds=600))

    assert returned.cleanup_at == _state(run.uuid).cleanup_at == T0 + timedelta(minutes=3)
    assert json.loads(_events(run.uuid)[-1].details)["payload"] == {
        "cleanup_at": (T0 + timedelta(minutes=3)).isoformat()}


def test_cancel_a_started_run_keeps_its_windows():
    run = register(_registration(), LAUNCHER)
    start(run.uuid, LAUNCHER)
    cancel(run.uuid, LAUNCHER)

    run = _state(run.uuid)
    assert run.state == RunState.CANCELED and run.canceled_at is not None and run.attribution_ends_at is not None
    assert HOOKS == []
    with pytest.raises(RunStateConflict):
        cancel(run.uuid, LAUNCHER)


def test_cancel_before_start_closes_the_run():
    run = register(_registration(), LAUNCHER)
    cancel(run.uuid, LAUNCHER)

    run = _state(run.uuid)
    assert (run.state, run.close_reason) == (RunState.CLOSED, "canceled before start")
    assert [(e.from_state, e.to_state) for e in _events(run.uuid) if e.kind == RunEventKind.TRANSITION] == [
        (RunState.CREATED, RunState.CANCELED), (RunState.CANCELED, RunState.CLOSED)]
    assert HOOKS == [("closed", run.uuid)]


#
# a person ending a run early
#

def _user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def test_a_person_ends_a_started_run_early(caplog):
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)
    caplog.set_level(logging.INFO)

    # to the second, as start is
    runs.end_by_person(run.uuid, "alice", _user_id(), "  the test failed: nothing will fire ",
                       now=T0 + timedelta(minutes=10, milliseconds=600))

    run = _state(run.uuid)
    end = T0 + timedelta(minutes=10)
    assert (run.state, run.ended_at, run.observation_ends_at, run.end_reason) == (
        RunState.ENDED, end, end, "the test failed: nothing will fire")
    # an alert the test causes anyway is still the run's, as late
    assert run.attribution_ends_at == T0 + timedelta(hours=25)
    event = _events(run.uuid)[-1]
    assert (event.kind, event.from_state, event.to_state, event.actor, json.loads(event.details)) == (
        RunEventKind.TRANSITION, RunState.STARTED, RunState.ENDED, "alice",
        {"reason": "the test failed: nothing will fire"})
    (record,) = [r for r in caplog.records if getattr(r, "to_state", None) == RunState.ENDED]
    assert (record.svs_run, record.actor, record.reason) == (run.uuid, "alice", "the test failed: nothing will fire")
    # its result is computed now, and the timers have nothing left to do with it
    assert HOOKS == [("ended", run.uuid)]
    assert run_timers(T0 + timedelta(hours=2)).ended == 0
    assert HOOKS == [("ended", run.uuid)]


def test_ending_a_run_early_needs_a_started_run_and_a_reason():
    run = register(_registration(), LAUNCHER, now=T0)
    with pytest.raises(RunStateConflict):
        runs.end_by_person(run.uuid, "alice", _user_id(), "nothing fired", now=T0)

    start(run.uuid, LAUNCHER, now=T0)
    with pytest.raises(runs.ReasonRequired):
        runs.end_by_person(run.uuid, "alice", _user_id(), "  ", now=T0 + timedelta(minutes=1))
    assert _state(run.uuid).state == RunState.STARTED

    run_timers(T0 + timedelta(hours=1))
    with pytest.raises(RunStateConflict):
        runs.end_by_person(run.uuid, "alice", _user_id(), "nothing fired", now=T0 + timedelta(hours=1, minutes=1))
    assert _state(run.uuid).end_reason is None
    with pytest.raises(UnknownRun):
        runs.end_by_person("00000000-0000-4000-8000-000000000000", "alice", _user_id(), "nothing fired")


def test_ending_a_run_the_timers_end_meanwhile_is_a_conflict(monkeypatch):
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)
    get_run = runs.get_run

    def timers_of_another_process():
        try:
            run_timers(T0 + timedelta(hours=1))
        finally:
            get_db().remove()

    # the timers end it in their own session, so the run end_by_person read still says Started
    def read_then_the_timers_end_it(run_uuid):
        read = get_run(run_uuid)
        timers = threading.Thread(target=timers_of_another_process)
        timers.start()
        timers.join(30)
        assert not timers.is_alive()
        return read

    monkeypatch.setattr(runs, "get_run", read_then_the_timers_end_it)
    with pytest.raises(RunStateConflict):
        runs.end_by_person(run.uuid, "alice", _user_id(), "nothing fired", now=T0 + timedelta(hours=1))
    monkeypatch.undo()

    # the timers' end stands, once
    run = _state(run.uuid)
    assert (run.end_reason, run.ended_at) == (None, T0 + timedelta(hours=1))
    assert [e.actor for e in _events(run.uuid) if e.to_state == RunState.ENDED] == ["svs"]


def test_ending_a_run_whose_window_passed_before_the_timers_ended_it_keeps_its_window():
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)

    runs.end_by_person(run.uuid, "alice", _user_id(), "nothing fired", now=T0 + timedelta(hours=1, minutes=5))
    run = _state(run.uuid)
    assert (run.observation_ends_at, run.ended_at) == (T0 + timedelta(hours=1), T0 + timedelta(hours=1, minutes=5))


def test_a_run_ended_early_frees_its_hosts():
    first = register(_registration(), LAUNCHER, now=T0)
    start(first.uuid, LAUNCHER, now=T0)
    runs.end_by_person(first.uuid, "alice", _user_id(), "nothing fired", now=T0 + timedelta(minutes=10))

    second = register(_registration(), LAUNCHER, now=T0 + timedelta(minutes=11))
    start(second.uuid, LAUNCHER, now=T0 + timedelta(minutes=11))
    assert _state(second.uuid).state == RunState.STARTED


def test_a_run_ended_early_whose_test_holds_the_host_still_holds_it():
    set_test_settings(GUID, None, holds_host=True)
    first = register(_registration(), LAUNCHER, now=T0)
    start(first.uuid, LAUNCHER, now=T0)
    runs.end_by_person(first.uuid, "alice", _user_id(), "nothing fired", now=T0 + timedelta(minutes=10))

    with pytest.raises(HostBusy) as error:
        register(_registration(), LAUNCHER, now=T0 + timedelta(hours=2))
    assert error.value.holders == [HostHolder("win10-01", first.uuid, RunState.ENDED, T0 + timedelta(hours=25))]


#
# timers
#

def test_a_run_never_started_times_out_and_is_closed():
    run = register(_registration(), LAUNCHER, now=T0)

    assert run_timers(T0 + timedelta(minutes=29)).timed_out == 0
    assert run_timers(T0 + timedelta(minutes=30)).timed_out == 1

    run = _state(run.uuid)
    assert (run.state, run.close_reason) == (RunState.CLOSED, "start timeout")
    assert run.error_reason == "start was not called within 30 minutes"
    assert [(e.from_state, e.to_state, e.actor) for e in _events(run.uuid) if e.kind == RunEventKind.TRANSITION] == [
        (RunState.CREATED, RunState.ERROR, "svs"), (RunState.ERROR, RunState.CLOSED, "svs")]
    assert HOOKS == [("closed", run.uuid)]


def test_a_started_run_ends_after_its_observation_window():
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)

    assert run_timers(T0 + timedelta(minutes=59)).ended == 0
    assert run_timers(T0 + timedelta(minutes=60)).ended == 1
    run = _state(run.uuid)
    assert (run.state, run.ended_at) == (RunState.ENDED, T0 + timedelta(minutes=60))
    assert HOOKS == [("ended", run.uuid)]

    # an Ended run waits for a person
    assert run_timers(T0 + timedelta(days=30)) == runs.TimerResult()
    assert _state(run.uuid).state == RunState.ENDED


@pytest.mark.parametrize("finish", ["cancel", "error"])
def test_a_canceled_or_failed_run_is_closed_after_its_attribution_window(finish):
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)
    if finish == "cancel":
        cancel(run.uuid, LAUNCHER, now=T0 + timedelta(minutes=1))
    else:
        executed(run.uuid, LAUNCHER, 1, now=T0 + timedelta(minutes=1))

    # it keeps attributing past its observation window
    assert run_timers(T0 + timedelta(hours=24)).closed == 0
    assert _state(run.uuid).state in (RunState.CANCELED, RunState.ERROR)

    assert run_timers(T0 + timedelta(hours=25)).closed == 1
    run = _state(run.uuid)
    assert (run.state, run.close_reason) == (RunState.CLOSED, "attribution window ended")
    assert HOOKS == [("closed", run.uuid)]


def test_a_timer_that_fires_twice_changes_nothing():
    run = register(_registration(), LAUNCHER, now=T0)
    start(run.uuid, LAUNCHER, now=T0)

    # a second timer read the run while it was Started, but the first one ended it
    stale = runs.get_run(run.uuid)
    assert run_timers(T0 + timedelta(hours=2)).ended == 1
    assert runs._end(stale, T0 + timedelta(hours=3)) is False

    assert len([e for e in _events(run.uuid) if e.to_state == RunState.ENDED]) == 1
    assert _state(run.uuid).ended_at == T0 + timedelta(hours=2)
    assert HOOKS == [("ended", run.uuid)]


def test_a_run_that_fails_to_move_does_not_stop_the_others(monkeypatch):
    first = register(_registration(), LAUNCHER, now=T0)
    second = register(_registration(targets=[TargetSpec("anyuser-01")]), LAUNCHER, now=T0)
    failing = first.uuid

    real_end = runs._end

    def end(run, now):
        if run.uuid == failing:
            raise RuntimeError("database went away")
        return real_end(run, now)

    monkeypatch.setattr(runs, "_end", end)
    for run in (first, second):
        start(run.uuid, LAUNCHER, now=T0)

    assert run_timers(T0 + timedelta(hours=2)).ended == 1
    assert _state(first.uuid).state == RunState.STARTED
    assert _state(second.uuid).state == RunState.ENDED


#
# service_svs
#

def test_the_service_moves_runs(monkeypatch):
    # the uuid now: the catalog refresh retires the fixture's unconfigured repository and expires the run
    uuid = register(_registration(), LAUNCHER, now=datetime.now() - timedelta(hours=1)).uuid

    SVSService().start_single_threaded()

    assert _state(uuid).state == RunState.CLOSED


def test_the_run_timer_runs_until_stopped_and_survives_a_failure(monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database went away")

    monkeypatch.setattr(svs_service, "run_timers", flaky)
    monkeypatch.setattr(svs_service, "refresh_catalog", lambda **kwargs: [])
    monkeypatch.setattr(get_config().svs.runs, "timer_interval_seconds", 0.05)
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    service = SVSService()
    service.start()
    try:
        deadline = time.time() + 10
        while len(calls) < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert len(calls) >= 2 and service.runs.thread.is_alive()
    finally:
        service.stop()
        service.wait()
    assert not service.runs.thread.is_alive()


def test_the_run_timer_stays_idle_off_the_primary_node(monkeypatch):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    service = SVSService()
    service.start()
    assert service.runs is None
    service.stop()


def test_a_single_threaded_service_is_finished_when_it_returns():
    """`ace service start --single-threaded svs` waits on wait() after start_single_threaded()."""
    service = SVSService()
    service.start_single_threaded()

    waiter = threading.Thread(target=service.wait, daemon=True)
    waiter.start()
    waiter.join(10)
    assert not waiter.is_alive()
