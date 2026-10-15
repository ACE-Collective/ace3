"""SVS test runs (saq.svs.runs, docs/SVS_RUNS.md): registration, the launcher's calls, the timers."""

import json
import threading
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from saq.configuration.config import get_config
from saq.database.model import SVSRegistrationRefusal, SVSRun, SVSRunEvent
from saq.database.pool import get_db
from saq.svs import runs
from saq.svs import service as svs_service
from saq.svs.constants import RunEventKind, RunState
from saq.svs.hosts import build_spec, create_host
from saq.svs.markers import MARKER_REGEX
from saq.svs.refusals import Caller
from saq.svs.runs import (
    InvalidRegistration,
    Registration,
    RegistrationRefused,
    RunStateConflict,
    TargetSpec,
    UnknownRun,
    cancel,
    executed,
    register,
    run_timers,
    start,
)
from saq.svs.service import SVSService
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LINUX_GUID = "bbbbbbbb-2222-4222-8222-222222222222"
REMOVED_GUID = "cccccccc-3333-4333-8333-333333333333"

LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")

T0 = datetime(2026, 10, 14, 12, 0, 0)


@pytest.fixture(autouse=True)
def setup(no_hunts, monkeypatch):
    add_catalog_test(GUID)
    add_catalog_test(LINUX_GUID, platforms=("linux", "macos"))
    add_catalog_test(REMOVED_GUID, removed=True)
    create_host(build_spec("win10-01.lab.example", usernames=["LAB\\svc_art"], platform="windows"), None)
    create_host(build_spec("anyuser-01"), None)
    monkeypatch.setattr(runs, "close_run_alerts", _record("closed"))
    monkeypatch.setattr(runs, "on_run_ended", _record("ended"))
    HOOKS.clear()


HOOKS: list[tuple[str, str]] = []


def _record(name: str):
    return lambda run, *args: HOOKS.append((name, run.uuid))


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
    assert get_db().execute(select(SVSRegistrationRefusal.host)).scalars().all() == [target.hostname.split(".")[0]]


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
    second = register(_registration(), LAUNCHER, now=T0)
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
    run = register(_registration(), LAUNCHER, now=datetime.now() - timedelta(hours=1))

    SVSService().start_single_threaded()

    assert _state(run.uuid).state == RunState.CLOSED


def test_the_run_timer_runs_until_stopped_and_survives_a_failure(monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database went away")

    monkeypatch.setattr(svs_service, "run_timers", flaky)
    monkeypatch.setattr(svs_service, "refresh_catalog", lambda **kwargs: [])
    monkeypatch.setattr(get_config().svs.runs, "timer_interval_seconds", 0.05)
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: True)
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
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: False)
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
