"""The SVS logging contract (docs/SVS.md, Part 5, *Logging contract*): every record about a run
carries svs_run, svs_test and svs_marker in extra, plus the fields of its row in the table. The
table is a contract; this keeps a refactor from dropping a field."""

import logging
from datetime import datetime, timedelta

import pytest

from saq.svs.hosts import build_spec, create_host
from saq.svs.refusals import Caller
from saq.svs.runs import Registration, RegistrationRefused, TargetSpec, cancel, executed, register, run_timers, start
from tests.saq.svs.conftest import add_catalog_test

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")
T0 = datetime(2026, 10, 14, 12, 0, 0)

RUN_FIELDS = ("svs_run", "svs_test", "svs_marker")
TRANSITION_FIELDS = RUN_FIELDS + ("from_state", "to_state", "actor")
LAUNCHER_CALL_FIELDS = RUN_FIELDS + ("launcher", "call", "outcome")
REFUSAL_FIELDS = ("caller", "host", "reason", "launcher", "svs_test")


@pytest.fixture(autouse=True)
def setup(no_hunts):
    add_catalog_test(GUID)
    create_host(build_spec("win10-01"), None)


def _registration(hostname: str = "win10-01") -> Registration:
    return Registration(test_guid=GUID, targets=[TargetSpec(hostname)], launcher="art")


def _records(caplog, prefix: str) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage().startswith(prefix)]


def _assert_fields(record: logging.LogRecord, fields: tuple[str, ...]):
    missing = [name for name in fields if not hasattr(record, name)]
    assert not missing, f"{record.getMessage()!r} lacks {missing}"


def test_lifecycle_transitions(caplog):
    with caplog.at_level(logging.INFO):
        first = register(_registration(), LAUNCHER, now=T0)
        start(first.uuid, LAUNCHER, now=T0)
        executed(first.uuid, LAUNCHER, 1, now=T0)
        second = register(_registration(), LAUNCHER, now=T0)
        cancel(second.uuid, LAUNCHER, now=T0)
        third = register(_registration(), LAUNCHER, now=T0)
        start(third.uuid, LAUNCHER, now=T0)
        run_timers(T0 + timedelta(days=2))

    records = _records(caplog, "svs run ")
    assert {(r.from_state, r.to_state) for r in records} == {
        (None, "created"), ("created", "started"), ("started", "error"), ("created", "canceled"),
        ("canceled", "closed"), ("started", "ended"), ("error", "closed")}
    for record in records:
        assert record.levelno == logging.INFO
        _assert_fields(record, TRANSITION_FIELDS)
    assert {r.svs_run for r in records} == {first.uuid, second.uuid, third.uuid}
    assert {r.actor for r in records} == {"art-launcher", "svs"}


def test_launcher_calls(caplog):
    with caplog.at_level(logging.INFO):
        run = register(_registration(), LAUNCHER)
        start(run.uuid, LAUNCHER)
        executed(run.uuid, LAUNCHER, 0)
        cancel(run.uuid, LAUNCHER)

    records = _records(caplog, "svs launcher call")
    assert [(r.call, r.outcome) for r in records] == [
        ("register", "created"), ("start", "started"), ("executed", "recorded"), ("cancel", "canceled")]
    for record in records:
        assert record.levelno == logging.INFO and record.svs_run == run.uuid
        _assert_fields(record, LAUNCHER_CALL_FIELDS)


def test_a_refused_registration(caplog):
    with caplog.at_level(logging.INFO), pytest.raises(RegistrationRefused):
        register(_registration("prod-dc-01"), LAUNCHER)

    (refusal,) = _records(caplog, "svs run registration refused")
    assert refusal.levelno == logging.WARNING and refusal.caller == "art-launcher"
    _assert_fields(refusal, REFUSAL_FIELDS)

    (call,) = _records(caplog, "svs launcher call")
    assert (call.levelno, call.call, call.outcome, call.caller) == (logging.WARNING, "register", "refused", "art-launcher")
