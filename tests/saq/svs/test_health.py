"""The health of service_svs (saq.svs.health, docs/SVS.md, Part 5, *Health*) and `ace svs status`."""

import argparse
import json
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.cli.commands.svs import cli_status
from saq.configuration.config import get_config
from saq.database.model import SVSRun, SVSServiceLoop, SVSValidation
from saq.database.private_session import private_transaction
from saq.svs import health, service as svs_service
from saq.svs.health import Loop, LoopState, record_pass, record_start, service_health
from saq.svs.service import CatalogRefresher, CoverageRefresher, RunTimer
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"


@pytest.fixture
def repositories(monkeypatch):
    """Something for the catalog and validation loops to do."""
    monkeypatch.setattr(get_config().svs.catalog, "repositories", ["atomics"])
    monkeypatch.setattr(get_config().svs.yara, "repositories", ["rules"])


def _loops() -> dict[Loop, health.LoopHealth]:
    return {loop.loop: loop for loop in service_health().loops}


def _age(loop: Loop, seconds: float) -> None:
    """The loop's last pass, that long ago by the database clock."""
    with private_transaction() as session:
        now = session.execute(select(health.func.now(6))).scalar()
        session.execute(update(SVSServiceLoop).where(SVSServiceLoop.name == loop.value)
                        .values(passed_at=now - timedelta(seconds=seconds)))


def test_a_service_that_never_ran(repositories):
    result = service_health()
    assert not result.healthy
    assert {loop.state for loop in result.loops} == {LoopState.NEVER}
    assert any("never ran" in problem for problem in result.problems)


def test_a_service_going_round(repositories):
    record_start(list(Loop))
    for loop in Loop:
        record_pass(loop)

    result = service_health()
    assert result.healthy, result.problems
    assert {loop.state for loop in result.loops} == {LoopState.OK}
    assert all(loop.node and loop.started_at and loop.age_seconds < 5 for loop in result.loops)


def test_loops_with_nothing_to_do_are_idle():
    """No catalog or rule repositories configured (the default)."""
    for loop in (Loop.TIMERS, Loop.COVERAGE):
        record_pass(loop)
    loops = _loops()
    assert (loops[Loop.CATALOG].state, loops[Loop.VALIDATIONS].state) == (LoopState.IDLE, LoopState.IDLE)
    assert service_health().healthy


def test_a_stopped_service_is_stale(repositories):
    for loop in Loop:
        record_pass(loop)
    # the timers run every 30s by default: stale after 90s
    _age(Loop.TIMERS, 80)
    assert _loops()[Loop.TIMERS].state == LoopState.OK
    _age(Loop.TIMERS, 100)
    result = service_health()
    assert _loops()[Loop.TIMERS].state == LoopState.STALE
    assert not result.healthy and "service_svs looks stopped" in result.problems[0]


def test_a_failing_loop(repositories):
    for loop in Loop:
        record_pass(loop)
    record_pass(Loop.COVERAGE, "the ATT&CK extract is missing")
    loop = _loops()[Loop.COVERAGE]
    assert (loop.state, loop.error) == (LoopState.FAILING, "the ATT&CK extract is missing")

    # a pass after the failure is healthy again, and the error is kept for reading
    record_pass(Loop.COVERAGE)
    assert _loops()[Loop.COVERAGE].state == LoopState.OK


def test_what_the_data_shows(no_hunts):
    for loop in Loop:
        record_pass(loop)
    add_catalog_test(GUID)
    add_test_host("win10-01")
    run = started_run(GUID, now=datetime.now() - timedelta(hours=3))
    with private_transaction() as session:
        # one waiting for an hour, and one whose worker stopped renewing its lease an hour ago
        for state, values in (("queued", {}), ("running", {"heartbeat_at": datetime.now() - timedelta(hours=1)})):
            session.add(SVSValidation(uuid=str(uuid.uuid4()), repository="rules", base_sha="a" * 40,
                                      head_sha="b" * 40, branch="main", state=state,
                                      created_at=datetime.now() - timedelta(hours=1), **values))

    result = service_health()
    assert (result.overdue_runs, result.oldest_overdue_run) == (1, run.uuid)
    assert (result.queued_validations, result.abandoned_validations) == (1, 1)
    assert result.oldest_queued_seconds > 3000 and result.warnings
    assert not result.healthy
    assert any("past their observation window" in problem for problem in result.problems)


@pytest.mark.parametrize("loop_class, loop, target", [
    (CatalogRefresher, Loop.CATALOG, "refresh_catalog"),
    (RunTimer, Loop.TIMERS, "run_timers"),
    (CoverageRefresher, Loop.COVERAGE, "refresh_coverage"),
])
def test_the_service_loops_record_their_passes(monkeypatch, repositories, loop_class, loop, target):
    monkeypatch.setattr(svs_service, target, lambda *args: None)
    loop_class(None).run_once()
    assert _loops()[loop].state == LoopState.OK

    def fail(*args):
        raise RuntimeError("database is gone")

    monkeypatch.setattr(svs_service, target, fail)
    loop_class(None).run_once()
    assert (_loops()[loop].state, _loops()[loop].error) == (LoopState.FAILING, "database is gone")


def test_the_status_command(capsys, repositories):
    args = argparse.Namespace(json=False)
    assert cli_status(args) == 1
    assert "NOT HEALTHY" in capsys.readouterr().out

    for loop in Loop:
        record_pass(loop)
    assert cli_status(args) == 0
    assert capsys.readouterr().out.startswith("service_svs: healthy")

    assert cli_status(argparse.Namespace(json=True)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["healthy"] and [loop["state"] for loop in report["loops"]] == ["ok"] * 4
