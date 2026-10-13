"""service_svs (saq.svs.service): workers that claim, run and store the queued validations."""

import json
import threading
import time
import uuid
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_SVS
from saq.database.model import SVSValidation, SVSValidationResult, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.sandbox.runner import landlock_available
from saq.svs import actions, service as svs_service
from saq.svs.service import INTERNAL_ERROR, SVSService, SVSServiceConfig, ValidationWorker
from saq.svs.validations import claim, request_validation
from saq.svs.yara.diff import Category
from saq.svs.yara.replay import ReplayCancelled, ReplayError, ReplayResult, SideReport
from tests.saq.svs.conftest import RULE_UUID
from tests.saq.svs.yara.conftest import REPOSITORY, rule, stored_sample

BASE = "a" * 40
HEAD = "b" * 40

BASE_SERVICE_CONFIG = {
    "name": "svs",
    "python_module": "saq.svs.service",
    "python_class": "SVSService",
    "description": "SVS",
    "enabled": True,
}


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _request(base: str = BASE, head: str = HEAD) -> str:
    return request_validation(REPOSITORY, base, head, "feature", None, _user_id())[0]


def _row(validation_uuid: str) -> SVSValidation:
    get_db().commit()
    get_db().expire_all()
    return get_db().execute(select(SVSValidation).where(SVSValidation.uuid == validation_uuid)).scalar_one()


def _empty_result() -> ReplayResult:
    return ReplayResult(repository=REPOSITORY, base_sha=BASE, head_sha=HEAD, base=SideReport(sha=BASE),
                        head=SideReport(sha=HEAD), diffed=True,
                        counts={category.value: 0 for category in Category})


@pytest.mark.unit
def test_the_config_refuses_timings_that_cannot_work():
    config = SVSServiceConfig.model_validate(BASE_SERVICE_CONFIG)
    assert (config.heartbeat_interval_seconds, config.lease_seconds) == (30, 300)
    assert SVSService.get_config_class() is SVSServiceConfig

    with pytest.raises(ValidationError, match="must not exceed lease_seconds"):
        SVSServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"heartbeat_interval_seconds": 200})
    with pytest.raises(ValidationError, match="shutdown_deadline_seconds"):
        SVSServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"shutdown_deadline_seconds": 5})


@pytest.mark.integration
def test_the_service_runs_a_queued_validation(svs_repository):
    validation_uuid = _request()
    sha256 = stored_sample("DELIVERY", b"svs service sample", [RULE_UUID])
    actions.retire(sha256, RULE_UUID, _user_id(), "intended")

    with patch.object(svs_service, "run_replay", return_value=_empty_result()) as run_replay:
        SVSService().start_single_threaded()

    row = _row(validation_uuid)
    assert (row.state, row.attempts, row.claim_token) == ("completed", 1, None)
    assert row.corpus_version and row.engine_fingerprint
    args, kwargs = run_replay.call_args
    assert args == (REPOSITORY, BASE, HEAD)
    assert kwargs["branch"] == "feature"
    assert kwargs["retired"] == frozenset({(sha256, RULE_UUID)})


@pytest.mark.integration
def test_a_replay_error_fails_the_validation_with_its_message(svs_repository):
    validation_uuid = _request()
    with patch.object(svs_service, "run_replay", side_effect=ReplayError("commit x is not in repository")):
        SVSService().start_single_threaded()

    row = _row(validation_uuid)
    assert (row.state, row.error, row.active_key) == ("failed", "commit x is not in repository", None)


@pytest.mark.integration
def test_an_unexpected_error_fails_the_validation_without_its_details(svs_repository):
    validation_uuid = _request()
    with patch.object(svs_service, "run_replay", side_effect=OSError("/secret/path: no space left")):
        SVSService().start_single_threaded()

    assert (_row(validation_uuid).state, _row(validation_uuid).error) == ("failed", INTERNAL_ERROR)


def _wait_until_cancelled(*args, cancel, **kwargs):
    if not cancel.wait(30):
        raise AssertionError("the replay was never cancelled")
    raise ReplayCancelled("the validation was cancelled")


def _run_in_thread(worker: ValidationWorker, validation_uuid: str) -> threading.Thread:
    claimed = claim(worker.node, lease_seconds=worker.config.lease_seconds, max_attempts=worker.config.max_attempts)
    assert claimed.uuid == validation_uuid
    thread = threading.Thread(target=worker.execute, args=(claimed,), daemon=True)
    thread.start()
    # the worker is running the replay once it has an event to cancel
    deadline = time.monotonic() + 10
    while worker._cancel is None and time.monotonic() < deadline:
        time.sleep(0.05)
    return thread


@pytest.mark.integration
def test_stopping_returns_the_running_validation_to_the_queue(svs_repository):
    validation_uuid = _request()
    shutdown = threading.Event()
    worker = ValidationWorker(get_service_config(SERVICE_SVS), "node1", shutdown, "test-worker")
    with patch.object(svs_service, "run_replay", side_effect=_wait_until_cancelled):
        thread = _run_in_thread(worker, validation_uuid)
        shutdown.set()
        worker.cancel()
        thread.join(timeout=30)

    assert not thread.is_alive()
    row = _row(validation_uuid)
    assert (row.state, row.attempts, row.claim_token) == ("queued", 0, None)


@pytest.mark.integration
def test_a_worker_that_loses_its_lease_stops(svs_repository):
    validation_uuid = _request()
    config = get_service_config(SERVICE_SVS).model_copy(update={"heartbeat_interval_seconds": 1})
    worker = ValidationWorker(config, "node1", threading.Event(), "test-worker")
    with patch.object(svs_service, "run_replay", side_effect=_wait_until_cancelled):
        thread = _run_in_thread(worker, validation_uuid)
        # another worker took the validation over
        other_token = str(uuid.uuid4())
        with private_transaction() as session:
            session.execute(update(SVSValidation).where(SVSValidation.uuid == validation_uuid)
                            .values(claim_token=other_token, claimed_by="node2"))
        thread.join(timeout=30)

    assert not thread.is_alive()
    row = _row(validation_uuid)
    assert (row.state, row.claim_token, row.claimed_by) == ("running", other_token, "node2")


def _waiting(service: SVSService) -> threading.Thread:
    """wait() in a thread; it must not return before the service is stopped, or `ace service
    start` would take the service for finished."""
    waiter = threading.Thread(target=service.wait, daemon=True)
    waiter.start()
    waiter.join(timeout=1)
    assert waiter.is_alive()
    return waiter


@pytest.mark.integration
def test_the_service_stays_idle_off_the_primary_node(svs_repository, monkeypatch):
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: False)
    service = SVSService()
    service.start()
    assert service.workers == []
    waiter = _waiting(service)
    service.stop()
    waiter.join(timeout=5)
    assert not waiter.is_alive()


@pytest.mark.integration
def test_the_service_starts_its_workers_and_stops_them(svs_repository, monkeypatch):
    monkeypatch.setattr(svs_service, "is_primary_node", lambda: True)
    service = SVSService()
    service.start()
    assert [worker.thread.is_alive() for worker in service.workers] == [True]
    waiter = _waiting(service)
    service.stop()
    waiter.join(timeout=30)
    assert not waiter.is_alive()
    assert [worker.thread.is_alive() for worker in service.workers] == [False]


@pytest.mark.integration
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_a_whole_validation_through_the_service(svs_repository):
    rule_uuid = str(uuid.uuid4())
    sha256 = stored_sample("DELIVERY", b"alpha evil", [rule_uuid])
    base = svs_repository.commit({"yara/acme/rules.yar": rule("one", rule_uuid, '$a = "evil"')})
    head = svs_repository.commit({"yara/acme/rules.yar": rule("one", rule_uuid, '$a = "nothing"')}, branch="feature")
    validation_uuid = request_validation(REPOSITORY, base, head, "feature", None, _user_id())[0]

    SVSService().start_single_threaded()

    row = _row(validation_uuid)
    assert row.state == "completed", row.error
    assert (row.regressions, row.new_fps, row.compile_errors, row.diffed) == (1, 0, 0, True)
    assert json.loads(row.counts)["regression"] == 1
    (result,) = get_db().execute(select(SVSValidationResult)).scalars().all()
    assert (result.sha256, result.rule_uuid, result.category, result.label) == (sha256, rule_uuid, "regression", "tp")
