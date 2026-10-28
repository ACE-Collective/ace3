import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import F_TEST, SERVICE_REMEDIATION
from saq.database.model import Remediation
from saq.database.pool import get_db
from saq.remediation.service import RemediationService
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus
from tests.saq.helpers import wait_for_condition


def _queue(key: str) -> int:
    # remediator_test (etc/saq.unittest.default.yaml) is named "test"
    return RemediationTarget("test", F_TEST, key).queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)


def _status(remediation_id: int) -> str:
    get_db().expire_all()
    return get_db().query(Remediation).filter(Remediation.id == remediation_id).one().status


@pytest.mark.integration
def test_start_single_threaded_remediates_everything_due():
    ids = [_queue("one"), _queue("two"), _queue("three")]

    service = RemediationService()
    service.start_single_threaded()

    assert [_status(remediation_id) for remediation_id in ids] == [RemediationStatus.COMPLETED.value] * 3

    # `ace service start` stops and waits for the service after it returns
    service.stop()
    service.wait()


@pytest.mark.integration
def test_start_single_threaded_stops_on_shutdown(monkeypatch):
    ids = [_queue("one"), _queue("two"), _queue("three")]
    # shutdown is requested (as a signal would) while the first item is being worked
    checks = iter([False])
    monkeypatch.setattr("saq.queue_service.is_shutting_down", lambda: next(checks, True))

    service = RemediationService()
    service.start_single_threaded()

    assert [_status(remediation_id) for remediation_id in ids].count(RemediationStatus.COMPLETED.value) == 1
    service.stop()
    service.wait()


@pytest.mark.integration
def test_service_lifecycle():
    remediation_id = _queue("one")

    service = RemediationService()
    service.start()
    try:
        assert service.wait_for_start(5)
        wait_for_condition(lambda: _status(remediation_id) == RemediationStatus.COMPLETED.value)
    finally:
        service.stop()
        service.wait()

    assert all(not thread.is_alive() for worker in service.manager.workers.values() for thread in worker.worker_threads)
    assert not service.manager.collector.collector_thread.is_alive()


@pytest.mark.unit
def test_service_passes_config_to_manager():
    config = get_service_config(SERVICE_REMEDIATION)
    config.lock_timeout_seconds = 11
    config.delay_time_seconds = 12

    collector = RemediationService().create_manager().collector

    assert (collector.lock_timeout_seconds, collector.delay_time_seconds) == (11, 12)
