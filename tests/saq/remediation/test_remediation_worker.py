import pytest

from saq.configuration.schema import RemediatorConfig
from saq.constants import F_TEST
from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.remediation.collector import create_remediation_work_item
from saq.remediation.remediator import Remediator
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediationWorkItem, RemediatorResult, RemediatorStatus
from saq.remediation.worker import RemediationWorker
from tests.saq.remediation.test_remediator import TestRemediator

@pytest.fixture
def worker() -> RemediationWorker:
    return RemediationWorker(TestRemediator(
        RemediatorConfig(
            name="custom",
            display_name="Custom Remediator",
            description="Custom remediator for testing",
            observable_type=F_TEST,
            python_module="value",
            python_class="value"
        )))


@pytest.mark.unit
def test_remediation_worker(worker):
    assert worker.remediator.name == "custom"
    assert worker.remediator.observable_type == F_TEST
    assert worker.work_queue.empty()
    assert not worker.worker_threads
    assert not worker.startup_events
    assert not worker.shutdown_event.is_set()

@pytest.mark.unit
def test_handle_remediation_request(worker):
    remediation = Remediation(
        name="custom",
        type=F_TEST,
        key="test"
    )
    worker.handle_remediation_request(remediation)
    assert not worker.work_queue.empty()
    assert worker.work_queue.get() == remediation

@pytest.mark.unit
def test_handle_remediation_request_invalid_name(worker):
    remediation = Remediation(
        name="other",
        type=F_TEST,
        key="test"
    )
    with pytest.raises(ValueError):
        worker.handle_remediation_request(remediation)

@pytest.mark.integration
def test_remediate(worker):
    class _custom_remediator(Remediator):
        def remove(self, target: RemediationWorkItem) -> RemediatorResult:
            return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.remove", restore_key="restore_key")
        def restore(self, target: RemediationWorkItem) -> RemediatorResult:
            return RemediatorResult(status=RemediatorStatus.SUCCESS, message="TestRemediator.restore")

    remediation_id = RemediationTarget("custom", F_TEST, "test").queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    work_item = create_remediation_work_item(remediation)

    worker = RemediationWorker(_custom_remediator(RemediatorConfig(
        name="custom",
        display_name="Custom Remediator",
        description="Custom remediator for testing",
        observable_type=F_TEST,
        python_module="value",
        python_class="value"
    )))
    result = worker.remediate(work_item)
    assert isinstance(result, RemediatorResult)
    assert result.status == RemediatorStatus.SUCCESS
    assert result.message == "TestRemediator.remove"
    assert result.restore_key == "restore_key"

    remediation = get_db().query(Remediation).filter(Remediation.id == remediation.id).first()
    assert remediation
    assert remediation.name == "custom"
    assert remediation.type == F_TEST
    assert remediation.key == "test"
    assert remediation.action == RemediationAction.REMOVE.value
    assert remediation.user_id == get_config().global_settings.automation_user_id
    assert remediation.result == RemediatorStatus.SUCCESS.value
    assert remediation.restore_key == "restore_key"
    assert remediation.comment is None
    assert remediation.status == RemediationStatus.COMPLETED.value

    remediation_history = get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation.id).first()
    assert remediation_history
    assert remediation_history.remediation_id == remediation.id
    assert remediation_history.result == RemediatorStatus.SUCCESS.value
    assert remediation_history.message == "TestRemediator.remove"
    assert remediation_history.status == RemediationStatus.COMPLETED.value

@pytest.mark.integration
def test_remediate_exception_handling(worker):
    class _failing_remediator(Remediator):
        def remove(self, target: RemediationWorkItem) -> RemediatorResult:
            raise RuntimeError("Simulated failure during remediation")
        def restore(self, target: RemediationWorkItem) -> RemediatorResult:
            raise RuntimeError("Simulated failure during remediation")

    remediation_id = RemediationTarget("custom", F_TEST, "test_error").queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    work_item = create_remediation_work_item(remediation)

    worker = RemediationWorker(_failing_remediator(RemediatorConfig(
        name="custom",
        display_name="Custom Remediator",
        description="Custom remediator for testing",
        observable_type=F_TEST,
        python_module="value",
        python_class="value"
    )))
    result = worker.remediate(work_item)
    assert isinstance(result, RemediatorResult)
    assert result.status == RemediatorStatus.ERROR
    assert result.message == "RuntimeError: Simulated failure during remediation"

    remediation = get_db().query(Remediation).filter(Remediation.id == remediation.id).first()
    assert remediation
    assert remediation.name == "custom"
    assert remediation.type == F_TEST
    assert remediation.key == "test_error"
    assert remediation.action == RemediationAction.REMOVE.value
    assert remediation.user_id == get_config().global_settings.automation_user_id
    assert remediation.result == RemediatorStatus.ERROR.value
    assert remediation.restore_key is None
    assert remediation.comment is None
    assert remediation.status == RemediationStatus.COMPLETED.value

    remediation_history = get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation.id).first()
    assert remediation_history
    assert remediation_history.remediation_id == remediation.id
    assert remediation_history.result == RemediatorStatus.ERROR.value
    assert remediation_history.message == "RuntimeError: Simulated failure during remediation"
    assert remediation_history.status == RemediationStatus.COMPLETED.value

@pytest.mark.parametrize("thread_count", [1, 2])
@pytest.mark.integration
def test_worker_lifecycle(worker, thread_count):
    assert isinstance(worker, RemediationWorker)
    # no threads created yet
    assert not worker.worker_threads
    assert not worker.startup_events
    worker.remediator.config.thread_count = thread_count
    worker.queue_wait_timeout = 0.1 # speed up the test
    worker.start()
    # threads and startup events created
    assert len(worker.worker_threads) == thread_count
    assert len(worker.startup_events) == thread_count
    assert worker.wait_for_start(5)
    # all should be running at this point
    for thread in worker.worker_threads:
        assert thread.is_alive()
    assert not worker.shutdown_event.is_set()
    worker.stop()
    # signal to stop should be set
    assert worker.shutdown_event.is_set()
    worker.wait()
    # all should be stopped at this point
    for thread in worker.worker_threads:
        assert not thread.is_alive()
