import multiprocessing

import pytest
from pydantic import ValidationError
from unittest.mock import Mock, patch, call

from saq.llm.embedding.service import (
    FAILED_TASK_KEY,
    MAX_TASK_ATTEMPTS,
    MAX_TASK_DEFERRALS,
    TASK_KEY,
    AlertLockUnavailable,
    EmbeddingManager,
    EmbeddingServiceConfig,
    EmbeddingWorker,
    EmbeddingTask,
)


@pytest.fixture
def worker():
    return EmbeddingWorker(name="worker-0")


@pytest.fixture
def task():
    return EmbeddingTask(alert_uuid="test-alert-uuid")


@pytest.mark.unit
class TestExecuteTask:
    def test_lock_acquired_alert_exists(self, worker, task):
        """Verify acquire, load, vectorize, release all called correctly."""
        mock_alert = Mock()

        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert", return_value=mock_alert) as mock_load,
            patch("saq.llm.embedding.service.vectorize") as mock_vectorize,
        ):
            worker.execute_task(task)

            mock_acquire.assert_called_once()
            acquire_args = mock_acquire.call_args
            assert acquire_args[0][0] == "test-alert-uuid"
            lock_uuid = acquire_args[0][1]
            assert acquire_args[1]["lock_owner"] == "EmbeddingWorker(worker-0)"

            mock_load.assert_called_once_with("test-alert-uuid")
            mock_vectorize.assert_called_once_with(mock_alert)

            mock_release.assert_called_once_with("test-alert-uuid", lock_uuid)

    def test_lock_not_acquired(self, worker, task):
        """Verify load_alert/vectorize NOT called when lock fails.

        A locked alert raises AlertLockUnavailable rather than returning silently, so the
        caller can defer the task instead of dropping it."""
        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=False) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert") as mock_load,
            patch("saq.llm.embedding.service.vectorize") as mock_vectorize,
        ):
            with pytest.raises(AlertLockUnavailable):
                worker.execute_task(task)

            mock_acquire.assert_called_once()
            mock_load.assert_not_called()
            mock_vectorize.assert_not_called()
            mock_release.assert_not_called()

    def test_vectorize_exception_releases_lock(self, worker, task):
        """Verify lock is released even when vectorize raises."""
        mock_alert = Mock()

        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert", return_value=mock_alert),
            patch("saq.llm.embedding.service.vectorize", side_effect=RuntimeError("vectorize failed")),
        ):
            with pytest.raises(RuntimeError, match="vectorize failed"):
                worker.execute_task(task)

            lock_uuid = mock_acquire.call_args[0][1]
            mock_release.assert_called_once_with("test-alert-uuid", lock_uuid)

    def test_load_alert_exception_releases_lock(self, worker, task):
        """Verify lock is released even when load_alert raises."""
        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert", side_effect=RuntimeError("db error")),
            patch("saq.llm.embedding.service.vectorize") as mock_vectorize,
        ):
            with pytest.raises(RuntimeError, match="db error"):
                worker.execute_task(task)

            lock_uuid = mock_acquire.call_args[0][1]
            mock_release.assert_called_once_with("test-alert-uuid", lock_uuid)
            mock_vectorize.assert_not_called()

    def test_alert_not_found(self, worker, task):
        """Verify vectorize NOT called when alert not found, lock still released."""
        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert", return_value=None),
            patch("saq.llm.embedding.service.vectorize") as mock_vectorize,
        ):
            worker.execute_task(task)

            mock_vectorize.assert_not_called()
            lock_uuid = mock_acquire.call_args[0][1]
            mock_release.assert_called_once_with("test-alert-uuid", lock_uuid)

    def test_unique_lock_uuid_per_call(self, worker):
        """Verify different lock_uuids are generated for each call."""
        task1 = EmbeddingTask(alert_uuid="alert-1")
        task2 = EmbeddingTask(alert_uuid="alert-2")

        lock_uuids = []

        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock"),
            patch("saq.database.model.load_alert", return_value=None),
            patch("saq.llm.embedding.service.vectorize"),
        ):
            worker.execute_task(task1)
            worker.execute_task(task2)

            assert mock_acquire.call_count == 2
            lock_uuids = [c[0][1] for c in mock_acquire.call_args_list]
            assert lock_uuids[0] != lock_uuids[1]


BASE_SERVICE_CONFIG = {
    "name": "llm_embedding",
    "python_module": "saq.llm.embedding.service",
    "python_class": "EmbeddingService",
    "description": "LLM Embedding - embeds alerts into a vector space",
    "enabled": True,
}


@pytest.mark.unit
class TestWorkerCount:
    @pytest.mark.parametrize("worker_count", [None, 3])
    def test_manager_worker_count(self, worker_count):
        """Verify the manager defaults to the cpu count and honors an explicit count."""
        manager = EmbeddingManager(worker_count=worker_count)
        assert manager.worker_count == (multiprocessing.cpu_count() if worker_count is None else worker_count)

    def test_manager_default_argument(self):
        """Verify omitting the argument entirely is the same as passing None."""
        assert EmbeddingManager().worker_count == multiprocessing.cpu_count()

    def test_manager_starts_configured_number_of_workers(self):
        manager = EmbeddingManager(worker_count=3)
        with patch.object(EmbeddingWorker, "start") as mock_start:
            manager.start()

        assert mock_start.call_count == 3
        assert len(manager.workers) == 3
        assert [worker.name for worker in manager.workers] == ["worker-0", "worker-1", "worker-2"]

    def test_config_worker_count_omitted(self):
        assert EmbeddingServiceConfig.model_validate(BASE_SERVICE_CONFIG).worker_count is None

    def test_config_worker_count_specified(self):
        assert EmbeddingServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"worker_count": 4}).worker_count == 4

    def test_config_worker_count_invalid(self):
        with pytest.raises(ValidationError):
            EmbeddingServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"worker_count": 0})


@pytest.mark.unit
class TestTaskRecovery:
    """Tasks are removed from redis by BLPOP before they run, so anything that goes wrong
    after that point loses the alert permanently unless it is explicitly put back."""

    def test_task_deserializes_without_new_fields(self):
        """Tasks queued before this change was deployed were serialized without the
        attempt/deferrals fields and must still validate."""
        task = EmbeddingTask.model_validate_json('{"alert_uuid": "test-alert-uuid"}')
        assert task.alert_uuid == "test-alert-uuid"
        assert task.attempt == 0
        assert task.deferrals == 0

    def test_requeue_increments_attempt(self, worker, task):
        with patch("saq.llm.embedding.service.get_redis_connection") as mock_get_redis:
            worker.requeue_task(task)

        mock_redis = mock_get_redis.return_value
        mock_redis.rpush.assert_called_once()
        key, payload = mock_redis.rpush.call_args[0]
        assert key == TASK_KEY
        assert EmbeddingTask.model_validate_json(payload).attempt == 1

    def test_requeue_uses_tail_of_queue(self, worker, task):
        """rpush rather than lpush is what keeps a persistent failure from becoming a hot
        retry loop, so it is asserted explicitly."""
        with patch("saq.llm.embedding.service.get_redis_connection") as mock_get_redis:
            worker.requeue_task(task)

        mock_get_redis.return_value.lpush.assert_not_called()

    def test_requeue_dead_letters_at_cap(self, worker):
        task = EmbeddingTask(alert_uuid="test-alert-uuid", attempt=MAX_TASK_ATTEMPTS - 1)
        with patch("saq.llm.embedding.service.get_redis_connection") as mock_get_redis:
            worker.requeue_task(task)

        key, _ = mock_get_redis.return_value.rpush.call_args[0]
        assert key == FAILED_TASK_KEY

    def test_defer_increments_deferrals_not_attempt(self, worker, task):
        """A locked alert is 'not ready yet', not 'broken', so it must not consume a retry."""
        with patch("saq.llm.embedding.service.get_redis_connection") as mock_get_redis:
            worker.defer_task(task)

        key, payload = mock_get_redis.return_value.rpush.call_args[0]
        assert key == TASK_KEY
        requeued = EmbeddingTask.model_validate_json(payload)
        assert requeued.deferrals == 1
        assert requeued.attempt == 0

    def test_defer_dead_letters_at_cap(self, worker):
        task = EmbeddingTask(alert_uuid="test-alert-uuid", deferrals=MAX_TASK_DEFERRALS - 1)
        with patch("saq.llm.embedding.service.get_redis_connection") as mock_get_redis:
            worker.defer_task(task)

        key, _ = mock_get_redis.return_value.rpush.call_args[0]
        assert key == FAILED_TASK_KEY

    def test_worker_execute_requeues_on_error(self, worker, task):
        with (
            patch.object(EmbeddingWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch.object(EmbeddingWorker, "execute_task", side_effect=RuntimeError("boom")),
            patch.object(EmbeddingWorker, "requeue_task") as mock_requeue,
            patch("saq.llm.embedding.service.report_exception"),
            patch("saq.llm.embedding.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_requeue.assert_called_once()

    def test_worker_execute_defers_on_lock_unavailable(self, worker, task):
        with (
            patch.object(EmbeddingWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch.object(EmbeddingWorker, "execute_task", side_effect=AlertLockUnavailable("test-alert-uuid")),
            patch.object(EmbeddingWorker, "defer_task") as mock_defer,
            patch.object(EmbeddingWorker, "requeue_task") as mock_requeue,
            patch("saq.llm.embedding.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_defer.assert_called_once()
        mock_requeue.assert_not_called()

    def test_missing_alert_does_not_requeue(self, worker, task):
        """A deleted alert is a terminal success, not a failure to retry."""
        with (
            patch.object(EmbeddingWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch("saq.llm.embedding.service.acquire_lock", return_value=True),
            patch("saq.llm.embedding.service.release_lock"),
            patch("saq.database.model.load_alert", return_value=None),
            patch.object(EmbeddingWorker, "requeue_task") as mock_requeue,
            patch.object(EmbeddingWorker, "defer_task") as mock_defer,
            patch("saq.llm.embedding.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_requeue.assert_not_called()
        mock_defer.assert_not_called()
