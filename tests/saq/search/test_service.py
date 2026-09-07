from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from saq.search.service import (
    DEFAULT_WORKER_COUNT,
    MAX_TASK_ATTEMPTS,
    MAX_TASK_DEFERRALS,
    AlertLockUnavailable,
    SearchIndexerServiceConfig,
    SearchIndexManager,
    SearchIndexService,
    SearchIndexWorker,
)
from saq.search.tasks import (
    FAILED_TASK_KEY,
    OP_DELETE,
    OP_INDEX,
    OP_PAYLOAD,
    TASK_KEY,
    SearchIndexTask,
    submit_delete_task,
    submit_index_task,
    submit_payload_task,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def worker():
    return SearchIndexWorker(name="worker-0")


@pytest.fixture
def task():
    return SearchIndexTask(alert_uuid="test-alert-uuid")


class TestSubmit:
    def test_disabled_service_is_a_noop(self, monkeypatch):
        with patch("saq.search.tasks.get_redis_connection") as mock_redis:
            assert submit_index_task("u") is False
        mock_redis.assert_not_called()

    def test_missing_service_section_is_a_noop(self, monkeypatch):
        def raise_(name):
            raise ValueError("no such service")

        monkeypatch.setattr("saq.search.tasks.get_service_config", raise_)
        assert submit_index_task("u") is False

    @pytest.mark.parametrize("submit,op", [(submit_index_task, OP_INDEX), (submit_payload_task, OP_PAYLOAD), (submit_delete_task, OP_DELETE)])
    def test_ops_are_queued(self, enable_indexer, submit, op):
        with patch("saq.search.tasks.get_redis_connection") as mock_redis:
            assert submit("u") is True

        key, payload = mock_redis.return_value.rpush.call_args[0]
        assert key == TASK_KEY
        assert SearchIndexTask.model_validate_json(payload) == SearchIndexTask(alert_uuid="u", op=op)

    def test_redis_failure_returns_false(self, enable_indexer):
        with patch("saq.search.tasks.get_redis_connection", side_effect=RuntimeError("down")), patch("saq.search.tasks.report_exception"):
            assert submit_index_task("u") is False


class TestExecuteTask:
    def test_index_takes_and_releases_the_lock(self, worker, task):
        with (
            patch("saq.search.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.search.service.release_lock") as mock_release,
            patch("saq.search.service.index.index_alert") as mock_index,
        ):
            worker.execute_task(task)

        assert mock_acquire.call_args[0][0] == "test-alert-uuid"
        assert mock_acquire.call_args[1]["lock_owner"] == "SearchIndexWorker(worker-0)"
        lock_uuid = mock_acquire.call_args[0][1]
        mock_index.assert_called_once_with("test-alert-uuid", model=None)
        mock_release.assert_called_once_with("test-alert-uuid", lock_uuid)

    def test_locked_alert_raises_lock_unavailable(self, worker, task):
        with (
            patch("saq.search.service.acquire_lock", return_value=False),
            patch("saq.search.service.release_lock") as mock_release,
            patch("saq.search.service.index.index_alert") as mock_index,
        ):
            with pytest.raises(AlertLockUnavailable):
                worker.execute_task(task)

        mock_index.assert_not_called()
        mock_release.assert_not_called()

    def test_index_error_still_releases_lock(self, worker, task):
        with (
            patch("saq.search.service.acquire_lock", return_value=True) as mock_acquire,
            patch("saq.search.service.release_lock") as mock_release,
            patch("saq.search.service.index.index_alert", side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(RuntimeError):
                worker.execute_task(task)

        mock_release.assert_called_once_with("test-alert-uuid", mock_acquire.call_args[0][1])

    def test_payload_and_delete_do_not_lock(self, worker):
        with (
            patch("saq.search.service.acquire_lock") as mock_acquire,
            patch("saq.search.service.index.update_alert_payload") as mock_payload,
            patch("saq.search.service.index.delete_alert") as mock_delete,
        ):
            worker.execute_task(SearchIndexTask(alert_uuid="u", op=OP_PAYLOAD))
            worker.execute_task(SearchIndexTask(alert_uuid="u", op=OP_DELETE))

        mock_acquire.assert_not_called()
        mock_payload.assert_called_once_with("u")
        mock_delete.assert_called_once_with("u")


BASE_SERVICE_CONFIG = {
    "name": "search_indexer",
    "python_module": "saq.search.service",
    "python_class": "SearchIndexService",
    "description": "Search Indexer",
    "enabled": True,
}


class TestWorkerCount:
    def test_manager_defaults(self):
        assert SearchIndexManager().worker_count == DEFAULT_WORKER_COUNT
        assert SearchIndexManager(worker_count=3).worker_count == 3

    def test_manager_starts_configured_number_of_workers(self):
        manager = SearchIndexManager(worker_count=3)
        with patch.object(SearchIndexWorker, "start") as mock_start:
            manager.start()

        assert mock_start.call_count == 3
        assert [w.name for w in manager.workers] == ["worker-0", "worker-1", "worker-2"]

    def test_config_defaults_and_validation(self):
        assert SearchIndexerServiceConfig.model_validate(BASE_SERVICE_CONFIG).worker_count == DEFAULT_WORKER_COUNT
        assert SearchIndexerServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"worker_count": 4}).worker_count == 4
        with pytest.raises(ValidationError):
            SearchIndexerServiceConfig.model_validate(BASE_SERVICE_CONFIG | {"worker_count": 0})

    def test_service_config_class(self):
        assert SearchIndexService.get_config_class() is SearchIndexerServiceConfig


class TestWorkerLoop:
    def test_started_event_is_set_and_loop_exits_on_stop(self, worker):
        worker.model = Mock()
        worker.stop()
        worker.worker_loop()
        assert worker.started_event.is_set()

    def test_loop_prepares_once(self, worker):
        calls = []

        def prepare():
            calls.append(1)
            worker.model = Mock()

        worker.prepare = prepare
        worker.worker_execute = lambda: worker.stop()
        worker.worker_loop()
        assert calls == [1]

    def test_single_threaded_start_runs_the_loop(self):
        service = SearchIndexService()
        with patch.object(SearchIndexWorker, "worker_loop") as mock_loop:
            service.start_single_threaded()
        mock_loop.assert_called_once()
        service.stop()
        assert service.single_threaded_worker.is_shutdown


class TestTaskRecovery:
    """Tasks are removed from redis by BLPOP before they run, so anything that goes wrong
    after that point loses the alert permanently unless it is explicitly put back."""

    def test_legacy_task_deserializes(self):
        task = SearchIndexTask.model_validate_json('{"alert_uuid": "u"}')
        assert task.op == OP_INDEX and task.attempt == 0 and task.deferrals == 0

    def test_requeue_increments_attempt_at_tail(self, worker, task):
        with patch("saq.search.service.get_redis_connection") as mock_get_redis:
            worker.requeue_task(task)

        mock_redis = mock_get_redis.return_value
        key, payload = mock_redis.rpush.call_args[0]
        assert key == TASK_KEY
        assert SearchIndexTask.model_validate_json(payload).attempt == 1
        mock_redis.lpush.assert_not_called()

    def test_requeue_dead_letters_at_cap(self, worker):
        task = SearchIndexTask(alert_uuid="u", attempt=MAX_TASK_ATTEMPTS - 1)
        with patch("saq.search.service.get_redis_connection") as mock_get_redis:
            worker.requeue_task(task)
        assert mock_get_redis.return_value.rpush.call_args[0][0] == FAILED_TASK_KEY

    def test_defer_increments_deferrals_not_attempt(self, worker, task):
        with patch("saq.search.service.get_redis_connection") as mock_get_redis:
            worker.defer_task(task)

        key, payload = mock_get_redis.return_value.rpush.call_args[0]
        requeued = SearchIndexTask.model_validate_json(payload)
        assert key == TASK_KEY and requeued.deferrals == 1 and requeued.attempt == 0

    def test_defer_dead_letters_at_cap(self, worker):
        task = SearchIndexTask(alert_uuid="u", deferrals=MAX_TASK_DEFERRALS - 1)
        with patch("saq.search.service.get_redis_connection") as mock_get_redis:
            worker.defer_task(task)
        assert mock_get_redis.return_value.rpush.call_args[0][0] == FAILED_TASK_KEY

    def test_worker_execute_requeues_on_error(self, worker, task):
        with (
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch.object(SearchIndexWorker, "execute_task", side_effect=RuntimeError("boom")),
            patch.object(SearchIndexWorker, "requeue_task") as mock_requeue,
            patch("saq.search.service.report_exception"),
            patch("saq.search.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_requeue.assert_called_once()

    def test_worker_execute_defers_on_lock_unavailable(self, worker, task):
        with (
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch.object(SearchIndexWorker, "execute_task", side_effect=AlertLockUnavailable("u")),
            patch.object(SearchIndexWorker, "defer_task") as mock_defer,
            patch.object(SearchIndexWorker, "requeue_task") as mock_requeue,
            patch("saq.search.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_defer.assert_called_once()
        mock_requeue.assert_not_called()

    def test_missing_alert_does_not_requeue(self, worker, task):
        """A deleted alert is a terminal success, not a failure to retry."""
        with (
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch("saq.search.service.acquire_lock", return_value=True),
            patch("saq.search.service.release_lock"),
            patch("saq.search.index.load_alert", return_value=None),
            patch.object(SearchIndexWorker, "requeue_task") as mock_requeue,
            patch.object(SearchIndexWorker, "defer_task") as mock_defer,
            patch("saq.search.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        mock_requeue.assert_not_called()
        mock_defer.assert_not_called()
