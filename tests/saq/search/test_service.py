import logging
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from saq.search.index import IndexResult
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
            patch("saq.search.service.index.index_alert", return_value=IndexResult(alert_uuid="test-alert-uuid", document_count=7, point_count=41)) as mock_index,
        ):
            outcome = worker.execute_task(task)

        assert outcome == {"documents": 7, "points": 41}
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
            assert worker.execute_task(SearchIndexTask(alert_uuid="u", op=OP_PAYLOAD)) == {"updated": mock_payload.return_value}
            assert worker.execute_task(SearchIndexTask(alert_uuid="u", op=OP_DELETE)) == {}

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


class TestLogging:
    """The indexer's INFO lines are the only thing an operator has to work with, so the event
    names and the extra={} fields are asserted like any other output. See saq/logging.py: the
    message is the event, the fields ride in extra={}."""

    @staticmethod
    def records(caplog, event: str) -> list[logging.LogRecord]:
        return [record for record in caplog.records if record.message == event]

    @staticmethod
    def run_task(worker, task, caplog, **index_patches):
        """Runs one task through worker_execute with redis and the db session stubbed out."""
        patches = {
            "index_alert": patch("saq.search.service.index.index_alert"),
            "update_alert_payload": patch("saq.search.service.index.update_alert_payload"),
            "delete_alert": patch("saq.search.service.index.delete_alert"),
        }
        patches.update(index_patches)
        with (
            caplog.at_level(logging.INFO),
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch("saq.search.service.acquire_lock", return_value=True),
            patch("saq.search.service.release_lock"),
            patch("saq.search.service.get_redis_connection") as mock_get_redis,
            patch("saq.search.service.remove_all_sessions"),
            patches["index_alert"],
            patches["update_alert_payload"],
            patches["delete_alert"],
        ):
            mock_get_redis.return_value.llen.return_value = 3
            worker.worker_execute()

    def test_index_task_logs_one_completion_line(self, worker, task, caplog):
        result = IndexResult(alert_uuid="test-alert-uuid", document_count=7, point_count=41, seconds=0.81)
        self.run_task(worker, task, caplog, index_alert=patch("saq.search.service.index.index_alert", return_value=result))

        records = self.records(caplog, "search_index_task_complete")
        assert len(records) == 1
        assert records[0].worker == "worker-0"
        assert records[0].op == OP_INDEX
        assert records[0].alert_uuid == "test-alert-uuid"
        assert records[0].documents == 7
        assert records[0].points == 41
        assert records[0].queue_depth == 3
        assert isinstance(records[0].elapsed_ms, int)
        # skipped is omitted rather than logged as None on every successful line
        assert not hasattr(records[0], "skipped")
        assert worker.tasks_completed == 1

    def test_skipped_index_reports_the_reason(self, worker, task, caplog):
        result = IndexResult(alert_uuid="test-alert-uuid", skipped="alert not found")
        self.run_task(worker, task, caplog, index_alert=patch("saq.search.service.index.index_alert", return_value=result))

        records = self.records(caplog, "search_index_task_complete")
        assert len(records) == 1
        assert records[0].skipped == "alert not found"

    def test_payload_task_logs_completion(self, worker, caplog):
        """payload and delete succeeded silently before this: an analyst dispositioning 50
        alerts produced nothing in the indexer log at all."""
        task = SearchIndexTask(alert_uuid="u", op=OP_PAYLOAD)
        self.run_task(worker, task, caplog, update_alert_payload=patch("saq.search.service.index.update_alert_payload", return_value=False))

        records = self.records(caplog, "search_index_task_complete")
        assert len(records) == 1
        assert records[0].op == OP_PAYLOAD
        assert records[0].alert_uuid == "u"
        assert records[0].updated is False

    def test_delete_task_logs_completion(self, worker, caplog):
        task = SearchIndexTask(alert_uuid="u", op=OP_DELETE)
        self.run_task(worker, task, caplog)

        records = self.records(caplog, "search_index_task_complete")
        assert len(records) == 1
        assert records[0].op == OP_DELETE

    def test_task_error_is_logged_and_requeued(self, worker, task, caplog):
        with (
            caplog.at_level(logging.INFO),
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", task.model_dump_json())),
            patch.object(SearchIndexWorker, "execute_task", side_effect=RuntimeError("boom")),
            patch("saq.search.service.get_redis_connection"),
            patch("saq.search.service.report_exception"),
            patch("saq.search.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        errors = self.records(caplog, "search_index_task_error")
        assert len(errors) == 1
        assert errors[0].alert_uuid == "test-alert-uuid"
        assert errors[0].error == "boom"
        assert self.records(caplog, "search_index_task_requeued")[0].attempt == 1
        assert worker.tasks_failed == 1

    def test_invalid_payload_is_logged_not_lost_silently(self, worker, caplog):
        """BLPOP already removed the task, so this line is the only record of what it was."""
        with (
            caplog.at_level(logging.INFO),
            patch.object(SearchIndexWorker, "get_next_task", return_value=("key", "{not json")),
            patch("saq.search.service.remove_all_sessions"),
        ):
            worker.worker_execute()

        records = self.records(caplog, "search_index_task_invalid")
        assert len(records) == 1
        assert records[0].payload == "{not json"

    @pytest.mark.parametrize("task,reason", [
        (SearchIndexTask(alert_uuid="u", attempt=MAX_TASK_ATTEMPTS - 1), "error"),
        (SearchIndexTask(alert_uuid="u", deferrals=MAX_TASK_DEFERRALS - 1), "locked"),
    ])
    def test_dead_letter_names_the_reason(self, worker, task, reason, caplog):
        with caplog.at_level(logging.INFO), patch("saq.search.service.get_redis_connection"):
            worker.requeue_task(task) if reason == "error" else worker.defer_task(task)

        records = self.records(caplog, "search_index_task_dead_lettered")
        assert len(records) == 1
        assert records[0].reason == reason
        assert records[0].queue == FAILED_TASK_KEY

    def test_deferral_is_logged(self, worker, task, caplog):
        with caplog.at_level(logging.INFO), patch("saq.search.service.get_redis_connection"):
            worker.defer_task(task)

        records = self.records(caplog, "search_index_task_deferred")
        assert len(records) == 1
        assert records[0].deferrals == 1
        assert records[0].max_deferrals == MAX_TASK_DEFERRALS

    def test_worker_loop_bookends(self, worker, caplog):
        worker.model = Mock()
        worker.stop()
        with caplog.at_level(logging.INFO):
            worker.worker_loop()

        assert len(self.records(caplog, "search_indexer_worker_started")) == 1
        exiting = self.records(caplog, "search_indexer_worker_exiting")
        assert len(exiting) == 1
        assert exiting[0].tasks_completed == 0
        assert exiting[0].tasks_failed == 0
        assert exiting[0].tasks_deferred == 0

    def test_prepare_logs_the_model_and_collection(self, worker, caplog):
        with (
            caplog.at_level(logging.INFO),
            patch("saq.search.service.load_model", return_value=Mock()),
            patch("saq.search.service.get_model_name", return_value="all-MiniLM-L6-v2"),
            patch("saq.search.service.index.get_qdrant_client"),
            patch("saq.search.service.index.ensure_collection", return_value="ace3-alerts-unittest-v1"),
        ):
            worker.prepare()

        assert len(self.records(caplog, "search_indexer_loading_model")) == 1
        ready = self.records(caplog, "search_indexer_worker_ready")
        assert len(ready) == 1
        assert ready[0].model == "all-MiniLM-L6-v2"
        assert ready[0].collection == "ace3-alerts-unittest-v1"
        assert isinstance(ready[0].model_load_ms, int)

    def test_manager_start_names_the_collection(self, caplog):
        manager = SearchIndexManager(worker_count=2)
        with (
            caplog.at_level(logging.INFO),
            patch.object(SearchIndexWorker, "start"),
            patch("saq.search.service.get_model_name", return_value="all-MiniLM-L6-v2"),
            patch("saq.search.service.index.collection_name", return_value="ace3-alerts-unittest-v1"),
        ):
            manager.start()

        records = self.records(caplog, "search_indexer_starting")
        assert len(records) == 1
        assert records[0].worker_count == 2
        assert records[0].model == "all-MiniLM-L6-v2"
        assert records[0].collection == "ace3-alerts-unittest-v1"
