import pytest
from unittest.mock import Mock, patch, call

from saq.llm.embedding.service import EmbeddingWorker, EmbeddingTask


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
        """Verify load_alert/vectorize NOT called when lock fails."""
        with (
            patch("saq.llm.embedding.service.acquire_lock", return_value=False) as mock_acquire,
            patch("saq.llm.embedding.service.release_lock") as mock_release,
            patch("saq.database.model.load_alert") as mock_load,
            patch("saq.llm.embedding.service.vectorize") as mock_vectorize,
        ):
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
