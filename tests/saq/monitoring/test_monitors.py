from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.monitoring.monitors.distributed_workload_monitor import DistributedWorkloadMonitor
from saq.monitoring.monitors.local_workload_monitor import LocalWorkloadMonitor
from saq.monitoring.monitors.distributed_delayed_analysis_monitor import DistributedDelayedAnalysisMonitor
from saq.monitoring.monitors.distributed_locks_monitor import DistributedLocksMonitor
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


def _make_mock_db(rows):
    """Create a mock db context manager that yields a db with a cursor iterating over rows."""
    mock_cursor = MagicMock()
    mock_cursor.__iter__ = MagicMock(return_value=iter(rows))

    mock_db = MagicMock()
    mock_db.cursor.return_value = mock_cursor
    mock_db.__enter__ = MagicMock(return_value=mock_db)
    mock_db.__exit__ = MagicMock(return_value=False)
    return mock_db


@pytest.mark.unit
class TestDistributedWorkloadMonitor:
    def test_inherits_from_ace_threaded_monitor(self):
        assert issubclass(DistributedWorkloadMonitor, ACEThreadedMonitor)

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_config")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_db_connection")
    def test_execute_emits_workload_data(self, mock_get_db, mock_get_config, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("analysis", 10),
            ("correlation", 5),
        ])
        mock_get_config.return_value.global_settings.company_id = 1

        monitor = DistributedWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_called_once()
        args = mock_emit.call_args
        data = args[0][1]
        assert data == {"workload": [
            {"analysis_mode": "analysis", "count": 10},
            {"analysis_mode": "correlation", "count": 5},
        ]}

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_config")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_db_connection")
    def test_execute_emits_empty_workload(self, mock_get_db, mock_get_config, mock_emit):
        mock_get_db.return_value = _make_mock_db([])
        mock_get_config.return_value.global_settings.company_id = 1

        monitor = DistributedWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_called_once()
        data = mock_emit.call_args[0][1]
        assert data == {"workload": []}

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_config")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_db_connection")
    def test_execute_queries_with_company_id(self, mock_get_db, mock_get_config, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_config.return_value.global_settings.company_id = 42

        monitor = DistributedWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        cursor = mock_db.cursor.return_value
        cursor.execute.assert_called_once()
        sql_params = cursor.execute.call_args[0][1]
        assert sql_params == (42,)

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_config")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_get_config, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_config.return_value.global_settings.company_id = 1

        monitor = DistributedWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_config")
    @patch("saq.monitoring.monitors.distributed_workload_monitor.get_db_connection")
    def test_execute_single_row(self, mock_get_db, mock_get_config, mock_emit):
        mock_get_db.return_value = _make_mock_db([("analysis", 3)])
        mock_get_config.return_value.global_settings.company_id = 1

        monitor = DistributedWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {"workload": [{"analysis_mode": "analysis", "count": 3}]}


@pytest.mark.unit
class TestLocalWorkloadMonitor:
    def test_inherits_from_ace_threaded_monitor(self):
        assert issubclass(LocalWorkloadMonitor, ACEThreadedMonitor)

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.local_workload_monitor.get_db_connection")
    def test_execute_emits_workload_data(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("http", "analysis", 8),
            ("email", "correlation", 3),
        ])

        monitor = LocalWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_called_once()
        data = mock_emit.call_args[0][1]
        assert data == {"workload": [
            {"type": "http", "mode": "analysis", "count": 8},
            {"type": "email", "mode": "correlation", "count": 3},
        ]}

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.local_workload_monitor.get_db_connection")
    def test_execute_emits_empty_workload(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([])

        monitor = LocalWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {"workload": []}

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.local_workload_monitor.get_db_connection")
    def test_execute_uses_collection_database(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([])

        monitor = LocalWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        from saq.constants import DB_COLLECTION
        mock_get_db.assert_called_once_with(DB_COLLECTION)

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.local_workload_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db

        monitor = LocalWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.local_workload_monitor.get_db_connection")
    def test_execute_single_row(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([("http", "analysis", 5)])

        monitor = LocalWorkloadMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {"workload": [{"type": "http", "mode": "analysis", "count": 5}]}


@pytest.mark.unit
class TestDistributedDelayedAnalysisMonitor:
    def test_inherits_from_ace_threaded_monitor(self):
        assert issubclass(DistributedDelayedAnalysisMonitor, ACEThreadedMonitor)

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_per_row(self, mock_get_db, mock_get_settings, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "analysis_module_yara", 2),
            ("/opt/ace/data/uuid-2", "analysis_module_sandbox", 5),
        ])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        assert mock_emit.call_count == 2

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_correct_data(self, mock_get_db, mock_get_settings, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/abc-123", "analysis_module_yara", 7),
        ])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {"uuid": "abc-123", "module": "yara", "count": 7}

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_strips_analysis_module_prefix(self, mock_get_db, mock_get_settings, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "analysis_module_cloudphish", 1),
        ])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data["module"] == "cloudphish"

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_queries_with_current_node(self, mock_get_db, mock_get_settings, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_settings.return_value.saq_node = "ace-node-5"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        cursor = mock_db.cursor.return_value
        sql_params = cursor.execute.call_args[0][1]
        assert sql_params == ("ace-node-5",)

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_nothing_for_empty_results(self, mock_get_db, mock_get_settings, mock_emit):
        mock_get_db.return_value = _make_mock_db([])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_get_settings, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()


@pytest.mark.unit
class TestDistributedLocksMonitor:
    def test_inherits_from_ace_threaded_monitor(self):
        assert issubclass(DistributedLocksMonitor, ACEThreadedMonitor)

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_per_row(self, mock_get_db, mock_get_settings, mock_emit):
        lock_time = datetime(2024, 1, 15, 12, 0, 0)
        mock_get_db.return_value = _make_mock_db([
            ("uuid-1", "lock-uuid-1", lock_time, "node1-worker-1"),
            ("uuid-2", "lock-uuid-2", lock_time, "node1-worker-2"),
        ])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        assert mock_emit.call_count == 2

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_correct_data(self, mock_get_db, mock_get_settings, mock_emit):
        lock_time = datetime(2024, 1, 15, 12, 30, 45)
        mock_get_db.return_value = _make_mock_db([
            ("alert-uuid-1", "lock-abc", lock_time, "node1-worker-3"),
        ])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {
            "uuid": "alert-uuid-1",
            "lock_uuid": "lock-abc",
            "lock_time": str(lock_time),
            "lock_owner": "node1-worker-3",
        }

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_queries_with_node_pattern(self, mock_get_db, mock_get_settings, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_settings.return_value.saq_node = "ace-prod-1"

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        cursor = mock_db.cursor.return_value
        sql_params = cursor.execute.call_args[0][1]
        assert sql_params == ("ace-prod-1",)

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_nothing_for_empty_results(self, mock_get_db, mock_get_settings, mock_emit):
        mock_get_db.return_value = _make_mock_db([])
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_global_runtime_settings")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_get_settings, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db
        mock_get_settings.return_value.saq_node = "node1"

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()
