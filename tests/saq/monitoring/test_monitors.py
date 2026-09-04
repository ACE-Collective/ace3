from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from saq.database import get_db_connection
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
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_per_row(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "analysis_module_yara", "node1", 2),
            ("/opt/ace/data/uuid-2", "analysis_module_sandbox", "node1", 5),
        ])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        assert mock_emit.call_count == 2

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_correct_data(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/abc-123", "analysis_module_yara", "node1", 7),
        ])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {"uuid": "abc-123", "module": "yara", "node": "node1", "count": 7}

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_reports_every_node_not_just_the_local_one(self, mock_get_db, mock_emit):
        """The monitor runs on one node and must report the whole cluster.

        It used to scope the query to nodes.name = saq_node. Every node ran it anyway,
        because load_threaded_monitors() ignored `enabled: false` overlays, so the union
        across nodes covered the cluster by accident. Once that was fixed the monitor ran
        only on correlation and reported almost nothing -- the scanners hold ~74% of
        delayed analysis. Scoping this query to the local node is the bug.
        """
        mock_db = _make_mock_db([
            ("/opt/ace/data/uuid-1", "yara", "email-scanner-1", 3),
            ("/opt/ace/data/uuid-2", "phishkit_analyzer", "file-content-scanner-1", 9),
        ])
        mock_get_db.return_value = mock_db

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        cursor = mock_db.cursor.return_value
        sql, *params = cursor.execute.call_args[0]
        assert not params, "query must not be parameterized by node"
        assert "nodes.name = " not in sql

        emitted = [c[0][1] for c in mock_emit.call_args_list]
        assert [e["node"] for e in emitted] == ["email-scanner-1", "file-content-scanner-1"]

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_strips_analysis_module_prefix(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "analysis_module_cloudphish", "node1", 1),
        ])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data["module"] == "cloudphish"

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_preserves_bare_module_name(self, mock_get_db, mock_emit):
        """delayed_analysis.analysis_module holds AnalysisModule.name, which is already
        the bare name -- add_delayed_analysis_request() writes analysis_module.name and
        base_module.name returns config.name. Stripping a prefix that is not there
        silently eats 16 characters off the front of the real name."""
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "o365_session_activity", "node1", 3),
            ("/opt/ace/data/uuid-2", "phishkit_analyzer", "node1", 1),
        ])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        modules = [c[0][1]["module"] for c in mock_emit.call_args_list]
        assert modules == ["o365_session_activity", "phishkit_analyzer"]

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_does_not_erase_short_module_name(self, mock_get_db, mock_emit):
        """A bare name of 16 characters or fewer was truncated to the empty string."""
        mock_get_db.return_value = _make_mock_db([
            ("/opt/ace/data/uuid-1", "yara", "node1", 9),
        ])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        assert mock_emit.call_args[0][1]["module"] == "yara"

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_emits_nothing_for_empty_results(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([])

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db

        monitor = DistributedDelayedAnalysisMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()


@pytest.mark.unit
class TestDistributedLocksMonitor:
    def test_inherits_from_ace_threaded_monitor(self):
        assert issubclass(DistributedLocksMonitor, ACEThreadedMonitor)

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_per_row(self, mock_get_db, mock_emit):
        lock_time = datetime(2024, 1, 15, 12, 0, 0)
        mock_get_db.return_value = _make_mock_db([
            ("uuid-1", "lock-uuid-1", lock_time, "node1-worker-1", "node1"),
            ("uuid-2", "lock-uuid-2", lock_time, "node1-worker-2", "node1"),
        ])

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        assert mock_emit.call_count == 2

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_correct_data(self, mock_get_db, mock_emit):
        lock_time = datetime(2024, 1, 15, 12, 30, 45)
        mock_get_db.return_value = _make_mock_db([
            ("alert-uuid-1", "lock-abc", lock_time, "node1-worker-3", "node1"),
        ])

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data == {
            "uuid": "alert-uuid-1",
            "lock_uuid": "lock-abc",
            "lock_time": str(lock_time),
            "lock_owner": "node1-worker-3",
            "node": "node1",
        }

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_reports_every_node_not_just_the_local_one(self, mock_get_db, mock_emit):
        """The monitor runs on one node and must report the whole cluster.

        It used to scope the query with lock_owner LIKE CONCAT(saq_node, '-%'). The
        scanners hold ~98% of the locks, so once the monitor correctly stopped running
        on them this reported next to nothing.
        """
        lock_time = datetime(2024, 1, 15, 12, 0, 0)
        mock_db = _make_mock_db([
            ("uuid-1", "lock-1", lock_time, "email-scanner-1-worker-2", "email-scanner-1"),
            ("uuid-2", "lock-2", lock_time, "file-content-scanner-1-worker-1", "file-content-scanner-1"),
        ])
        mock_get_db.return_value = mock_db

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        cursor = mock_db.cursor.return_value
        sql, *params = cursor.execute.call_args[0]
        assert not params, "query must not be parameterized by node"
        assert "CONCAT(%s" not in sql

        emitted = [c[0][1] for c in mock_emit.call_args_list]
        assert [e["node"] for e in emitted] == ["email-scanner-1", "file-content-scanner-1"]

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_reports_locks_with_no_owning_node(self, mock_get_db, mock_emit):
        """Not every lock_owner carries a node prefix -- the embedding service uses
        str(self) (saq/llm/embedding/service.py). The LEFT JOIN leaves node NULL for
        those rather than dropping the lock from the report entirely."""
        lock_time = datetime(2024, 1, 15, 12, 0, 0)
        mock_get_db.return_value = _make_mock_db([
            ("uuid-1", "lock-1", lock_time, "EmbeddingService", None),
        ])

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        data = mock_emit.call_args[0][1]
        assert data["lock_owner"] == "EmbeddingService"
        assert data["node"] is None

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_emits_nothing_for_empty_results(self, mock_get_db, mock_emit):
        mock_get_db.return_value = _make_mock_db([])

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    @patch("saq.monitoring.monitors.distributed_locks_monitor.get_db_connection")
    def test_execute_commits_transaction(self, mock_get_db, mock_emit):
        mock_db = _make_mock_db([])
        mock_get_db.return_value = mock_db

        monitor = DistributedLocksMonitor(name="test", frequency=1.0)
        monitor.execute()

        mock_db.commit.assert_called_once()


@pytest.mark.integration
class TestDistributedMonitorQueries:
    """Exercises the real SQL. The unit tests above mock the cursor, so they cannot catch
    a query that is malformed, that fans out one row into several, or that attributes a
    lock to the wrong node."""

    @staticmethod
    def _add_node(db, name):
        cursor = db.cursor()
        cursor.execute("SELECT id FROM company LIMIT 1")
        company_id = cursor.fetchone()[0]
        cursor.execute(
            "INSERT INTO nodes (name, location, company_id, last_update) VALUES (%s, %s, %s, NOW())",
            (name, name, company_id))
        return cursor.lastrowid

    @staticmethod
    def _add_lock(db, uuid, lock_owner):
        db.cursor().execute(
            "INSERT INTO locks (uuid, lock_uuid, lock_time, lock_owner) VALUES (%s, %s, NOW(), %s)",
            (uuid, "lock-" + uuid, lock_owner))

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    def test_locks_attributed_to_the_owning_node(self, mock_emit):
        """Node names contain hyphens, so the node cannot be split off the lock_owner in
        code -- it has to be resolved against the real node names."""
        with get_db_connection() as db:
            self._add_node(db, "email-scanner-1")
            self._add_node(db, "file-content-scanner-1")
            self._add_lock(db, "lock-uuid-a", "email-scanner-1-worker-3")
            self._add_lock(db, "lock-uuid-b", "file-content-scanner-1-worker-1")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        by_uuid = {c[0][1]["uuid"]: c[0][1]["node"] for c in mock_emit.call_args_list}
        assert by_uuid["lock-uuid-a"] == "email-scanner-1"
        assert by_uuid["lock-uuid-b"] == "file-content-scanner-1"

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    def test_lock_reported_once_when_node_names_share_a_prefix(self, mock_emit):
        """"db" is a prefix of "db-readonly". A LEFT JOIN on LIKE CONCAT(name, '-%')
        matches both and reports the lock twice, inflating the panel."""
        with get_db_connection() as db:
            self._add_node(db, "db")
            self._add_node(db, "db-readonly")
            self._add_lock(db, "lock-uuid-c", "db-readonly-worker-1")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        emitted = [c[0][1] for c in mock_emit.call_args_list if c[0][1]["uuid"] == "lock-uuid-c"]
        assert len(emitted) == 1
        assert emitted[0]["node"] == "db-readonly"

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor")
    def test_lock_without_a_node_prefix_is_still_reported(self, mock_emit):
        with get_db_connection() as db:
            self._add_node(db, "correlation")
            self._add_lock(db, "lock-uuid-d", "EmbeddingService")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        emitted = [c[0][1] for c in mock_emit.call_args_list if c[0][1]["uuid"] == "lock-uuid-d"]
        assert len(emitted) == 1
        assert emitted[0]["node"] is None

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor")
    def test_delayed_analysis_reports_every_node(self, mock_emit):
        with get_db_connection() as db:
            node_id = self._add_node(db, "email-scanner-2")
            db.cursor().execute(
                "INSERT INTO delayed_analysis (uuid, observable_uuid, analysis_module, "
                "insert_date, delayed_until, node_id, storage_dir) "
                "VALUES (%s, %s, %s, NOW(), NOW(), %s, %s)",
                ("da-uuid-1", "obs-uuid-1", "phishkit_analyzer", node_id,
                 "/opt/ace/data/da-uuid-1"))
            db.commit()

        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        emitted = [c[0][1] for c in mock_emit.call_args_list if c[0][1]["uuid"] == "da-uuid-1"]
        assert len(emitted) == 1
        assert emitted[0]["node"] == "email-scanner-2"
        assert emitted[0]["module"] == "phishkit_analyzer"
