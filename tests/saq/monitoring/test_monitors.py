from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

import pytest

from saq.cas import get_cas
from saq.collectors.workload_repository import WorkloadRepository
from saq.configuration.config import get_config
from saq.database import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitoring.monitors.distributed_workload_monitor import DistributedWorkloadMonitor
from saq.monitoring.monitors.local_workload_monitor import LocalWorkloadMonitor
from saq.monitoring.monitors.distributed_delayed_analysis_monitor import DistributedDelayedAnalysisMonitor
from saq.monitoring.monitors.distributed_locks_monitor import DistributedLocksMonitor
from saq.monitoring.monitors.node_status_monitor import NodeStatusMonitor
from saq.monitoring.monitors.cas_pool_monitor import CASPoolMonitor
from saq.monitoring.threaded_monitor import ACEThreadedMonitor


def _add_node(db, name, status="running", expected_state="online", heartbeat_age_seconds=0):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM company LIMIT 1")
    company_id = cursor.fetchone()[0]
    cursor.execute(
        "INSERT INTO nodes (name, location, company_id, last_update, status, expected_state) "
        "VALUES (%s, %s, %s, DATE_SUB(NOW(), INTERVAL %s SECOND), %s, %s)",
        (name, name, company_id, heartbeat_age_seconds, status, expected_state))
    return cursor.lastrowid


def _add_workload(db, uuid, analysis_mode, company_id=None, node_id=None):
    cursor = db.cursor()
    if company_id is None:
        company_id = get_config().global_settings.company_id
    if node_id is None:
        node_id = get_global_runtime_settings().saq_node_id
    cursor.execute(
        "INSERT INTO workload (uuid, node_id, company_id, analysis_mode, insert_date, storage_dir) "
        "VALUES (%s, %s, %s, %s, NOW(), %s)",
        (uuid, node_id, company_id, analysis_mode, f"/opt/ace/data/{uuid}"))


def _add_delayed_analysis(db, uuid, analysis_module, node_id, observable_uuid=None):
    db.cursor().execute(
        "INSERT INTO delayed_analysis (uuid, observable_uuid, analysis_module, "
        "insert_date, delayed_until, node_id, storage_dir) "
        "VALUES (%s, %s, %s, NOW(), NOW(), %s, %s)",
        (uuid, observable_uuid or str(uuid4()), analysis_module, node_id,
         f"/opt/ace/data/{uuid}"))


def _add_lock(db, uuid, lock_owner, lock_time=None):
    if lock_time is None:
        db.cursor().execute(
            "INSERT INTO locks (uuid, lock_uuid, lock_time, lock_owner) VALUES (%s, %s, NOW(), %s)",
            (uuid, "lock-" + uuid, lock_owner))
    else:
        db.cursor().execute(
            "INSERT INTO locks (uuid, lock_uuid, lock_time, lock_owner) VALUES (%s, %s, %s, %s)",
            (uuid, "lock-" + uuid, lock_time, lock_owner))


def _emitted(mock_emit):
    return [c[0][1] for c in mock_emit.call_args_list]


@pytest.mark.unit
def test_monitors_inherit_from_ace_threaded_monitor():
    for monitor_class in (DistributedWorkloadMonitor, LocalWorkloadMonitor,
                          DistributedDelayedAnalysisMonitor, DistributedLocksMonitor):
        assert issubclass(monitor_class, ACEThreadedMonitor)


@pytest.mark.integration
class TestDistributedWorkloadMonitor:
    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_counts_workload_per_analysis_mode(self, mock_emit):
        with get_db_connection() as db:
            _add_workload(db, "dw-uuid-1", "correlation")
            _add_workload(db, "dw-uuid-2", "correlation")
            _add_workload(db, "dw-uuid-3", "analysis")
            db.commit()

        DistributedWorkloadMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_called_once()
        assert _emitted(mock_emit)[0] == {"workload": [
            {"analysis_mode": "analysis", "count": 1},
            {"analysis_mode": "correlation", "count": 2},
        ]}

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_empty_workload(self, mock_emit):
        DistributedWorkloadMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_called_once()
        assert _emitted(mock_emit)[0] == {"workload": []}

    @patch("saq.monitoring.monitors.distributed_workload_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_counts_only_the_configured_company(self, mock_emit, monkeypatch):
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO company (name) VALUES ('other-company')")
            other_company_id = cursor.lastrowid
            _add_workload(db, "dw-uuid-4", "correlation")
            _add_workload(db, "dw-uuid-5", "analysis", company_id=other_company_id)
            db.commit()

        DistributedWorkloadMonitor(name="test", frequency=1.0).execute()
        assert _emitted(mock_emit)[-1] == {"workload": [{"analysis_mode": "correlation", "count": 1}]}

        monkeypatch.setattr(get_config().global_settings, "company_id", other_company_id)
        DistributedWorkloadMonitor(name="test", frequency=1.0).execute()
        assert _emitted(mock_emit)[-1] == {"workload": [{"analysis_mode": "analysis", "count": 1}]}


@pytest.mark.integration
class TestLocalWorkloadMonitor:
    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_counts_this_nodes_workload_per_type_and_mode(self, mock_emit):
        local = WorkloadRepository(get_global_runtime_settings().saq_node_id)
        http_type = local.get_workload_type_id("http")
        email_type = local.get_workload_type_id("email")
        local.insert_workload(http_type, "analysis", "lw-uuid-1")
        local.insert_workload(http_type, "analysis", "lw-uuid-2")
        local.insert_workload(email_type, "correlation", "lw-uuid-3")

        # the same table holds every node's collected work
        with get_db_connection() as db:
            other_node_id = _add_node(db, "other-collector")
            db.commit()
        remote = WorkloadRepository(other_node_id)
        remote.insert_workload(http_type, "analysis", "lw-uuid-4")
        remote.insert_workload(email_type, "analysis", "lw-uuid-5")

        LocalWorkloadMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_called_once()
        assert _emitted(mock_emit)[0] == {"workload": [
            {"type": "email", "mode": "correlation", "count": 1},
            {"type": "http", "mode": "analysis", "count": 2},
        ]}

    @patch("saq.monitoring.monitors.local_workload_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_empty_workload(self, mock_emit):
        LocalWorkloadMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_called_once()
        assert _emitted(mock_emit)[0] == {"workload": []}


@pytest.mark.integration
class TestDistributedDelayedAnalysisMonitor:
    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_one_record_per_root_module_and_node(self, mock_emit):
        with get_db_connection() as db:
            node_id = _add_node(db, "node1")
            for i in range(7):
                _add_delayed_analysis(db, "abc-123", "yara", node_id, observable_uuid=f"obs-{i}")
            _add_delayed_analysis(db, "abc-456", "yara", node_id)
            db.commit()

        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        emitted = sorted(_emitted(mock_emit), key=lambda e: e["uuid"])
        assert emitted == [
            {"uuid": "abc-123", "module": "yara", "node": "node1", "count": 7},
            {"uuid": "abc-456", "module": "yara", "node": "node1", "count": 1},
        ]

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_strips_analysis_module_prefix(self, mock_emit):
        with get_db_connection() as db:
            node_id = _add_node(db, "node1")
            _add_delayed_analysis(db, "uuid-1", "analysis_module_phishkit_analyzer", node_id)
            db.commit()

        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        assert [e["module"] for e in _emitted(mock_emit)] == ["phishkit_analyzer"]

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_preserves_bare_module_name(self, mock_emit):
        """delayed_analysis.analysis_module holds AnalysisModule.name, which is already
        the bare name -- add_delayed_analysis_request() writes analysis_module.name and
        base_module.name returns config.name. Stripping a prefix that is not there
        silently eats 16 characters off the front of the real name. A bare name of 16
        characters or fewer was truncated to the empty string."""
        with get_db_connection() as db:
            node_id = _add_node(db, "node1")
            _add_delayed_analysis(db, "uuid-1", "o365_session_activity", node_id)
            _add_delayed_analysis(db, "uuid-2", "phishkit_analyzer", node_id)
            _add_delayed_analysis(db, "uuid-3", "yara", node_id)
            db.commit()

        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        modules = sorted(e["module"] for e in _emitted(mock_emit))
        assert modules == ["o365_session_activity", "phishkit_analyzer", "yara"]

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_nothing_for_empty_results(self, mock_emit):
        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_delayed_analysis_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_reports_every_node_not_just_the_local_one(self, mock_emit):
        """The monitor runs on one node and must report the whole cluster.

        It used to scope the query to nodes.name = saq_node. Every node ran it anyway,
        because load_threaded_monitors() ignored `enabled: false` overlays, so the union
        across nodes covered the cluster by accident. Once that was fixed the monitor ran
        only on correlation and reported almost nothing -- the scanners hold ~74% of
        delayed analysis. Scoping this query to the local node is the bug.
        """
        with get_db_connection() as db:
            email_node_id = _add_node(db, "email-scanner-2")
            file_node_id = _add_node(db, "file-content-scanner-1")
            _add_delayed_analysis(db, "da-uuid-1", "phishkit_analyzer", email_node_id)
            _add_delayed_analysis(db, "da-uuid-2", "yara", file_node_id)
            db.commit()

        DistributedDelayedAnalysisMonitor(name="test", frequency=1.0).execute()

        by_uuid = {e["uuid"]: e["node"] for e in _emitted(mock_emit)}
        assert by_uuid == {"da-uuid-1": "email-scanner-2", "da-uuid-2": "file-content-scanner-1"}


@pytest.mark.integration
class TestDistributedLocksMonitor:
    """The locks table has no node_id, so the node is resolved from lock_owner against the
    real node names."""

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_correct_data(self, mock_emit):
        lock_time = datetime(2024, 1, 15, 12, 30, 45)
        with get_db_connection() as db:
            _add_node(db, "node1")
            _add_lock(db, "alert-uuid-1", "node1-worker-3", lock_time=lock_time)
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        assert _emitted(mock_emit) == [{
            "uuid": "alert-uuid-1",
            "lock_uuid": "lock-alert-uuid-1",
            "lock_time": str(lock_time),
            "lock_owner": "node1-worker-3",
            "node": "node1",
        }]

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor", wraps=emit_monitor)
    def test_execute_emits_nothing_for_empty_results(self, mock_emit):
        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        mock_emit.assert_not_called()

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor", wraps=emit_monitor)
    def test_locks_attributed_to_the_owning_node(self, mock_emit):
        """The monitor runs on one node and must report the whole cluster. It used to scope
        the query with lock_owner LIKE CONCAT(saq_node, '-%'); the scanners hold ~98% of
        the locks. Node names contain hyphens, so the node cannot be split off the
        lock_owner in code -- it has to be resolved against the real node names."""
        with get_db_connection() as db:
            _add_node(db, "email-scanner-1")
            _add_node(db, "file-content-scanner-1")
            _add_lock(db, "lock-uuid-a", "email-scanner-1-worker-3")
            _add_lock(db, "lock-uuid-b", "file-content-scanner-1-worker-1")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        by_uuid = {e["uuid"]: e["node"] for e in _emitted(mock_emit)}
        assert by_uuid["lock-uuid-a"] == "email-scanner-1"
        assert by_uuid["lock-uuid-b"] == "file-content-scanner-1"

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor", wraps=emit_monitor)
    def test_lock_reported_once_when_node_names_share_a_prefix(self, mock_emit):
        """"db" is a prefix of "db-readonly". A LEFT JOIN on LIKE CONCAT(name, '-%')
        matches both and reports the lock twice, inflating the panel."""
        with get_db_connection() as db:
            _add_node(db, "db")
            _add_node(db, "db-readonly")
            _add_lock(db, "lock-uuid-c", "db-readonly-worker-1")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        emitted = [e for e in _emitted(mock_emit) if e["uuid"] == "lock-uuid-c"]
        assert len(emitted) == 1
        assert emitted[0]["node"] == "db-readonly"

    @patch("saq.monitoring.monitors.distributed_locks_monitor.emit_monitor", wraps=emit_monitor)
    def test_lock_without_a_node_prefix_is_still_reported(self, mock_emit):
        """Not every lock_owner carries a node prefix -- the embedding service uses
        str(self) (saq/llm/embedding/service.py). It gets node NULL rather than being
        dropped from the report entirely."""
        with get_db_connection() as db:
            _add_node(db, "correlation")
            _add_lock(db, "lock-uuid-d", "EmbeddingService")
            db.commit()

        DistributedLocksMonitor(name="test", frequency=1.0).execute()

        emitted = [e for e in _emitted(mock_emit) if e["uuid"] == "lock-uuid-d"]
        assert len(emitted) == 1
        assert emitted[0]["lock_owner"] == "EmbeddingService"
        assert emitted[0]["node"] is None


@pytest.mark.integration
class TestNodeStatusMonitorQueries:
    """Exercises the real SQL behind the node status monitor.

    The point of this monitor is that monitoring can no longer tell a planned outage from
    a failure: a node that was drained and shut down and a node that crashed both end up
    at status = stopped. These tests pin the distinction it exists to preserve."""

    @staticmethod
    def _emitted_by_node(mock_emit):
        return {c[0][1]["node"]: c[0][1] for c in mock_emit.call_args_list}

    @patch("saq.monitoring.monitors.node_status_monitor.emit_monitor", wraps=emit_monitor)
    def test_drained_node_is_distinguishable_from_a_crashed_one(self, mock_emit):
        """The regression this monitor exists for. Both nodes are stopped with a stale
        heartbeat and are indistinguishable by status alone; only expected_state says
        which one anybody meant to take down."""
        with get_db_connection() as db:
            _add_node(db, "planned-node", status="stopped",
                           expected_state="offline", heartbeat_age_seconds=3600)
            _add_node(db, "crashed-node", status="stopped",
                           expected_state="online", heartbeat_age_seconds=3600)
            db.commit()

        NodeStatusMonitor(name="test", frequency=1.0).execute()

        emitted = self._emitted_by_node(mock_emit)
        assert emitted["planned-node"]["status"] == "stopped"
        assert emitted["planned-node"]["expected_state"] == "offline"
        assert emitted["crashed-node"]["status"] == "stopped"
        assert emitted["crashed-node"]["expected_state"] == "online"

    @patch("saq.monitoring.monitors.node_status_monitor.emit_monitor", wraps=emit_monitor)
    def test_reports_a_node_that_is_not_running(self, mock_emit):
        """A node that is off cannot report on itself, which is exactly why this reads the
        database from one node rather than having each node report for itself."""
        with get_db_connection() as db:
            _add_node(db, "shut-down-node", status="stopped",
                           expected_state="offline", heartbeat_age_seconds=7200)
            db.commit()

        NodeStatusMonitor(name="test", frequency=1.0).execute()

        assert "shut-down-node" in self._emitted_by_node(mock_emit)

    @patch("saq.monitoring.monitors.node_status_monitor.emit_monitor", wraps=emit_monitor)
    def test_heartbeat_age_comes_from_the_database_clock(self, mock_emit):
        with get_db_connection() as db:
            _add_node(db, "stale-node", heartbeat_age_seconds=600)
            _add_node(db, "fresh-node", heartbeat_age_seconds=0)
            db.commit()

        NodeStatusMonitor(name="test", frequency=1.0).execute()

        emitted = self._emitted_by_node(mock_emit)
        # allow a little slack for the time between the insert and the query
        assert 595 <= emitted["stale-node"]["heartbeat_age_seconds"] <= 660
        assert emitted["fresh-node"]["heartbeat_age_seconds"] < 60

    @patch("saq.monitoring.monitors.node_status_monitor.emit_monitor", wraps=emit_monitor)
    def test_each_node_reported_exactly_once_with_both_counts(self, mock_emit):
        """workload and delayed_analysis are both one-to-many against nodes: joining them
        in a single statement multiplies the rows and reports 2x2 instead of 2 and 2."""
        with get_db_connection() as db:
            node_id = _add_node(db, "counted-node")
            cursor = db.cursor()
            cursor.execute("SELECT id FROM company LIMIT 1")
            company_id = cursor.fetchone()[0]
            for i in range(2):
                cursor.execute(
                    "INSERT INTO workload (uuid, node_id, company_id, analysis_mode, insert_date, storage_dir) "
                    "VALUES (%s, %s, %s, %s, NOW(), %s)",
                    (f"wl-uuid-{i}", node_id, company_id, "correlation", f"/opt/ace/data/wl-uuid-{i}"))
            for i in range(2):
                cursor.execute(
                    "INSERT INTO delayed_analysis (uuid, observable_uuid, analysis_module, "
                    "insert_date, delayed_until, node_id, storage_dir) "
                    "VALUES (%s, %s, %s, NOW(), NOW(), %s, %s)",
                    (f"ns-da-uuid-{i}", f"ns-obs-{i}", "phishkit_analyzer", node_id,
                     f"/opt/ace/data/ns-da-uuid-{i}"))
            db.commit()

        NodeStatusMonitor(name="test", frequency=1.0).execute()

        emitted = [c[0][1] for c in mock_emit.call_args_list if c[0][1]["node"] == "counted-node"]
        assert len(emitted) == 1
        assert emitted[0]["workload_count"] == 2
        assert emitted[0]["delayed_analysis_count"] == 2

    @patch("saq.monitoring.monitors.node_status_monitor.emit_monitor", wraps=emit_monitor)
    def test_carries_the_node_name_splunk_uses_as_host(self, mock_emit):
        """The payload key is `node` and it holds nodes.name -- the same string fluent-bit
        stamps as the Splunk host, which is what the saved searches join on."""
        with get_db_connection() as db:
            _add_node(db, "email-scanner-1")
            db.commit()

        NodeStatusMonitor(name="test", frequency=1.0).execute()

        emitted = self._emitted_by_node(mock_emit)["email-scanner-1"]
        assert emitted["node"] == "email-scanner-1"
        assert emitted["location"] == "email-scanner-1"


@pytest.mark.integration
class TestCASPoolMonitor:
    @patch("saq.monitoring.monitors.cas_pool_monitor.emit_monitor", wraps=emit_monitor)
    def test_emits_one_record_per_pool(self, mock_emit):
        get_cas().pool("test_plain").put(b"monitored")

        CASPoolMonitor(name="test", frequency=1.0).execute()

        emitted = {c[0][1]["pool"]: c[0][1] for c in mock_emit.call_args_list}
        assert {c[0][0].path for c in mock_emit.call_args_list} == {"cas.pool"}
        # yara_qa and svs_samples are the pools saq.default.yaml defines out of the box
        assert set(emitted) == {"test_plain", "test_encrypted", "test_permanent", "yara_qa", "svs_samples"}
        assert emitted["test_plain"]["objects_present"] == 1
        assert emitted["test_plain"]["size_bytes"] == len(b"monitored")
