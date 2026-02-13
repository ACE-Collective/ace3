from threading import Event
import uuid as uuid_module
import pytest

from saq.analysis.root import RootAnalysis
from saq.collectors.remote_node import RemoteNode, RemoteNodeGroup
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, DB_COLLECTION
from saq.database.pool import get_db_connection
from saq.environment import get_global_runtime_settings
from saq.util.time import local_time
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_submission

@pytest.fixture
def remote_node() -> RemoteNode:
    return RemoteNode(
        1, get_global_runtime_settings().saq_node, "location", 1, local_time(), ANALYSIS_MODE_ANALYSIS, 1)

@pytest.mark.unit
def test_remote_node_is_local(remote_node):
    assert remote_node.is_local
    remote_node.name = "remote"
    assert not remote_node.is_local

@pytest.mark.unit
def test_remote_local_selection_logic(monkeypatch, remote_node):
    submit_local = False
    submit_remote = False

    def mock_submit_local(self, *args, **kwargs):
        nonlocal submit_local
        submit_local = True

    def mock_submit_remote(self, *args, **kwargs):
        nonlocal submit_remote
        submit_remote = True

    monkeypatch.setattr(remote_node, "submit_local", mock_submit_local)
    monkeypatch.setattr(remote_node, "submit_remote", mock_submit_remote)

    remote_node.submit(create_submission())
    assert submit_local
    assert not submit_remote

    submit_local = False
    submit_remote = False

    remote_node.name = "remote"
    remote_node.submit(create_submission())
    assert not submit_local
    assert submit_remote
    
@pytest.mark.integration
def test_submit_local(root_analysis, remote_node):
    result = remote_node.submit_local(root_analysis.create_submission())
    new_uuid = result["result"]
    assert new_uuid != root_analysis.uuid
    root = RootAnalysis(storage_dir=get_storage_dir(new_uuid))
    root.load()
    assert root.description == root_analysis.description

@pytest.mark.integration
def test_submit_local_alert(root_analysis, remote_node):
    root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
    result = remote_node.submit_local(root_analysis.create_submission())
    new_uuid = result["result"]
    assert new_uuid != root_analysis.uuid
    root = RootAnalysis(storage_dir=get_storage_dir(new_uuid))
    root.load()
    assert root.description == root_analysis.description

@pytest.mark.integration
def test_submit_remote(root_analysis, remote_node, mock_api_call):
    new_uuid = remote_node.submit_remote(root_analysis.create_submission())
    assert new_uuid != root_analysis.uuid
    root = RootAnalysis(storage_dir=get_storage_dir(new_uuid))
    root.load()
    assert root.description == root_analysis.description

@pytest.fixture
def remote_node_group() -> RemoteNodeGroup:
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO work_distribution_groups ( name ) VALUES ( 'test' )""")
        group_id = cursor.lastrowid
        cursor.execute("""INSERT INTO incoming_workload_type ( name ) VALUES ( 'test' )""")
        workload_type_id = cursor.lastrowid
        db.commit()

    return RemoteNodeGroup("test", 100, True, get_global_runtime_settings().company_id, DB_COLLECTION, group_id, workload_type_id, Event())


def insert_workload_item(cursor, type_id, mode, group_id, status="READY", lock_uuid=None):
    """Insert a row into incoming_workload and work_distribution. Returns (work_id, work_uuid)."""
    work_uuid = str(uuid_module.uuid4())
    cursor.execute(
        "INSERT INTO incoming_workload (type_id, mode, work) VALUES (%s, %s, %s)",
        (type_id, mode, work_uuid),
    )
    work_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO work_distribution (group_id, work_id, status, lock_uuid) VALUES (%s, %s, %s, %s)",
        (group_id, work_id, status, lock_uuid),
    )
    return work_id, work_uuid


@pytest.fixture
def priority_cleanup():
    """Track custom analysis_mode_priority rows and clean them up after the test."""
    added_modes = []

    def _add_priority(cursor, mode, priority):
        cursor.execute(
            "INSERT INTO analysis_mode_priority (analysis_mode, priority) VALUES (%s, %s)",
            (mode, priority),
        )
        added_modes.append(mode)

    yield _add_priority

    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        for mode in added_modes:
            cursor.execute(
                "DELETE FROM analysis_mode_priority WHERE analysis_mode = %s",
                (mode,),
            )
        db.commit()


@pytest.mark.integration
@pytest.mark.parametrize(
    "case_id, priorities",
    [
        ("explicit_priorities", [("mode_high", 10), ("mode_low", 1)]),
        ("unlisted_mode_defaults_to_zero", [("mode_listed", 5)]),
    ],
)
def test_fetch_query_orders_by_priority_then_id(
    remote_node_group, priority_cleanup, case_id, priorities
):
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()

        for mode, priority in priorities:
            priority_cleanup(cursor, mode, priority)
        db.commit()

        lock_uuid = str(uuid_module.uuid4())

        if case_id == "explicit_priorities":
            # Insert low-priority items first (lower IDs)
            low_ids = []
            for _ in range(2):
                wid, _ = insert_workload_item(
                    cursor, remote_node_group.workload_type_id, "mode_low",
                    remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
                )
                low_ids.append(wid)

            high_ids = []
            for _ in range(2):
                wid, _ = insert_workload_item(
                    cursor, remote_node_group.workload_type_id, "mode_high",
                    remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
                )
                high_ids.append(wid)
            db.commit()

            # Run the fetch query
            cursor.execute(
                """
                SELECT
                    incoming_workload.id,
                    incoming_workload.mode,
                    incoming_workload.work
                FROM
                    incoming_workload
                    JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
                    LEFT JOIN analysis_mode_priority ON incoming_workload.mode = analysis_mode_priority.analysis_mode
                WHERE
                    work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
                ORDER BY
                    COALESCE(analysis_mode_priority.priority, 0) DESC, incoming_workload.id ASC
                """,
                (lock_uuid,),
            )
            rows = cursor.fetchall()

            result_ids = [r[0] for r in rows]
            assert result_ids == sorted(high_ids) + sorted(low_ids)

        else:  # unlisted_mode_defaults_to_zero
            # Insert unlisted mode items first (lower IDs, will default to priority 0)
            unlisted_ids = []
            for _ in range(2):
                wid, _ = insert_workload_item(
                    cursor, remote_node_group.workload_type_id, "mode_unlisted",
                    remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
                )
                unlisted_ids.append(wid)

            listed_ids = []
            for _ in range(2):
                wid, _ = insert_workload_item(
                    cursor, remote_node_group.workload_type_id, "mode_listed",
                    remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
                )
                listed_ids.append(wid)
            db.commit()

            cursor.execute(
                """
                SELECT
                    incoming_workload.id,
                    incoming_workload.mode,
                    incoming_workload.work
                FROM
                    incoming_workload
                    JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
                    LEFT JOIN analysis_mode_priority ON incoming_workload.mode = analysis_mode_priority.analysis_mode
                WHERE
                    work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
                ORDER BY
                    COALESCE(analysis_mode_priority.priority, 0) DESC, incoming_workload.id ASC
                """,
                (lock_uuid,),
            )
            rows = cursor.fetchall()

            result_ids = [r[0] for r in rows]
            assert result_ids == sorted(listed_ids) + sorted(unlisted_ids)


@pytest.mark.integration
def test_fetch_query_same_priority_orders_by_id_ascending(remote_node_group):
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()

        lock_uuid = str(uuid_module.uuid4())
        inserted_ids = []
        for _ in range(5):
            wid, _ = insert_workload_item(
                cursor, remote_node_group.workload_type_id, ANALYSIS_MODE_ANALYSIS,
                remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
            )
            inserted_ids.append(wid)
        db.commit()

        cursor.execute(
            """
            SELECT
                incoming_workload.id,
                incoming_workload.mode,
                incoming_workload.work
            FROM
                incoming_workload
                JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
                LEFT JOIN analysis_mode_priority ON incoming_workload.mode = analysis_mode_priority.analysis_mode
            WHERE
                work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
            ORDER BY
                COALESCE(analysis_mode_priority.priority, 0) DESC, incoming_workload.id ASC
            """,
            (lock_uuid,),
        )
        rows = cursor.fetchall()

        result_ids = [r[0] for r in rows]
        assert result_ids == sorted(inserted_ids)


@pytest.mark.integration
def test_lock_query_prioritizes_higher_priority_modes(
    remote_node_group, priority_cleanup
):
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()

        priority_cleanup(cursor, "mode_low_pri", 1)
        priority_cleanup(cursor, "mode_high_pri", 10)
        db.commit()

        # Insert low-priority items first (they get lower IDs)
        low_ids = []
        for _ in range(3):
            wid, _ = insert_workload_item(
                cursor, remote_node_group.workload_type_id, "mode_low_pri",
                remote_node_group.group_id, status="READY",
            )
            low_ids.append(wid)

        # Insert high-priority items second (they get higher IDs)
        high_ids = []
        for _ in range(3):
            wid, _ = insert_workload_item(
                cursor, remote_node_group.workload_type_id, "mode_high_pri",
                remote_node_group.group_id, status="READY",
            )
            high_ids.append(wid)
        db.commit()

        lock_uuid = str(uuid_module.uuid4())
        batch_size = 3
        available_modes = ["mode_low_pri", "mode_high_pri"]

        sql = """
UPDATE work_distribution
SET
    status = 'LOCKED',
    lock_time = NOW(),
    lock_uuid = %s
WHERE
    group_id = %s
    AND work_id IN ( SELECT * FROM (
        SELECT
            incoming_workload.id
        FROM
            incoming_workload
            JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
            LEFT JOIN analysis_mode_priority ON incoming_workload.mode = analysis_mode_priority.analysis_mode
        WHERE
            incoming_workload.type_id = %s
            AND work_distribution.group_id = %s
            AND incoming_workload.mode IN ( {} )
            AND (
                work_distribution.status = 'READY'
                OR ( work_distribution.status = 'LOCKED' AND TIMESTAMPDIFF(minute, work_distribution.lock_time, NOW()) >= 10 )
            )
        ORDER BY
            COALESCE(analysis_mode_priority.priority, 0) DESC, incoming_workload.id ASC
        LIMIT %s ) AS t1 )
""".format(",".join(["%s" for _ in available_modes]))

        params = [
            lock_uuid,
            remote_node_group.group_id,
            remote_node_group.workload_type_id,
            remote_node_group.group_id,
        ]
        params.extend(available_modes)
        params.append(batch_size)

        cursor.execute(sql, tuple(params))
        db.commit()

        # Verify only high-priority items were locked
        cursor.execute(
            "SELECT work_id FROM work_distribution WHERE lock_uuid = %s AND status = 'LOCKED' ORDER BY work_id",
            (lock_uuid,),
        )
        locked_ids = [r[0] for r in cursor.fetchall()]
        assert locked_ids == sorted(high_ids)

        # Verify low-priority items are still READY
        for wid in low_ids:
            cursor.execute(
                "SELECT status FROM work_distribution WHERE work_id = %s AND group_id = %s",
                (wid, remote_node_group.group_id),
            )
            assert cursor.fetchone()[0] == "READY"


@pytest.mark.integration
def test_default_seed_correlation_before_analysis(remote_node_group):
    """Verify that the seed data (correlation=1) causes correlation items to be fetched before analysis items."""
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()

        lock_uuid = str(uuid_module.uuid4())

        # Insert analysis items first (lower IDs, priority defaults to 0)
        analysis_ids = []
        for _ in range(3):
            wid, _ = insert_workload_item(
                cursor, remote_node_group.workload_type_id, ANALYSIS_MODE_ANALYSIS,
                remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
            )
            analysis_ids.append(wid)

        # Insert correlation items second (higher IDs, priority 1 from seed)
        correlation_ids = []
        for _ in range(3):
            wid, _ = insert_workload_item(
                cursor, remote_node_group.workload_type_id, ANALYSIS_MODE_CORRELATION,
                remote_node_group.group_id, status="LOCKED", lock_uuid=lock_uuid,
            )
            correlation_ids.append(wid)
        db.commit()

        cursor.execute(
            """
            SELECT
                incoming_workload.id,
                incoming_workload.mode,
                incoming_workload.work
            FROM
                incoming_workload
                JOIN work_distribution ON incoming_workload.id = work_distribution.work_id
                LEFT JOIN analysis_mode_priority ON incoming_workload.mode = analysis_mode_priority.analysis_mode
            WHERE
                work_distribution.lock_uuid = %s AND work_distribution.status = 'LOCKED'
            ORDER BY
                COALESCE(analysis_mode_priority.priority, 0) DESC, incoming_workload.id ASC
            """,
            (lock_uuid,),
        )
        rows = cursor.fetchall()

        result_ids = [r[0] for r in rows]
        # Correlation (priority 1) should come before analysis (priority 0)
        assert result_ids == sorted(correlation_ids) + sorted(analysis_ids)
