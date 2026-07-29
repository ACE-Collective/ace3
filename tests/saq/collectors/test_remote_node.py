import os
from threading import Event
import uuid as uuid_module
import pytest
import requests

from saq.analysis.root import RootAnalysis
from saq.collectors.remote_node import RemoteNode, RemoteNodeGroup
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, DB_COLLECTION
from saq.database.pool import execute_with_db_cursor, get_db_connection
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


#
# delivery retry bounding / dead-lettering
#
# RemoteNodeGroup.execute() only claims a new batch when it holds no locks of its own, and the
# 10 minute stale-lock steal requires a *different* lock_uuid. With thread_count=1 there is no
# other lock_uuid, so an item that keeps failing with a retriable error used to hold the batch
# lock forever and stall every item queued behind it.
#

def _ensure_live_any_mode_node():
    """Makes sure the local node exists, accepts any analysis mode and looks alive to the
    node availability query in RemoteNodeGroup.execute()."""
    from saq.database import initialize_node

    if get_global_runtime_settings().saq_node_id is None:
        initialize_node()

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET any_mode = 1, status = 'running', last_update = NOW()")
        cursor.execute("DELETE FROM node_modes_excluded")
        db.commit()


def insert_deliverable_work_item(cursor, group, mode=ANALYSIS_MODE_ANALYSIS):
    """Like insert_workload_item, but also writes a real RootAnalysis into the group's incoming
    dir so execute() can load it. Returns (work_id, work_uuid)."""
    work_uuid = str(uuid_module.uuid4())
    root = RootAnalysis(
        uuid=work_uuid,
        storage_dir=os.path.join(group.incoming_dir, work_uuid),
        desc='test delivery',
        analysis_mode=mode,
        tool='test_tool',
        tool_instance='test_tool_instance',
        alert_type='test_type')
    root.initialize_storage()
    root.save()

    cursor.execute(
        "INSERT INTO incoming_workload (type_id, mode, work) VALUES (%s, %s, %s)",
        (group.workload_type_id, mode, work_uuid),
    )
    work_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO work_distribution (group_id, work_id, status) VALUES (%s, %s, 'READY')",
        (group.group_id, work_id),
    )
    return work_id, work_uuid


def _work_distribution_row(group, work_id):
    """Returns (status, attempt_count) for the given work item."""
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT status, attempt_count FROM work_distribution WHERE group_id = %s AND work_id = %s",
            (group.group_id, work_id))
        return cursor.fetchone()


@pytest.mark.integration
def test_record_delivery_attempt_increments(remote_node_group):
    """each recorded failure bumps the persisted attempt counter"""
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        work_id, _ = insert_workload_item(
            cursor, remote_node_group.workload_type_id, ANALYSIS_MODE_ANALYSIS,
            remote_node_group.group_id)
        db.commit()

        assert remote_node_group.record_delivery_attempt(db, cursor, work_id) == 1
        assert remote_node_group.record_delivery_attempt(db, cursor, work_id) == 2

    assert _work_distribution_row(remote_node_group, work_id)[1] == 2


@pytest.mark.integration
def test_record_delivery_attempt_dead_letters_unknown_item(remote_node_group):
    """an item we cannot track is reported as exhausted rather than retried forever"""
    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        attempts = remote_node_group.record_delivery_attempt(db, cursor, 999999999)

    assert attempts == remote_node_group.max_delivery_attempts


@pytest.mark.integration
def test_delivery_retries_then_dead_letters(monkeypatch, remote_node_group):
    """a work item that always fails is retried up to max_delivery_attempts, then marked ERROR

    without the bound it would stay LOCKED forever and stall this group's queue"""
    _ensure_live_any_mode_node()
    remote_node_group.max_delivery_attempts = 3

    def _always_fails(self, submission):
        raise requests.exceptions.ConnectionError("target is unreachable")

    monkeypatch.setattr(RemoteNode, "submit", _always_fails)

    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        work_id, _ = insert_deliverable_work_item(cursor, remote_node_group)
        db.commit()

    work_lock_uuid = str(uuid_module.uuid4())

    # first two passes retry and leave the item locked
    for expected_attempts in (1, 2):
        execute_with_db_cursor(DB_COLLECTION, remote_node_group.execute, work_lock_uuid)
        status, attempt_count = _work_distribution_row(remote_node_group, work_id)
        assert status == "LOCKED"
        assert attempt_count == expected_attempts

    # the third exhausts the budget and dead-letters it
    execute_with_db_cursor(DB_COLLECTION, remote_node_group.execute, work_lock_uuid)
    status, attempt_count = _work_distribution_row(remote_node_group, work_id)
    assert status == "ERROR"
    assert attempt_count == 3


@pytest.mark.integration
def test_dead_lettered_item_does_not_block_following_work(monkeypatch, remote_node_group):
    """once a poison item is dead-lettered the group delivers what was queued behind it

    this is the regression: a new batch is only locked when the thread holds no locks, so a
    permanently failing item used to stall everything behind it indefinitely"""
    _ensure_live_any_mode_node()
    remote_node_group.max_delivery_attempts = 2
    # force each pass to handle a single item so the poison item is a batch of its own
    remote_node_group.batch_size = 1

    poison_uuid = {}

    def _fail_only_poison(self, submission):
        if submission.root.uuid == poison_uuid["value"]:
            raise requests.exceptions.ConnectionError("target is unreachable")
        return {"result": submission.root.uuid}

    monkeypatch.setattr(RemoteNode, "submit", _fail_only_poison)

    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        poison_id, poison_root_uuid = insert_deliverable_work_item(cursor, remote_node_group)
        good_id, _ = insert_deliverable_work_item(cursor, remote_node_group)
        db.commit()

    poison_uuid["value"] = poison_root_uuid

    work_lock_uuid = str(uuid_module.uuid4())

    # drive the loop until the poison item is dead-lettered and the good item is delivered
    for _ in range(6):
        execute_with_db_cursor(DB_COLLECTION, remote_node_group.execute, work_lock_uuid)
        if _work_distribution_row(remote_node_group, good_id)[0] == "COMPLETED":
            break

    assert _work_distribution_row(remote_node_group, poison_id)[0] == "ERROR"
    assert _work_distribution_row(remote_node_group, good_id)[0] == "COMPLETED", \
        "work queued behind a poison item must still be delivered"


@pytest.mark.integration
def test_successful_delivery_does_not_record_attempts(monkeypatch, remote_node_group):
    """the attempt counter only moves on failure"""
    _ensure_live_any_mode_node()

    def _always_succeeds(self, submission):
        return {"result": submission.root.uuid}

    monkeypatch.setattr(RemoteNode, "submit", _always_succeeds)

    with get_db_connection(DB_COLLECTION) as db:
        cursor = db.cursor()
        work_id, _ = insert_deliverable_work_item(cursor, remote_node_group)
        db.commit()

    execute_with_db_cursor(DB_COLLECTION, remote_node_group.execute, str(uuid_module.uuid4()))

    status, attempt_count = _work_distribution_row(remote_node_group, work_id)
    assert status == "COMPLETED"
    assert attempt_count == 0
