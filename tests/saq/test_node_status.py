import uuid as uuidlib

import pytest

from saq.constants import (
    NODE_EXPECTED_STATE_OFFLINE,
    NODE_EXPECTED_STATE_ONLINE,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
    NODE_STATUS_STARTING,
    NODE_STATUS_STOPPED,
)
from saq.database.pool import get_db_connection
from saq.database.util.node import (
    check_and_advance_collectors_drained,
    drain_node,
    get_node_expected_state,
    resume_node,
    check_and_mark_drained,
    clear_node_status_cache,
    get_collector_statuses,
    get_node_status,
    get_node_status_cached,
    get_node_workload_counts,
    reconcile_stale_node_statuses,
    revert_drained_if_work_appeared,
    revert_draining_if_collector_pending,
    set_node_status,
    transition_node_status,
    update_collector_status,
)
from saq.environment import get_global_runtime_settings

pytestmark = pytest.mark.integration


def local_node_id() -> int:
    return get_global_runtime_settings().saq_node_id


def insert_node(name: str, status: str = NODE_STATUS_RUNNING, last_update_age_seconds: int = 0) -> int:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO nodes ( name, location, company_id, last_update, status )
                          VALUES ( %s, %s, %s, NOW() - INTERVAL %s SECOND, %s )""",
                       (name, "test:443", get_global_runtime_settings().company_id, last_update_age_seconds, status))
        db.commit()
        return cursor.lastrowid


def insert_workload(node_id: int) -> str:
    _uuid = str(uuidlib.uuid4())
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
                          VALUES ( %s, %s, 'analysis', %s, %s, NOW() )""",
                       (_uuid, node_id, get_global_runtime_settings().company_id, f"data/test/{_uuid}"))
        db.commit()

    return _uuid


def insert_delayed_analysis(node_id: int, _uuid: str = None) -> str:
    if _uuid is None:
        _uuid = str(uuidlib.uuid4())

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO delayed_analysis ( uuid, observable_uuid, analysis_module, insert_date, delayed_until, node_id, storage_dir )
                          VALUES ( %s, %s, 'test_module', NOW(), NOW() + INTERVAL 1 HOUR, %s, %s )""",
                       (_uuid, str(uuidlib.uuid4()), node_id, f"data/test/{_uuid}"))
        db.commit()

    return _uuid


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_node_status_cache()
    yield
    clear_node_status_cache()


def test_set_and_get_node_status():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_STARTING)
    assert get_node_status(node_id) == NODE_STATUS_STARTING
    set_node_status(node_id, NODE_STATUS_RUNNING)
    assert get_node_status(node_id) == NODE_STATUS_RUNNING


def test_get_node_status_unknown_node():
    assert get_node_status(999999999) is None


def test_get_node_status_cached():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)
    assert get_node_status_cached(node_id) == NODE_STATUS_RUNNING

    # change the status behind the cache's back
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET status = 'draining' WHERE id = %s", (node_id,))
        db.commit()

    # the cached value is returned until the cache is cleared
    assert get_node_status_cached(node_id) == NODE_STATUS_RUNNING
    clear_node_status_cache()
    assert get_node_status_cached(node_id) == NODE_STATUS_DRAINING


def test_transition_node_status():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)

    # valid transition
    assert transition_node_status(node_id, NODE_STATUS_DRAINING, [NODE_STATUS_RUNNING])
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # invalid transition (already draining)
    assert not transition_node_status(node_id, NODE_STATUS_DRAINING, [NODE_STATUS_RUNNING])
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # resume from either draining or drained
    assert transition_node_status(node_id, NODE_STATUS_RUNNING, [NODE_STATUS_DRAINING, NODE_STATUS_DRAINED])
    assert get_node_status(node_id) == NODE_STATUS_RUNNING


def test_check_and_advance_collectors_drained_no_collectors():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING_COLLECTORS)

    # a node with no collectors advances immediately
    assert check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_check_and_advance_collectors_drained_requires_status():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)
    assert not check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_RUNNING


def test_check_and_advance_collectors_drained_blocked_by_live_collector():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING_COLLECTORS)

    # a live collector that is still flushing blocks the advance
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)
    assert not check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS

    # a drained collector does not
    update_collector_status(node_id, "test", NODE_STATUS_DRAINED, 0)
    assert check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_check_and_advance_collectors_drained_ignores_stopped_collector():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING_COLLECTORS)
    update_collector_status(node_id, "test", NODE_STATUS_STOPPED, 0)
    assert check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_check_and_advance_collectors_drained_ignores_stale_collector(caplog):
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING_COLLECTORS)
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)

    # backdate the collector heartbeat past the stale threshold
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE collector_status SET last_update = NOW() - INTERVAL 1 HOUR WHERE node_id = %s", (node_id,))
        db.commit()

    assert check_and_advance_collectors_drained(node_id, collector_stale_seconds=120)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING
    assert "ignoring stale collector status" in caplog.text


def test_revert_draining_if_collector_pending():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)

    # no collector activity -- stays draining
    assert not revert_draining_if_collector_pending(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # a live collector with an unflushed backlog reverts the node
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)
    assert revert_draining_if_collector_pending(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS


def test_revert_draining_if_collector_pending_ignores_stale_collector():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)

    # a stale collector status does not revert the node
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE collector_status SET last_update = NOW() - INTERVAL 1 HOUR WHERE node_id = %s", (node_id,))
        db.commit()

    assert not revert_draining_if_collector_pending(node_id, collector_stale_seconds=120)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_check_and_mark_drained_no_outstanding_work():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    assert check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


def test_check_and_mark_drained_requires_draining_status():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)
    assert not check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_RUNNING


def test_check_and_mark_drained_blocked_by_workload():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    insert_workload(node_id)
    assert not check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_check_and_mark_drained_delayed_analysis_expected_count():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    insert_delayed_analysis(node_id)

    # a delayed analysis row blocks the drain by default
    assert not check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # unless it is expected (untransferable -- no compatible node exists for it)
    assert check_and_mark_drained(node_id, expected_delayed_count=1)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


def test_check_and_mark_drained_blocked_by_live_collector():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)

    # a live collector that is still draining blocks the drain
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)
    assert not check_and_mark_drained(node_id)

    # a drained collector does not
    update_collector_status(node_id, "test", NODE_STATUS_DRAINED, 0)
    assert check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


def test_check_and_mark_drained_ignores_stale_collector(caplog):
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)

    # backdate the collector heartbeat past the stale threshold
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE collector_status SET last_update = NOW() - INTERVAL 1 HOUR WHERE node_id = %s", (node_id,))
        db.commit()

    assert check_and_mark_drained(node_id, collector_stale_seconds=120)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED
    assert "ignoring stale collector status" in caplog.text


def test_check_and_mark_drained_ignores_stopped_collector():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)
    update_collector_status(node_id, "test", NODE_STATUS_STOPPED, 0)
    assert check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


def test_revert_drained_if_work_appeared():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINED)

    # no work -- stays drained
    assert not revert_drained_if_work_appeared(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED

    # work appeared -- back to draining
    insert_workload(node_id)
    assert revert_drained_if_work_appeared(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_reconcile_stale_node_statuses():
    fresh_id = insert_node("test_fresh_node", NODE_STATUS_RUNNING, last_update_age_seconds=0)
    stale_id = insert_node("test_stale_node", NODE_STATUS_RUNNING, last_update_age_seconds=3600)
    stale_stopped_id = insert_node("test_stale_stopped_node", NODE_STATUS_STOPPED, last_update_age_seconds=3600)

    assert reconcile_stale_node_statuses(120) == 1
    assert get_node_status(fresh_id) == NODE_STATUS_RUNNING
    assert get_node_status(stale_id) == NODE_STATUS_STOPPED
    assert get_node_status(stale_stopped_id) == NODE_STATUS_STOPPED


def test_get_node_workload_counts():
    node_id = local_node_id()
    assert get_node_workload_counts(node_id) == (0, 0)

    insert_workload(node_id)
    insert_workload(node_id)
    insert_delayed_analysis(node_id)

    assert get_node_workload_counts(node_id) == (2, 1)


def test_update_collector_status_upsert():
    node_id = local_node_id()

    update_collector_status(node_id, "test", NODE_STATUS_RUNNING, 0)
    statuses = get_collector_statuses(node_id)
    assert len(statuses) == 1
    name, status, backlog_count, last_update = statuses[0]
    assert name == "test"
    assert status == NODE_STATUS_RUNNING
    assert backlog_count == 0

    # updating the same collector replaces the row
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 5)
    statuses = get_collector_statuses(node_id)
    assert len(statuses) == 1
    name, status, backlog_count, last_update = statuses[0]
    assert status == NODE_STATUS_DRAINING
    assert backlog_count == 5


def test_transition_node_status_writes_expected_state():
    """status and expected_state move in one statement, so operator intent can never
    disagree with the transition that carried it."""
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)

    assert transition_node_status(node_id, NODE_STATUS_DRAINING, [NODE_STATUS_RUNNING],
                                  expected_state=NODE_EXPECTED_STATE_OFFLINE)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING
    assert get_node_expected_state(node_id) == NODE_EXPECTED_STATE_OFFLINE

    # a rejected transition must not write expected_state either
    assert not transition_node_status(node_id, NODE_STATUS_RUNNING, [NODE_STATUS_STARTING],
                                      expected_state=NODE_EXPECTED_STATE_ONLINE)
    assert get_node_expected_state(node_id) == NODE_EXPECTED_STATE_OFFLINE


def test_drain_and_resume_node():
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_RUNNING)

    assert drain_node(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS
    assert get_node_expected_state(node_id) == NODE_EXPECTED_STATE_OFFLINE

    assert resume_node(node_id)
    assert get_node_status(node_id) == NODE_STATUS_RUNNING
    assert get_node_expected_state(node_id) == NODE_EXPECTED_STATE_ONLINE


def test_drain_node_is_rejected_when_not_running():
    """`ace node drain` has to be safe to run twice from a shutdown script, so a second
    drain is a no-op rather than an error."""
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_DRAINING)

    assert not drain_node(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


def test_resume_node_works_from_every_drain_phase():
    node_id = local_node_id()

    for status in (NODE_STATUS_DRAINING_COLLECTORS, NODE_STATUS_DRAINING, NODE_STATUS_DRAINED):
        set_node_status(node_id, status)
        assert resume_node(node_id), f"could not resume from {status}"
        assert get_node_status(node_id) == NODE_STATUS_RUNNING


def test_resume_node_is_rejected_from_stopped():
    """A stopped node is not resumed by an API call -- it is resumed by being started,
    which is what sets it back to starting/running."""
    node_id = local_node_id()
    set_node_status(node_id, NODE_STATUS_STOPPED)

    assert not resume_node(node_id)
    assert get_node_status(node_id) == NODE_STATUS_STOPPED
