from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from saq.constants import (
    NODE_EXPECTED_STATE_OFFLINE,
    NODE_EXPECTED_STATE_ONLINE,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
    NODE_STATUS_STARTING,
)
from saq.database.pool import get_db_connection
from saq.database.util.node import (
    get_node_status,
    set_node_expected_state,
    update_collector_status,
)
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineType
from saq.engine.node_manager.local_node_manager import LocalNodeManager
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.environment import get_global_runtime_settings

@pytest.mark.unit
def test_should_update_node_status():
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))

    # never updated yet
    assert node_manager.should_update_node_status() is True

    node_manager._node_manager.next_status_update_time = datetime.now() + timedelta(hours=1)
    assert node_manager.should_update_node_status() is False

    node_manager._node_manager.next_status_update_time = datetime.now() - timedelta(seconds=1)
    assert node_manager.should_update_node_status() is True


@pytest.mark.unit
def test_a_local_engine_gets_the_local_node_manager():
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL)))
    assert isinstance(node_manager._node_manager, LocalNodeManager)
    # a local engine has no node row, so this writes nothing
    node_manager.set_status(NODE_STATUS_RUNNING)


@pytest.mark.integration
def test_distributed_initialize_node_sets_starting_status():
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    assert get_node_status(get_global_runtime_settings().saq_node_id) == NODE_STATUS_STARTING


def _get_node_expected_state(node_id: int) -> str:
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT expected_state FROM nodes WHERE id = %s", (node_id,))
        return cursor.fetchone()[0]


@pytest.mark.integration
def test_distributed_initialize_node_clears_offline_intent():
    """Starting the engine on a node cancels a drain, and that has to include the intent
    to keep it offline -- otherwise a node that was drained, restarted and put back to work
    would stay invisible to monitoring for as long as it ran."""
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    set_node_expected_state(get_global_runtime_settings().saq_node_id, NODE_EXPECTED_STATE_OFFLINE)

    # a second startup, as though the host had been brought back up
    get_global_runtime_settings().saq_node_id = None
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()

    assert _get_node_expected_state(get_global_runtime_settings().saq_node_id) == NODE_EXPECTED_STATE_ONLINE


@pytest.mark.integration
def test_execute_drain_routines():
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    node_id = get_global_runtime_settings().saq_node_id

    # nothing happens when the node is running
    node_manager.set_status(NODE_STATUS_RUNNING)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_RUNNING

    # a draining node with no outstanding work becomes drained
    node_manager.set_status(NODE_STATUS_DRAINING)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINED

    # a drained node that acquired new work reverts to draining
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO workload ( uuid, node_id, analysis_mode, company_id, storage_dir, insert_date )
                          VALUES ( 'b18e1039-cbe9-49f1-b507-d4429e9d0b3c', %s, 'analysis', %s, 'data/test/x', NOW() )""",
                       (node_id, get_global_runtime_settings().company_id))
        db.commit()

    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINING


@pytest.mark.integration
def test_execute_drain_routines_advances_draining_collectors():
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    node_id = get_global_runtime_settings().saq_node_id

    # a live collector with an unflushed backlog holds the node in draining_collectors
    node_manager.set_status(NODE_STATUS_DRAINING_COLLECTORS)
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS

    # once the collector reports drained the node advances to draining
    update_collector_status(node_id, "test", NODE_STATUS_DRAINED, 0)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # and the next cycle completes the drain
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


@pytest.mark.integration
def test_execute_drain_routines_reverts_draining_on_pending_collector(monkeypatch):
    from saq.engine.node_manager import distributed_node_manager

    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    node_id = get_global_runtime_settings().saq_node_id

    # a collector that came back with an unflushed backlog (e.g. crash and restart)
    # reverts a draining node to draining_collectors so the backlog can flush
    # a Mock rather than a stand-in that raises: execute_drain_routines catches and logs anything raised
    transfer = Mock(return_value=(0, 0, 0))
    monkeypatch.setattr(distributed_node_manager, "transfer_delayed_analysis", transfer)
    node_manager.set_status(NODE_STATUS_DRAINING)
    update_collector_status(node_id, "test", NODE_STATUS_DRAINING, 3)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINING_COLLECTORS
    transfer.assert_not_called()


@pytest.mark.integration
def test_execute_drain_routines_skipped_transfers_defer_drained_check(monkeypatch):
    from saq.engine.node_manager import distributed_node_manager

    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    node_manager.initialize_node()
    node_id = get_global_runtime_settings().saq_node_id

    # when transfers were skipped (locked or raced) the drained check is deferred to the next cycle
    monkeypatch.setattr(distributed_node_manager, "transfer_delayed_analysis", lambda: (0, 0, 1))
    node_manager.set_status(NODE_STATUS_DRAINING)
    node_manager._node_manager.execute_drain_routines()
    assert get_node_status(node_id) == NODE_STATUS_DRAINING
