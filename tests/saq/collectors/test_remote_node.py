from threading import Event
import pytest

from saq.analysis.root import RootAnalysis
from saq.collectors.remote_node import RemoteNode, RemoteNodeGroup
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, DB_COLLECTION, G_COMPANY_ID, G_SAQ_NODE
from saq.database.pool import get_db_connection
from saq.environment import g, g_int
from saq.util.time import local_time
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_submission

@pytest.fixture
def remote_node() -> RemoteNode:
    return RemoteNode(
        1, g(G_SAQ_NODE), "location", 1, local_time(), ANALYSIS_MODE_ANALYSIS, 1)

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

    return RemoteNodeGroup("test", 100, True, g_int(G_COMPANY_ID), DB_COLLECTION, group_id, workload_type_id, Event())
