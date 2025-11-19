#
# TODO: end-to-end tests
#

import configparser
from datetime import datetime
import os
import shutil
import threading
from typing import Generator, override
from uuid import uuid4
import pytest
import requests

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.remote_node import RemoteNode, RemoteNodeGroup
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, CONFIG_ENGINE, DB_COLLECTION, G_COMPANY_ID, G_SAQ_NODE, G_SAQ_NODE_ID, QUEUE_DEFAULT
from saq.database.model import PersistenceSource
from saq.database.pool import get_db, get_db_connection
from saq.database.util.node import initialize_node
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.environment import g, g_int, get_data_dir, set_g
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import log_count, search_log_condition, wait_for_log_count

def create_root_analysis() -> RootAnalysis:
    root_uuid = str(uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=get_storage_dir(root_uuid),
        desc='test_description',
        analysis_mode='analysis',
        tool='unittest_tool',
        tool_instance='unittest_tool_instance',
        alert_type='unittest_type',
        event_time=datetime.now(),
        details={'hello': 'world'})
    root.initialize_storage()
    root.save()
    return root

def create_submission(**kwargs):
    return Submission(create_root_analysis(), **kwargs)

class custom_submission(Submission):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.success_event = threading.Event()
        self.fail_event = threading.Event()

    def success(self, group, result):
        self.success_event.set()

    def fail(self, group):
        self.fail_event.set()

class TestCollector(Collector):
    __test__ = False

    @override
    def collect(self) -> Generator[Submission, None, None]:
        if False:
            yield  # This is a stub to satisfy the type checker and linter.

    @override
    def update(self) -> None:
        pass

    @override
    def cleanup(self) -> None:
        pass

@pytest.fixture(autouse=True)
def setup(monkeypatch):
    mock_config = configparser.ConfigParser()
    mock_config.read_string(
        """
[service_test_collector]
module = tests.saq.collectors.test_base
class = TestCollector
description = Test Collector
enabled = yes
workload_type = test
        """)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM work_distribution_groups")
        cursor.execute("DELETE FROM incoming_workload")
        cursor.execute("DELETE FROM workload")
        cursor.execute("UPDATE nodes SET last_update = SUBTIME(NOW(), '01:00:00')")
        db.commit()

    get_config()["service_test_collector"] = mock_config["service_test_collector"]
    #monkeypatch.setitem(get_config(), "service_test_collector", mock_config["service_test_collector"])
    monkeypatch.setitem(get_config()[CONFIG_ENGINE], "local_analysis_modes", "")

@pytest.fixture
def engine():
    result = Engine(config=EngineConfiguration(default_analysis_mode=ANALYSIS_MODE_ANALYSIS))
    result.node_manager.initialize_node()
    result.node_manager.update_node_status()
    return result

@pytest.mark.integration
def test_add_group():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test', 100, True, g_int(G_COMPANY_ID), 'ace', target_node_as_company_id=None)
    collector_service.remote_node_groups.append(tg1)
    
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, name FROM work_distribution_groups")
        result = cursor.fetchall()

        assert len(result) == 1
        row = result[0]
        group_id = row[0]
        assert row[1] == 'test'

        # when we do it a second time, we should get the name group ID since we used the same name
        collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
        tg1 = collector_service.create_group_loader()._create_group('test', 100, True, g_int(G_COMPANY_ID), 'ace', target_node_as_company_id=None)
        collector_service.remote_node_groups.append(tg1)
        
        cursor.execute("SELECT id, name FROM work_distribution_groups")
        result = cursor.fetchall()
        assert len(result) == 1
        row = result[0]
        assert row[0] == group_id
        assert row[1] == 'test'

@pytest.mark.integration
def test_load_groups():

    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    collector_service.load_groups()
    assert len(collector_service.remote_node_groups) == 1
    assert collector_service.remote_node_groups[0].name == 'unittest'
    assert collector_service.remote_node_groups[0].coverage == 100
    assert collector_service.remote_node_groups[0].full_delivery
    assert collector_service.remote_node_groups[0].database == 'ace'

@pytest.mark.integration
def test_load_disabled_groups(monkeypatch):

    monkeypatch.setitem(get_config()["collection_group_unittest"], "enabled", False)

    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    collector_service.load_groups()
    # nothing should be loaded since we disabled the group
    assert not collector_service.remote_node_groups

@pytest.mark.integration
def test_missing_groups():
    # a collector cannot be started without adding at least one group
    del get_config()['collection_group_unittest']
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    with pytest.raises(RuntimeError):
        collector_service.start()

@pytest.mark.system
def test_startup():
    # make sure we can start one up, see it collect nothing, and then shut down gracefully
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test', 100, True, g_int(G_COMPANY_ID), 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.start()
    assert collector_service.wait_for_start(timeout=5)

    collector_service.stop()
    collector_service.wait()

@pytest.mark.integration
def test_work_item():
    class _custom_collector(TestCollector):
        @override
        def collect(self) -> Generator[Submission, None, None]:
            if not hasattr(self, 'submitted'):
                self.submitted = True
                yield create_submission()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace')
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, g_int(G_COMPANY_ID), 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    assert log_count('scheduled test_description mode analysis') == 1

    # we should have a single entry in the incoming_workload table
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, mode, work FROM incoming_workload")
        work = cursor.fetchall()
        assert len(work) == 1
        work = work[0]
        _id, mode, root_uuid = work
        assert mode == 'analysis'
        root = RootAnalysis(storage_dir=os.path.join(collector_service.incoming_dir, root_uuid))
        root.load()
        submission = Submission(root)
        assert isinstance(submission, Submission)
        assert submission.root.description == 'test_description'
        assert submission.root.details == {'hello': 'world'}

        # and then we should have two assignments for the two groups
        cursor.execute("SELECT group_id, work_id, status FROM work_distribution WHERE work_id = %s", (_id,))
        assignments = cursor.fetchall()
        assert len(assignments) == 2
        for group_id, work_id, status in assignments:
            assert status == 'READY'

@pytest.mark.integration
def test_submit(engine):

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') ==  1
    assert log_count('submitting 1 items') == 1
    assert log_count('completed work item') == 1

    # both the incoming_workload and work_distribution tables should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

        # and we should have one item in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0] == 1

@pytest.mark.integration
def test_submit_api(mock_api_call, engine):
    # same as test_submit except we force the use of the api
    get_config()['collection']['force_api'] = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') == 1
    assert log_count('submitting 1 items') == 1
    assert log_count('completed work item') == 1

    # both the incoming_workload and work_distribution tables should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

        # and we should have one item in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0] == 1

@pytest.mark.system
def test_threaded_remote_node_single_submission(mock_api_call, engine):
    get_config()['collection']['force_api'] = True

    # test a single submissions against a remote node group that is
    # configured with two submission threads 

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace', thread_count=2)
    collector_service.remote_node_groups.append(tg1)
    collector_service.start()
    assert collector_service.wait_for_start(timeout=5)

    # we should see 1 of these
    wait_for_log_count('scheduled test_description mode analysis', 1, 5)
    wait_for_log_count('submitting 1 items', 1, 5)
    wait_for_log_count('completed work item', 1, 5)

    collector_service.stop()
    collector_service.wait()

    # both the incoming_workload and work_distribution tables should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

        # and we should have one item in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0], 1

@pytest.mark.system
def test_threaded_remote_node_multi_submissions(mock_api_call, engine):
    get_config()['collection']['force_api'] = True

    # test two submissions against a remote node group that is
    # configured with two submission threads and a batch size of one
    # we should see each thread submit a single submission

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(2)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace', batch_size=1, thread_count=2)
    collector_service.remote_node_groups.append(tg1)
    collector_service.start()
    assert collector_service.wait_for_start(timeout=5)

    # we should see 2 of these
    wait_for_log_count('scheduled test_description mode analysis', 2, 5)
    wait_for_log_count('submitting 1 items', 2, 5)
    wait_for_log_count('completed work item', 2, 5)

    collector_service.stop()
    collector_service.wait()

    # both the incoming_workload and work_distribution tables should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

        # and we should have two items in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload")
        assert cursor.fetchone()[0] == 2

@pytest.mark.system
def test_threaded_remote_node_multi_submissions_with_large_batch(engine):
    get_config()['collection']['force_api'] = True

    # test two submissions against a remote node group that is
    # configured with two submission threads and a batch size of 2
    # we should see one thread submit two and the other thread submit nothing

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(2)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # start an engine to get a node created
    #engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    #engine.node_manager.initialize_node()
    #engine.node_manager.update_node_status()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace', batch_size=2, thread_count=2)
    collector_service.remote_node_groups.append(tg1)
    collector_service.start()
    assert collector_service.wait_for_start(timeout=5)

    # TODO
    wait_for_log_count('scheduled test_description mode analysis', 2, 5)
    wait_for_log_count('submitting 2 items', 1, 5)

    collector_service.stop()
    collector_service.wait()

    # both the incoming_workload and work_distribution tables should have 2 entries
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 2
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 2

@pytest.mark.integration
def test_submit_target_nodes(mock_api_call):
    from saq.database import initialize_node

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    _node_id = g_int(G_SAQ_NODE_ID)
    _node = g(G_SAQ_NODE)
    set_g(G_SAQ_NODE, 'node_1')
    set_g(G_SAQ_NODE_ID, None)
    initialize_node()
    node_1_id = g_int(G_SAQ_NODE_ID)
    set_g(G_SAQ_NODE, 'node_2')
    set_g(G_SAQ_NODE_ID, None)
    initialize_node()
    node_2_id = g_int(G_SAQ_NODE_ID)

    # we have two nodes at this point
    assert isinstance(node_1_id, int)
    assert isinstance(node_2_id, int)
    assert node_1_id != node_2_id

    # XXX need some abstraction man
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET any_mode = 1")
        db.commit()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    # add a group that only targets node_1 
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, g_int(G_COMPANY_ID), 'ace', target_nodes=['node_1'])
    collector_service.remote_node_groups.append(tg1)

    # and then take node_1 offline
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET last_update = DATE_ADD(last_update, INTERVAL -1 DAY) WHERE id = %s", (node_1_id,))
        db.commit()

    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see a warning that no nodes are available, even though node_2 is set to any and is active
    assert log_count('no remote nodes are avaiable') == 1

    # make sure nothing was attempted to be submitted
    assert log_count('submitting 1 items') == 0

    # now make node_1 active and run again
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET last_update = NOW() WHERE id = %s", (node_1_id,))
        db.commit()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    # add a group that only targets node_1 
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, g_int(G_COMPANY_ID), 'ace', target_nodes=['node_1'])
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # should see the attempt to submit the item now
    assert log_count("submitting 1 items") == 1

@pytest.mark.integration
def test_coverage(engine):
    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(10)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 50, True, g_int(G_COMPANY_ID), 'ace') # 50% coverage
    tg3 = collector_service.create_group_loader()._create_group('test_group_3', 10, True, g_int(G_COMPANY_ID), 'ace') # 10% coverage, full_coverage = yes
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.remote_node_groups.append(tg3)
    for _ in range(10):
        collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)
    
    # we should see 10 of these
    assert log_count('scheduled test_description mode analysis') ==  10
    # and then 16 of these
    assert log_count('got submission result') == 16
    # and 10 of these
    assert log_count('completed work item') == 10

    # both the incoming_workload and work_distribution tables should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        # both the incoming_workload and work_distribution tables should be empty
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg2.group_id,))
        assert cursor.fetchone()[0] == 0
        # both the incoming_workload and work_distribution tables should be empty
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg3.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

    # there should be 10 of these messages for test_group_1
    assert len(search_log_condition(lambda r: 'test_group_1' in r.getMessage() and 'got submission result' in r.getMessage())) == 10

    # and then 5 for this one
    assert len(search_log_condition(lambda r: 'test_group_2' in r.getMessage() and 'got submission result' in r.getMessage())) == 5

    # and just 1 for this one
    assert len(search_log_condition(lambda r: 'test_group_3' in r.getMessage() and 'got submission result' in r.getMessage())) == 1

@pytest.mark.integration
def test_fail_submit_full_coverage(engine): # NOTE we do not start the api server
    get_config()['collection']['force_api'] = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') == 1

    # watch for the failure
    assert log_count('unable to submit work item') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # both the work_distribution and incoming_workload tables should have entries for the work item
        # that has not been sent yet
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 1
        # both the incoming_workload and work_distribution tables should be empty
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 1

        # and we should have 0 in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0] == 0

@pytest.mark.integration
def test_fail_submit_no_coverage(engine):
    get_config()['collection']['force_api'] = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # we do NOT start the API server making it unavailable

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, g_int(G_COMPANY_ID), 'ace') # 100% coverage, full_coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') == 1

    # watch for the failure
    assert log_count('unable to submit work item') == 1

    # wait for the queue to clear
    assert log_count('completed work item') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # everything should be empty at this point since we do not have full coverage
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        # both the incoming_workload and work_distribution tables should be empty
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

@pytest.mark.integration
def test_no_coverage_missing_node(mock_api_call, engine):
    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None
            
            yield self.available_work.pop()


    # enable the second ace database schema built that is entirely empty
    # this is where we look for nodes in the "ace_2" remote node group (see below)
    get_config()['database_ace_2'] = {
        'hostname': get_config()['database_ace']['hostname'],
        'unix_socket': get_config()['database_ace']['unix_socket'],
        'database': 'ace-unittest-2',
        'username': get_config()['database_ace']['username'],
        'password': get_config()['database_ace']['password'],
        #'ssl_ca': get_config['database_ace']['ssl_ca'],
    }

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage, full_coverage = yes
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, False, g_int(G_COMPANY_ID), 'ace_2') # 100% coverage, full_coverage = no
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') == 1

    # watch for the failure
    assert log_count('no remote nodes are avaiable for all analysis modes') == 1

    # wait for the queue to clear
    assert log_count('completed work item') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # everything should be empty at this point since we do not have full coverage
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        # both the incoming_workload and work_distribution tables should be empty
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

@pytest.mark.integration
def test_full_coverage_missing_node(mock_api_call, engine):
    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None
            
            yield self.available_work.pop()

    # enable the second ace database schema built that is entirely empty
    # this is where we look for nodes in the "ace_2" remote node group (see below)
    get_config()['database_ace_2'] = {
        'hostname': get_config()['database_ace']['hostname'],
        'unix_socket': get_config()['database_ace']['unix_socket'],
        'database': 'ace-unittest-2',
        'username': get_config()['database_ace']['username'],
        'password': get_config()['database_ace']['password'],
        #'ssl_ca': get_config['database_ace']['ssl_ca'],
    }

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage, full_coverage = yes
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, g_int(G_COMPANY_ID), 'ace_2') # 100% coverage, full_coverage = no
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('scheduled test_description mode analysis') == 1

    # watch for the failure
    assert log_count('no remote nodes are avaiable for all analysis modes') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # the first group assignment should have completed
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s AND status = 'COMPLETED'", (tg1.group_id,))
        assert cursor.fetchone()[0] == 1
        # the second group assignment should still be in ready status
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s AND status = 'READY'", (tg2.group_id,))
        assert cursor.fetchone()[0] == 1
        # and we should still have our workload item
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 1

@pytest.mark.integration
def test_cleanup_files(tmpdir, engine):

    file_path = tmpdir / "temp_file.txt"
    file_path.write_binary(b"Hello, world!")
    file_path = str(file_path)

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.work = create_submission()
            self.work.root.add_file_observable(file_path, move=True)

        def collect(self) -> Generator[Submission, None, None]:
            if self.work:
                result = self.work
                self.work = None
                yield result


    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    collector_service.config.delete_files = True
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    assert log_count('scheduled test_description mode analysis') == 1
    assert log_count('submitting 1 items') == 1

    # the file should have been deleted
    assert not os.path.exists(file_path)

@pytest.mark.integration
def test_recovery(mock_api_call, engine, monkeypatch):
    get_config()['collection']['force_api'] = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(10)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None
            
            yield self.available_work.pop()


    class _custom_collector_2(TestCollector):
        def collect(self) -> Generator[Submission, None, None]:
            if False:
                yield None

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)

    def fail_execute_api_call(*args, **kwargs):
        # the exception type is important, it decides if we retry or not
        raise requests.exceptions.ConnectionError("controlled failure")

    with monkeypatch.context() as m_context:
        import ace_api
        m_context.setattr(ace_api, "_execute_api_call", fail_execute_api_call)

        for _ in range(10):
            collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    # the API server is not running so these will fail
    assert log_count('scheduled test_description mode analysis') == 10
    assert log_count('unable to submit work item') == 10

    with get_db_connection() as db:
        cursor = db.cursor()
        # both the incoming_workload and work_distribution tables should have all 10 items
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 10
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 10

    for node in collector_service.remote_node_groups:
        node.release_work_locks()

    # NOW "start" the API server
    # and then start up the collector
    collector_service = CollectorService(collector=_custom_collector_2(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)

    for _ in range(10):
        collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    # with the API server running now we should see these go out
    assert log_count('completed work item') == 10

    # now these should be empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0

        # and we should have 10 workload entries
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0] == 10

@pytest.mark.unit
def test_node_translation():

    initialize_node()
    engine = Engine()
    engine.node_manager.update_node_status()

    # get the current node settings from the database
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT id, name, location, company_id, last_update, is_primary, any_mode FROM nodes")
        node_id, name, location, _, last_update, _, any_mode = cursor.fetchone()

    # add a configuration to map this location to a different location
    get_config()['node_translation']['unittest'] = '{},test:443'.format(location)

    remote_node = RemoteNode(node_id, name, location, any_mode, last_update, ANALYSIS_MODE_ANALYSIS, 0)
    assert remote_node.location == 'test:443'

@pytest.mark.integration
def test_node_assignment(engine):

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            submission = create_submission()
            submission.group_assignments = ['test_group_1']
            self.available_work = [submission]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()
    
    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION, execute_nodes=False)

    with get_db_connection() as db:
        cursor = db.cursor()
        # after this is executed we should have an assignment to test_group_1 but not test_group_2
        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_1',))
        assert cursor.fetchone()[0] ==  1

        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_2',))
        assert cursor.fetchone()[0] == 0

@pytest.mark.integration
def test_node_default_assignment(engine):

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # we don't make any custom assignments
            self.available_work = [create_submission()]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()
    
    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION, execute_nodes=False)

    with get_db_connection() as db:
        cursor = db.cursor()
        # after this is executed we should have assignments to both groups
        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_1',))
        assert cursor.fetchone()[0] == 1

        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_2',))
        assert cursor.fetchone()[0] == 1

@pytest.mark.integration
def test_node_invalid_assignment(engine):

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            submission = create_submission()
            # we assign to an invalid (unknown) group
            submission.group_assignments = ['test_group_invalid']
            self.available_work = [submission]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None
            
            yield self.available_work.pop()
    
    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.remote_node_groups.append(tg2)
    collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION, execute_nodes=False)

    with get_db_connection() as db:
        cursor = db.cursor()
        # after this is executed we should have an assignment to test_group_1 but not test_group_2
        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_1',))
        assert cursor.fetchone()[0] == 1

        cursor.execute("""SELECT COUNT(*) FROM work_distribution JOIN work_distribution_groups ON work_distribution.group_id = work_distribution_groups.id
                        WHERE work_distribution_groups.name = %s""", ('test_group_2',))
        assert cursor.fetchone()[0] == 1

@pytest.mark.integration
def test_submission_filter(engine):

    tuning_rule_dir = os.path.join(get_data_dir(), 'tuning_rules')
    if os.path.isdir(tuning_rule_dir):
        shutil.rmtree(tuning_rule_dir)

    os.mkdir(tuning_rule_dir)
    get_config()['collection']['tuning_dir_default'] = tuning_rule_dir

    with open(os.path.join(tuning_rule_dir, 'filter.yar'), 'w') as fp:
        fp.write("""
rule test_filter {
meta:
    targets = "submission"
strings:
    $ = "description = test_description"
condition:
    all of them
}
""")

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None
            
            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, g_int(G_COMPANY_ID), 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # we should see 1 of these
    assert log_count('submission test_description matched 1 tuning rules') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # everything should be empty
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM incoming_workload")
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM workload ")
        assert cursor.fetchone()[0] == 0

@pytest.mark.integration
def test_persistence_source_created():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    #collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # a persistence source should have been created for this collector service
    assert get_db().query(PersistenceSource).filter(PersistenceSource.name == collector_service.config.workload_type).one_or_none() is not None

@pytest.mark.integration
def test_collector_defaults():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    assert collector_service.config.workload_type == "test"
    assert isinstance(collector_service.workload_type_id, int)
    assert collector_service.config.queue == QUEUE_DEFAULT

@pytest.mark.integration
def test_initialize_service_environment():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    
    # check required directories
    assert os.path.exists(collector_service.persistence_dir)
    assert os.path.exists(collector_service.incoming_dir)

@pytest.mark.integration
def test_add_group_loader():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    assert not collector_service.remote_node_groups
    node = collector_service.create_group_loader()._create_group("test_name", 100, True, g_int(G_COMPANY_ID), DB_COLLECTION)
    collector_service.remote_node_groups.append(node)
    assert isinstance(node, RemoteNodeGroup)
    assert collector_service.remote_node_groups

@pytest.mark.integration
def test_schedule_submission():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    assert collector_service.submission_scheduler is not None

    assert collector_service.submission_scheduler.schedule_submission(Submission(RootAnalysis(
        desc="test",
        analysis_mode=ANALYSIS_MODE_ANALYSIS,
        tool="test_tool",
        tool_instance="test_tool_instance",
        alert_type="test_type",
    )), collector_service.remote_node_groups) >= 0

    # unknown node group assignment
    assert collector_service.submission_scheduler.schedule_submission(create_submission(group_assignments=["unknown"]), collector_service.remote_node_groups) >= 0

@pytest.mark.integration
def test_clear_expired_persistent_data():
    collector_service = CollectorService(collector=TestCollector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    assert collector_service.persistence_manager is not None
    
    collector_service.persistence_manager.save_persistent_data("test", "test")
    assert collector_service.persistence_manager.load_persistent_data("test") == "test"
    
    # default config does it after delay
    collector_service.clear_expired_persistent_data()
    assert collector_service.persistence_manager.load_persistent_data("test") == "test"

    # eliminate delay
    collector_service.config.persistence_clear_seconds = 0
    collector_service.config.persistence_expiration_seconds = 0
    collector_service.config.persistence_unmodified_expiration_seconds = 0

    # should clear now
    collector_service.clear_expired_persistent_data()
    with pytest.raises(KeyError):
        collector_service.persistence_manager.load_persistent_data("test")


@pytest.mark.integration
def test_collector_update():
    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.updated = False

        @override
        def update(self) -> None:
            self.updated = True

    collector_service = CollectorService(collector=_custom_collector(), config=CollectorServiceConfiguration.from_config(get_config()['service_test_collector']))
    assert isinstance(collector_service.collector, _custom_collector)
    assert not collector_service.collector.updated
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SHOT)
    assert collector_service.collector.updated