#
# TODO: end-to-end tests
#

from datetime import datetime
import os
import threading
from typing import Generator, override
from uuid import uuid4
import pytest
import requests

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import (
    SUBMISSION_OUTCOME_DUPLICATE,
    SUBMISSION_OUTCOME_SCHEDULED,
    Collector,
    CollectorExecutionMode,
    CollectorService,
)
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.remote_node import RemoteNode, RemoteNodeGroup
from saq.collectors.submission_scheduler import SubmissionScheduler
from saq.configuration.config import get_config, get_database_config, get_engine_config, get_service_config
from saq.configuration.schema import DatabaseConfig
from saq.constants import ANALYSIS_MODE_ANALYSIS, DB_ACE, DB_COLLECTION, NODE_STATUS_RUNNING, QUEUE_DEFAULT
from saq.database.model import PersistenceSource
from saq.database.pool import get_db, get_db_connection
from saq.database.util.node import initialize_node
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.environment import get_global_runtime_settings
from saq.logging import get_transaction_id, transaction_id
from saq.util.uuid import get_storage_dir
from saq.collectors.hunter.service import HunterCollector
from tests.saq.helpers import create_staged_submission, log_count, search_log_condition, wait_for_log_count

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

class TestCollectorService(CollectorService):
    pass

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
    #mock_config = configparser.ConfigParser()
    #mock_config.read_string(
        #"""
#[service_test_collector]
#module = tests.saq.collectors.test_base
#class = TestCollectorService
#description = Test Collector
#enabled = yes
#workload_type = test
        #""")

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM work_distribution_groups")
        cursor.execute("DELETE FROM incoming_workload")
        cursor.execute("DELETE FROM workload")
        cursor.execute("UPDATE nodes SET last_update = SUBTIME(NOW(), '01:00:00')")
        db.commit()

    get_config().add_service_config("test_collector", CollectorServiceConfiguration(
        name="test_collector",
        python_module="tests.saq.collectors.test_base",
        python_class="TestCollectorService",
        description="Test Collector",
        enabled=True,
        workload_type="test",
        delete_files=False,
        collection_frequency=1
    ))

    monkeypatch.setattr(get_engine_config(), "local_analysis_modes", [])

@pytest.fixture
def engine():
    result = Engine(config=EngineConfiguration(default_analysis_mode=ANALYSIS_MODE_ANALYSIS))
    result.node_manager.initialize_node()
    result.node_manager.update_node_status()
    # only running nodes are eligible to receive work
    result.node_manager.set_status(NODE_STATUS_RUNNING)
    return result

@pytest.mark.integration
def test_add_group():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test', 100, True, get_global_runtime_settings().company_id, 'ace', target_node_as_company_id=None)
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
        collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
        tg1 = collector_service.create_group_loader()._create_group('test', 100, True, get_global_runtime_settings().company_id, 'ace', target_node_as_company_id=None)
        collector_service.remote_node_groups.append(tg1)
        
        cursor.execute("SELECT id, name FROM work_distribution_groups")
        result = cursor.fetchall()
        assert len(result) == 1
        row = result[0]
        assert row[0] == group_id
        assert row[1] == 'test'

@pytest.mark.integration
def test_load_groups():

    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    collector_service.load_groups()
    assert len(collector_service.remote_node_groups) == 1
    assert collector_service.remote_node_groups[0].name == 'unittest'
    assert collector_service.remote_node_groups[0].coverage == 100
    assert collector_service.remote_node_groups[0].full_delivery
    assert collector_service.remote_node_groups[0].database == 'ace'

@pytest.mark.integration
def test_load_disabled_groups(monkeypatch):

    get_config().get_collection_group_config("unittest").enabled = False

    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    collector_service.load_groups()
    # nothing should be loaded since we disabled the group
    assert not collector_service.remote_node_groups

@pytest.mark.integration
def test_missing_groups():
    # a collector cannot be started without adding at least one group
    get_config().clear_collection_group_configs()
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    with pytest.raises(RuntimeError):
        collector_service.start()

@pytest.mark.system
def test_startup():
    # make sure we can start one up, see it collect nothing, and then shut down gracefully
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test', 100, True, get_global_runtime_settings().company_id, 'ace')
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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, get_global_runtime_settings().company_id, 'ace')
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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    get_config().collection.force_api = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    get_config().collection.force_api = True

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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace', thread_count=2)
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
    get_config().collection.force_api = True

    # test two submissions against a remote node group that is
    # configured with two submission threads and a batch size of one
    # we should see each thread submit a single submission

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(2)]

        def collect(self) -> Generator[Submission, None, None]:
            # hands back everything it has in one pass, like most collectors
            while self.available_work:
                yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace', batch_size=1, thread_count=2)
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
    get_config().collection.force_api = True

    # test two submissions against a remote node group that is
    # configured with two submission threads and a batch size of 2
    # we should see one thread submit two and the other thread submit nothing

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(2)]

        def collect(self) -> Generator[Submission, None, None]:
            # both submissions have to come out of the same pass for them to be batched
            # together - a collector that hands back one per pass would have them a
            # collection_frequency apart
            while self.available_work:
                yield self.available_work.pop()

    # start an engine to get a node created
    #engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    #engine.node_manager.initialize_node()
    #engine.node_manager.update_node_status()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace', batch_size=2, thread_count=2)
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

    _node_id = get_global_runtime_settings().saq_node_id
    _node = get_global_runtime_settings().saq_node
    get_global_runtime_settings().saq_node = 'node_1'
    get_global_runtime_settings().saq_node_id = None
    initialize_node()
    node_1_id = get_global_runtime_settings().saq_node_id
    get_global_runtime_settings().saq_node = 'node_2'
    get_global_runtime_settings().saq_node_id = None
    initialize_node()
    node_2_id = get_global_runtime_settings().saq_node_id

    # we have two nodes at this point
    assert isinstance(node_1_id, int)
    assert isinstance(node_2_id, int)
    assert node_1_id != node_2_id

    # XXX need some abstraction man
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET any_mode = 1")
        db.commit()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    # add a group that only targets node_1 
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, get_global_runtime_settings().company_id, 'ace', target_nodes=['node_1'])
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
    # a node must be running (not just have a fresh heartbeat) to receive work
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET last_update = NOW(), status = 'running' WHERE id = %s", (node_1_id,))
        db.commit()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    # add a group that only targets node_1 
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, get_global_runtime_settings().company_id, 'ace', target_nodes=['node_1'])
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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 50, True, get_global_runtime_settings().company_id, 'ace') # 50% coverage
    tg3 = collector_service.create_group_loader()._create_group('test_group_3', 10, True, get_global_runtime_settings().company_id, 'ace') # 10% coverage, full_coverage = yes
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
    get_config().collection.force_api = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    get_config().collection.force_api = True

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # we do NOT start the API server making it unavailable

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, False, get_global_runtime_settings().company_id, 'ace') # 100% coverage, full_coverage
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
    db_config = get_database_config(DB_ACE)  # noqa: F821
    get_config().add_database_config("ace_2", DatabaseConfig(
        name="ace_2",
        hostname=db_config.hostname,
        unix_socket=db_config.unix_socket,
        database='ace-unittest-2',
        username=db_config.username,
        password=db_config.password,
        ssl_ca=db_config.ssl_ca,
    ))

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage, full_coverage = yes
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, False, get_global_runtime_settings().company_id, 'ace_2') # 100% coverage, full_coverage = no
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
    db_config = get_database_config(DB_ACE)  # noqa: F821
    get_config().add_database_config("ace_2", DatabaseConfig(
        name="ace_2",
        hostname=db_config.hostname,
        unix_socket=db_config.unix_socket,
        database='ace-unittest-2',
        username=db_config.username,
        password=db_config.password,
        ssl_ca=db_config.ssl_ca,
    ))

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage, full_coverage = yes
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, get_global_runtime_settings().company_id, 'ace_2') # 100% coverage, full_coverage = no
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


    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    collector_service.config.delete_files = True
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    assert log_count('scheduled test_description mode analysis') == 1
    assert log_count('submitting 1 items') == 1

    # the file should have been deleted
    assert not os.path.exists(file_path)

@pytest.mark.integration
def test_recovery(mock_api_call, engine, monkeypatch):
    get_config().collection.force_api = True

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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    collector_service = CollectorService(collector=_custom_collector_2(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    get_config().node_translation['unittest'] = '{},test:443'.format(location)

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
    
    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    
    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
    
    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
    tg2 = collector_service.create_group_loader()._create_group('test_group_2', 100, True, get_global_runtime_settings().company_id, 'ace') # 100% coverage
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
def test_persistence_source_created():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    #collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # a persistence source should have been created for this collector service
    assert get_db().query(PersistenceSource).filter(PersistenceSource.name == collector_service.config.workload_type).one_or_none() is not None

@pytest.mark.integration
def test_collector_defaults():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    assert collector_service.config.workload_type == "test"
    assert isinstance(collector_service.workload_type_id, int)
    assert collector_service.config.queue == QUEUE_DEFAULT

@pytest.mark.integration
def test_initialize_service_environment():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    
    # check required directories
    assert os.path.exists(collector_service.persistence_dir)
    assert os.path.exists(collector_service.incoming_dir)

@pytest.mark.integration
def test_add_group_loader():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    assert not collector_service.remote_node_groups
    node = collector_service.create_group_loader()._create_group("test_name", 100, True, get_global_runtime_settings().company_id, DB_COLLECTION)
    collector_service.remote_node_groups.append(node)
    assert isinstance(node, RemoteNodeGroup)
    assert collector_service.remote_node_groups

@pytest.mark.integration
def test_schedule_submission():
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
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
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
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

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    assert isinstance(collector_service.collector, _custom_collector)
    assert not collector_service.collector.updated
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SHOT)
    assert collector_service.collector.updated

# collection cadence tests
# ------------------------------------------------------------------------

class _sleep_recorder:
    """stands in for CollectorService.sleep - records what each loop slept on and stops the loop

    returns True the way the real sleep does once the shutdown event is set, so the loops that
    break on the return value still terminate"""

    def __init__(self, collector_service: CollectorService, stop_after: int = 1):
        self.collector_service = collector_service
        self.stop_after = stop_after
        self.calls = []

    def __call__(self, seconds: float) -> bool:
        self.calls.append(seconds)
        if len(self.calls) >= self.stop_after:
            self.collector_service.shutdown_event.set()

        return self.collector_service.is_shutdown()


def _ensure_node_running():
    """collection_loop pauses on a draining node, and node status outlives the test that set it"""
    from saq.database.util.node import clear_node_status_cache, set_node_status

    set_node_status(get_global_runtime_settings().saq_node_id, NODE_STATUS_RUNNING)
    clear_node_status_cache()


class _paced_collector(TestCollector):
    """yields one fresh submission per pass for the first passes_with_work passes"""

    def __init__(self, passes_with_work: int = 1, **kwargs):
        super().__init__(**kwargs)
        self.passes_with_work = passes_with_work
        self.collect_count = 0

    @override
    def collect(self) -> Generator[Submission, None, None]:
        self.collect_count += 1
        if self.collect_count <= self.passes_with_work:
            yield create_submission()


@pytest.mark.integration
def test_collection_loop_sleeps_after_scheduling_work():
    """a collector that drains its source waits collection_frequency even after a productive pass

    there is nothing left for it to collect when collect() returns, so looping straight back
    around would only re-hit the source"""
    _ensure_node_running()
    collector = _paced_collector(passes_with_work=1)
    collector_service = CollectorService(collector=collector, config=get_service_config("test_collector"))
    assert not collector_service.collect_until_empty

    recorder = _sleep_recorder(collector_service)
    collector_service.sleep = recorder
    collector_service.collection_loop()

    # the pass scheduled work and the loop still slept, so there was only ever one pass
    assert collector.collect_count == 1
    assert recorder.calls == [collector_service.config.collection_frequency]


@pytest.mark.integration
def test_collect_until_empty_skips_the_sleep_after_scheduling_work():
    """a collector that returns a bounded batch runs again immediately while it keeps producing"""
    _ensure_node_running()
    collector = _paced_collector(passes_with_work=1)
    collector.collect_until_empty = True
    collector_service = CollectorService(collector=collector, config=get_service_config("test_collector"))
    assert collector_service.collect_until_empty

    recorder = _sleep_recorder(collector_service)
    collector_service.sleep = recorder
    collector_service.collection_loop()

    # the productive pass was followed immediately by another, and only the empty one slept
    assert collector.collect_count == 2
    assert recorder.calls == [collector_service.config.collection_frequency]


@pytest.mark.integration
def test_collect_until_empty_still_sleeps_when_nothing_is_scheduled():
    """opting in must not let a source that re-serves the same items spin the loop

    the sleep keys off what was scheduled, not what was yielded, so a pass that yields plenty
    and schedules nothing still waits"""
    _ensure_node_running()
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    class _RepeatingCollector(Collector):
        """stands in for a bounded source that hands back the same entry on every pass"""

        collect_until_empty = True

        def __init__(self):
            super().__init__()
            self.collect_count = 0

        def collect(self) -> Generator[Submission, None, None]:
            self.collect_count += 1
            create_staged_submission(file_manager, key="always-the-same")
            yield from file_manager.iter_staged_submissions()

    collector = _RepeatingCollector()
    collector_service.collector = collector

    recorder = _sleep_recorder(collector_service)
    collector_service.sleep = recorder
    collector_service.collection_loop()

    # the first pass schedules the key and runs again immediately, the second yields just as much
    # but schedules nothing and falls through to the sleep
    assert collector.collect_count == 2
    assert recorder.calls == [collector_service.config.collection_frequency]


@pytest.mark.integration
def test_collect_until_empty_config_overrides_the_collector():
    """the collector declares whether it returns a bounded batch, the config gets the last word"""
    collector = TestCollector()
    assert not collector.collect_until_empty

    base_config = get_service_config("test_collector")

    # nothing configured defers to the collector
    assert not CollectorService(collector=collector, config=base_config).collect_until_empty

    # either explicit setting wins over the collector
    on = base_config.model_copy(update={"collect_until_empty": True})
    assert CollectorService(collector=collector, config=on).collect_until_empty

    collector.collect_until_empty = True
    off = base_config.model_copy(update={"collect_until_empty": False})
    assert not CollectorService(collector=collector, config=off).collect_until_empty


@pytest.mark.integration
def test_cleanup_loop_uses_cleanup_frequency():
    """workload cleanup runs on its own schedule - a slow collector must not stall it"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    collector_service.config.collection_frequency = 3600
    collector_service.config.cleanup_frequency = 7

    recorder = _sleep_recorder(collector_service)
    collector_service.sleep = recorder
    collector_service.cleanup_loop()

    assert recorder.calls == [7]


@pytest.mark.integration
def test_update_loop_uses_update_frequency():
    """Collector.update() runs on its own schedule for the same reason"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    collector_service.config.collection_frequency = 3600
    collector_service.config.update_frequency = 11

    recorder = _sleep_recorder(collector_service)
    collector_service.sleep = recorder
    collector_service.update_loop()

    assert recorder.calls == [11]


# node drain tests
# ------------------------------------------------------------------------

@pytest.mark.integration
def test_collection_paused_while_node_draining():
    from saq.constants import NODE_STATUS_DRAINED, NODE_STATUS_DRAINING, NODE_STATUS_DRAINING_COLLECTORS
    from saq.database.util.node import clear_node_status_cache, set_node_status
    from saq.environment import get_global_runtime_settings as _grs

    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    node_id = _grs().saq_node_id

    try:
        # a running (or stopped) node does not pause collection
        set_node_status(node_id, NODE_STATUS_RUNNING)
        assert not collector_service.is_collection_paused()

        # any drain phase pauses collection
        set_node_status(node_id, NODE_STATUS_DRAINING_COLLECTORS)
        assert collector_service.is_collection_paused()

        set_node_status(node_id, NODE_STATUS_DRAINING)
        assert collector_service.is_collection_paused()

        set_node_status(node_id, NODE_STATUS_DRAINED)
        assert collector_service.is_collection_paused()
    finally:
        clear_node_status_cache()


@pytest.mark.integration
def test_collection_loop_skips_collection_while_paused(monkeypatch):
    from saq.constants import NODE_STATUS_DRAINING
    from saq.database.util.node import clear_node_status_cache, set_node_status
    from saq.environment import get_global_runtime_settings as _grs

    class _counting_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.collect_count = 0

        @override
        def collect(self) -> Generator[Submission, None, None]:
            self.collect_count += 1
            if False:
                yield

    collector_service = CollectorService(collector=_counting_collector(), config=get_service_config("test_collector"))
    set_node_status(_grs().saq_node_id, NODE_STATUS_DRAINING)
    clear_node_status_cache()

    try:
        # run the collection loop on a thread in continuous mode while paused
        collector_service.execution_mode = CollectorExecutionMode.CONTINUOUS
        collection_thread = threading.Thread(target=collector_service.collection_loop)
        collection_thread.start()
        assert collector_service.collect_started_event.wait(5)

        # wait for the pause to be logged, then stop
        wait_for_log_count("pausing collection", 1, timeout=5)
        collector_service.shutdown_event.set()
        collection_thread.join(5)
        assert not collection_thread.is_alive()

        # collection never executed
        assert collector_service.collector.collect_count == 0
    finally:
        collector_service.shutdown_event.set()
        clear_node_status_cache()


@pytest.mark.integration
def test_report_collector_status():
    from saq.constants import NODE_STATUS_DRAINED, NODE_STATUS_DRAINING
    from saq.database.util.node import clear_node_status_cache, get_collector_statuses, set_node_status
    from saq.environment import get_global_runtime_settings as _grs

    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    node_id = _grs().saq_node_id

    try:
        # a collector on a running node reports running
        set_node_status(node_id, NODE_STATUS_RUNNING)
        collector_service.report_collector_status()
        statuses = get_collector_statuses(node_id)
        assert len(statuses) == 1
        assert statuses[0][0] == "test"
        assert statuses[0][1] == NODE_STATUS_RUNNING

        # a collector on a draining node with a backlog reports draining
        set_node_status(node_id, NODE_STATUS_DRAINING)
        clear_node_status_cache()

        work_id = collector_service.workload_repository.insert_workload(
            collector_service.workload_type_id, ANALYSIS_MODE_ANALYSIS, str(uuid4()))
        group_id = collector_service.workload_repository.create_or_get_work_distribution_group("test_group_1")
        collector_service.workload_repository.assign_work_to_group(work_id, group_id)

        collector_service.report_collector_status()
        statuses = get_collector_statuses(node_id)
        assert statuses[0][1] == NODE_STATUS_DRAINING
        assert statuses[0][2] == 1

        # once the backlog is flushed it reports drained
        with get_db_connection(DB_COLLECTION) as db:
            cursor = db.cursor()
            cursor.execute("UPDATE work_distribution SET status = 'COMPLETED'")
            db.commit()

        collector_service.report_collector_status()
        statuses = get_collector_statuses(node_id)
        assert statuses[0][1] == NODE_STATUS_DRAINED
        assert statuses[0][2] == 0
    finally:
        clear_node_status_cache()


@pytest.mark.integration
def test_no_submission_to_draining_node(engine):
    from saq.constants import NODE_STATUS_DRAINING

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # the only node available is draining so it cannot receive work
    engine.node_manager.set_status(NODE_STATUS_DRAINING)

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # the work was collected but no node was available to send it to
    assert log_count('no remote nodes are avaiable') == 1

    # the work stays READY in the distribution queue (full delivery group)
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s AND status = 'READY'", (tg1.group_id,))
        assert cursor.fetchone()[0] == 1

        # and nothing landed in the engine workload
        cursor.execute("SELECT COUNT(*) FROM workload")
        assert cursor.fetchone()[0] == 0


@pytest.mark.integration
def test_local_backlog_flushes_while_node_draining_collectors(engine):
    from saq.constants import NODE_STATUS_DRAINED, NODE_STATUS_DRAINING_COLLECTORS
    from saq.database.util.node import get_collector_statuses

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # the only node available is the local node in the first phase of the drain
    # it still accepts work so the collector can flush its backlog
    engine.node_manager.set_status(NODE_STATUS_DRAINING_COLLECTORS)

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # the work was delivered to the local node and the backlog is empty
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM work_distribution WHERE group_id = %s AND status IN ( 'READY', 'LOCKED' )", (tg1.group_id,))
        assert cursor.fetchone()[0] == 0

        cursor.execute("SELECT COUNT(*) FROM workload")
        assert cursor.fetchone()[0] == 1

    # with the backlog flushed the collector reports drained
    collector_service.report_collector_status()
    statuses = get_collector_statuses(get_global_runtime_settings().saq_node_id)
    assert statuses[0][1] == NODE_STATUS_DRAINED
    assert statuses[0][2] == 0

    # and the rest of the drain proceeds: the node advances to draining,
    # the workers finish the workload, and the node is marked drained
    from saq.constants import NODE_STATUS_DRAINING
    from saq.database.util.node import check_and_advance_collectors_drained, check_and_mark_drained, get_node_status

    node_id = get_global_runtime_settings().saq_node_id
    assert check_and_advance_collectors_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINING

    # the flushed work blocks the drain until the workers complete it
    assert not check_and_mark_drained(node_id)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM workload")
        db.commit()

    assert check_and_mark_drained(node_id)
    assert get_node_status(node_id) == NODE_STATUS_DRAINED


@pytest.mark.integration
def test_running_node_preferred_over_draining_collectors_node(engine, monkeypatch):
    from saq.constants import NODE_STATUS_DRAINING_COLLECTORS

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission() for _ in range(1)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    # the local node is starting to drain but another running node is available
    engine.node_manager.set_status(NODE_STATUS_DRAINING_COLLECTORS)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO nodes ( name, location, company_id, last_update, status, any_mode )
                          VALUES ( 'test_running_node', 'test_running_node:443', %s, NOW(), 'running', 1 )""",
                       (get_global_runtime_settings().company_id,))
        db.commit()

    submitted_to = []

    def fake_submit(self, submission):
        submitted_to.append(self.name)
        return {'result': 'test'}

    monkeypatch.setattr(RemoteNode, "submit", fake_submit)

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    # the running node was preferred over the local draining_collectors node
    assert submitted_to == ['test_running_node']

@pytest.mark.integration
def test_submission_adopts_root_transaction_id(engine, monkeypatch):
    """the collector and the node group both do their work under the transaction id
    recorded on the root, so an alert can be traced back to whatever produced it

    the id is asserted against the context actually in effect (rather than the emitted log
    records) because the filter that stamps it onto a record is only installed by
    initialize_logging()"""
    known_transaction_id = str(uuid4())

    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            root = create_root_analysis()
            root.transaction_id = known_transaction_id
            root.save()
            self.available_work = [Submission(root)]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    scheduled_transaction_ids = []
    original_schedule = SubmissionScheduler.schedule_submission
    def _record_schedule(self, submission, remote_node_groups):
        scheduled_transaction_ids.append(get_transaction_id())
        return original_schedule(self, submission, remote_node_groups)

    submitted_transaction_ids = []
    original_submit = RemoteNode.submit
    def _record_submit(self, submission):
        submitted_transaction_ids.append(get_transaction_id())
        return original_submit(self, submission)

    monkeypatch.setattr(SubmissionScheduler, "schedule_submission", _record_schedule)
    monkeypatch.setattr(RemoteNode, "submit", _record_submit)

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    collector_service.remote_node_groups.append(tg1)
    collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    assert scheduled_transaction_ids == [known_transaction_id]
    assert submitted_transaction_ids == [known_transaction_id]

    # and the timing lines we rely on to attribute a delay to a stage are present
    assert log_count("collected submission") == 1
    assert log_count("queued_for=") == 1

@pytest.mark.integration
def test_submission_without_transaction_id_keeps_current(engine, monkeypatch):
    """a root with no recorded transaction id does not clear the ambient one"""
    class _custom_collector(TestCollector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.available_work = [create_submission()]

        def collect(self) -> Generator[Submission, None, None]:
            if not self.available_work:
                return None

            yield self.available_work.pop()

    scheduled_transaction_ids = []
    original_schedule = SubmissionScheduler.schedule_submission
    def _record_schedule(self, submission, remote_node_groups):
        scheduled_transaction_ids.append(get_transaction_id())
        return original_schedule(self, submission, remote_node_groups)

    monkeypatch.setattr(SubmissionScheduler, "schedule_submission", _record_schedule)

    collector_service = CollectorService(collector=_custom_collector(), config=get_service_config("test_collector"))
    tg1 = collector_service.create_group_loader()._create_group('test_group_1', 100, True, get_global_runtime_settings().company_id, 'ace')
    collector_service.remote_node_groups.append(tg1)

    with transaction_id("ambient-transaction-id"):
        collector_service.start(single_threaded=True, execution_mode=CollectorExecutionMode.SINGLE_SUBMISSION)

    assert scheduled_transaction_ids == ["ambient-transaction-id"]


#
# durable staging directory
#
# the collector process is always hard-killed rather than shut down cleanly, so work that has
# been emitted but not yet collected has to survive on disk.
#

@pytest.mark.integration
def test_staged_submissions_survive_a_restart():
    """a fresh CollectorService collects whatever the previous one left staged"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    staged = [create_staged_submission(file_manager) for _ in range(3)]

    # stand in for a restart - a brand new service against the same directories
    recovered_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    recovered = recovered_service.file_manager.list_staged_submissions()

    assert sorted(recovered) == sorted(staged)


@pytest.mark.integration
def test_purge_incomplete_staging_leaves_committed_work():
    """startup cleanup removes half-built submissions but not staged ones"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    staged_uuid = create_staged_submission(file_manager)
    incomplete_dir = file_manager.get_staging_tmp_path("half-built")
    os.makedirs(incomplete_dir, exist_ok=True)

    assert file_manager.purge_incomplete_staging() >= 1

    assert not os.path.exists(incomplete_dir)
    assert file_manager.list_staged_submissions() == [staged_uuid]


@pytest.mark.integration
def test_scheduling_removes_submission_from_staging():
    """a scheduled submission leaves the staging directory - that move is the commit point"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    create_staged_submission(file_manager)
    submission = next(iter(file_manager.iter_staged_submissions()))

    collector_service.process_submission(submission)

    assert file_manager.list_staged_submissions() == []
    assert file_manager.submission_directory_exists(submission.root.uuid)


@pytest.mark.integration
def test_duplicate_submission_removed_from_staging():
    """a duplicate never reaches the incoming dir, so it must be discarded explicitly

    without this it would be re-collected on every pass forever"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    # first one through marks the key as seen
    create_staged_submission(file_manager, key="repeated-key")
    first = next(iter(file_manager.iter_staged_submissions()))
    collector_service.process_submission(first)

    # second one with the same key is a duplicate
    duplicate_uuid = create_staged_submission(file_manager, key="repeated-key")
    duplicate = next(iter(file_manager.iter_staged_submissions()))
    assert duplicate.root.uuid == duplicate_uuid

    collector_service.process_submission(duplicate)

    assert file_manager.list_staged_submissions() == []
    assert not file_manager.submission_directory_exists(duplicate_uuid)


@pytest.mark.integration
def test_repeated_duplicates_are_not_counted_as_scheduled_work():
    """a source that keeps re-serving the same items must not starve the collector of its sleep

    execute_collection_loop reports what it yielded and what it actually scheduled, and
    collection_loop sleeps on the scheduled count. keying the sleep off the yielded count
    instead lets a collector whose source re-serves the same items spin as fast as that source
    can answer, since every pass yields a nonzero count that is then dropped as duplicate.

    this holds regardless of collect_until_empty - see
    test_collect_until_empty_still_sleeps_when_nothing_is_scheduled"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    class _RepeatingCollector(Collector):
        """stands in for a source that hands back the same entry on every pass"""

        def collect(self) -> Generator[Submission, None, None]:
            create_staged_submission(file_manager, key="always-the-same")
            yield from file_manager.iter_staged_submissions()

    collector_service.collector = _RepeatingCollector()

    # the first pass sees the key for the first time, so it becomes real work
    assert collector_service.execute_collection_loop() == (1, 1)

    # every pass after that yields just as much but schedules nothing, which is what lets
    # collection_loop fall through to sleep(collection_frequency)
    assert collector_service.execute_collection_loop() == (1, 0)
    assert collector_service.execute_collection_loop() == (1, 0)


@pytest.mark.integration
def test_duplicate_submission_reports_duplicate_outcome():
    """process_submission reports why it dropped a submission, not just that it did"""
    collector_service = CollectorService(collector=TestCollector(), config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager

    create_staged_submission(file_manager, key="repeated-key")
    first = next(iter(file_manager.iter_staged_submissions()))
    assert collector_service.process_submission(first) == (False, SUBMISSION_OUTCOME_SCHEDULED)

    create_staged_submission(file_manager, key="repeated-key")
    duplicate = next(iter(file_manager.iter_staged_submissions()))
    assert collector_service.process_submission(duplicate) == (False, SUBMISSION_OUTCOME_DUPLICATE)


@pytest.mark.integration
def test_failing_submission_is_quarantined_not_retried_forever():
    """a submission that fails to process is moved aside rather than blocking the queue

    staged submissions persist until they reach a terminal outcome, so without this a
    permanently failing submission would be retried on every pass and - because one exception
    abandons the rest of the batch - would block everything queued behind it"""
    # HunterCollector is the collector that actually reads from the staging directory
    collector = HunterCollector()
    collector_service = CollectorService(collector=collector, config=get_service_config("test_collector"))
    file_manager = collector_service.file_manager
    collector.file_manager = file_manager

    poison_uuid = create_staged_submission(file_manager)
    good_uuid = create_staged_submission(file_manager)

    processed = []

    def _explode(submission):
        if submission.root.uuid == poison_uuid:
            raise RuntimeError("nope")

        processed.append(submission.root.uuid)
        return False, SUBMISSION_OUTCOME_SCHEDULED

    collector_service.process_submission = _explode
    collector_service.execute_collection_loop()

    # the poison submission is out of staging and available for review
    assert poison_uuid not in file_manager.list_staged_submissions()
    assert os.path.isdir(os.path.join(file_manager.error_dir, poison_uuid))

    # and the submission queued behind it was still handed to process_submission rather than
    # being abandoned along with the rest of the batch
    assert good_uuid in processed
