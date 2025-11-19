from datetime import datetime, timedelta
from glob import glob
import json
from multiprocessing import cpu_count
import os
import re
import shutil
import signal
import uuid
import pytest

from saq.analysis.analysis import Analysis, UnknownAnalysis
from saq.analysis.io_tracking import _get_io_read_count, _get_io_write_count
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED, CONFIG_ENGINE, CONFIG_ENGINE_AUTO_REFRESH_FREQUENCY, CONFIG_ENGINE_COPY_FILE_ON_ERROR, CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_WARNING_TIME, DIRECTIVE_ARCHIVE, DIRECTIVE_IGNORE_AUTOMATION_LIMITS, DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE, F_FILE, F_TEST, F_USER, G_API_PREFIX, G_COMPANY_ID, G_LOCK_TIMEOUT_SECONDS, G_MODULE_STATS_DIR, G_SAQ_NODE, G_SAQ_NODE_ID, G_TEMP_DIR
from saq.database.model import Alert, DelayedAnalysis, User, Workload, load_alert
from saq.database.pool import get_db, get_db_connection
from saq.database.util.alert import set_dispositions
from saq.database.util.locking import acquire_lock
from saq.database.util.node import get_node_excluded_analysis_modes, get_node_included_analysis_modes, node_supports_any_analysis_mode
from saq.database.util.tag_mapping import add_observable_tag_mapping, remove_observable_tag_mapping
from saq.database.util.workload import add_workload
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType
from saq.environment import g, g_int, g_obj, get_data_dir, reset_node, set_g
from saq.modules.test import BasicTestAnalysis, ConfigurableModuleTestAnalysis, DelayedAnalysisTestAnalysis, FileSizeLimitAnalysis, FinalAnalysisTestAnalysis, GenericTestAnalysis, GroupedByTimeRangeAnalysis, GroupingTargetAnalysis, PostAnalysisTestResult, TestInstanceAnalysis, WaitAnalysis_A, WaitAnalysis_B, WaitAnalysis_C, WaitAnalyzerModule_B
from saq.observables.file import FileObservable
from saq.util.maintenance import cleanup_alerts
from saq.util.time import parse_event_time
from saq.util.uuid import get_storage_dir, workload_storage_dir
from tests.saq.helpers import create_root_analysis, log_count, search_log, search_log_regex, track_io, wait_for_log_count, wait_for_process

@pytest.mark.system
def test_signal_TERM():
    engine = Engine()
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

@pytest.mark.system
def test_signal_INT():
    engine = Engine()
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

@pytest.mark.system
def test_signal_HUP():
    engine = Engine()
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    # tell ACE to reload the configuration and then reload all the workers
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGHUP)

    #wait_for_log_count('reloading engine configuration', 1, 5)
    wait_for_log_count('restarting all workers', 1, 5)
    wait_for_log_count('started worker', 2)
    
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

@pytest.mark.system
def test_engine_default_pools():

    del get_config()["service_engine"]["pool_size_limit"]

    # test starting with no analysis pools defined
    engine = Engine()
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

    # we should see this log message
    regex = re.compile(r'no analysis pools defined -- defaulting to (\d+) workers assigned to any pool')
    results = search_log_regex(regex)
    assert len(results) == 1
    match = regex.search(results[0].getMessage())
    assert match
    assert int(match.group(1)) == cpu_count()

@pytest.mark.integration
def test_acquire_node_id():

    engine = Engine()

    # when an Engine starts up it should acquire a node_id for g(G_SAQ_NODE)
    assert g_int(G_SAQ_NODE_ID)
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name, location, company_id, is_primary, any_mode
                        FROM nodes WHERE id = %s""", (g_int(G_SAQ_NODE_ID),))
        row = cursor.fetchone()
        assert row
        _name, _location, _company_id, _is_primary, _any_mode = row
        assert _name == g(G_SAQ_NODE)
        assert _location == g(G_API_PREFIX)
        assert _company_id == g_int(G_COMPANY_ID)

@pytest.mark.integration
def test_analysis_modes():

    engine = Engine()

    assert "test_empty" not in engine.configuration_manager.analysis_mode_mapping

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_empty')
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', 'test_empty')
    engine.configuration_manager.enable_module('analysis_module_test_engine_locking', 'test_empty')
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis', 'test_empty')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis', 'test_empty')
    engine.configuration_manager.load_modules()

    # analysis mode test_single should have 1 module
    assert len(engine.configuration_manager.analysis_mode_mapping['test_single']) == 1
    assert engine.configuration_manager.analysis_mode_mapping['test_single'][0].config_section_name == 'analysis_module_basic_test'

    # analysis mode test_groups should have 5 modules
    assert len(engine.configuration_manager.analysis_mode_mapping['test_groups']) == 5

    # analysis mode test_disabled should have 4 modules (minus basic_test)
    assert len(engine.configuration_manager.analysis_mode_mapping['test_disabled']) == 4
    assert 'analysis_module_basic_test' not in [m.config_section_name for m in engine.configuration_manager.analysis_mode_mapping['test_disabled']]

@pytest.mark.integration
def test_single_process_analysis(root_analysis: RootAnalysis):

    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    root_analysis.analysis_mode = 'test_single'
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(analysis_priority_mode='test_single', execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

@pytest.mark.system
def test_multi_process_analysis(root_analysis: RootAnalysis):

    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    root_analysis.analysis_mode = 'test_single'
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_shot()

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

@pytest.mark.integration
def test_missing_analysis_mode(root_analysis: RootAnalysis):

    root_analysis.analysis_mode = None
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # the analysis mode should default to test_single
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

@pytest.mark.integration
def test_analysis_queues(root_analysis: RootAnalysis):
    root_analysis.analysis_mode = 'test_queues'
    root_analysis.queue = 'test'
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_valid_queues_test')
    engine.configuration_manager.enable_module('analysis_module_invalid_queues_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    assert observable

    # make sure modules with no valid_queues or invlaid_queues run on all queues
    # XXX was this always a mistake?
    #analysis = observable.get_and_load_analysis('BasicTestAnalysis')
    #assert analysis

    # make sure modules with valid_queues run
    analysis = observable.get_and_load_analysis('ValidQueueAnalysis')
    assert analysis

    # make sure modules with invalid queues do not run
    analysis = observable.get_and_load_analysis('InvalidQueueAnalysis')
    assert analysis is None

@pytest.mark.integration
def test_invalid_analysis_mode(root_analysis: RootAnalysis):

    # an invalid analysis mode happens when you submit an analysis to an engine
    # that supports any analysis mode but doesn't have any configuration settings
    # for the one that was submitted
    # in that case we use the default_analysis_mode

    # we're setting the analysis mode to an invalid value
    root_analysis.analysis_mode = "foobar"
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=[], default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # the analysis mode should default to test_empty but we should also get a warning
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis
    assert log_count('invalid analysis mode') > 0

@pytest.mark.system
def test_multi_process_multi_analysis():

    uuids = []

    for _ in range(3):
        root_uuid = str(uuid.uuid4())
        root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_TEST, 'test_1')
        root.analysis_mode = 'test_single'
        root.save()
        root.schedule()
        uuids.append((root.uuid, observable.uuid))

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    for root_uuid, observable_uuid in uuids:
        root = RootAnalysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
        root.load()
        observable = root.get_observable(observable_uuid)
        assert observable
        from saq.modules.test import BasicTestAnalysis
        analysis = observable.get_and_load_analysis(BasicTestAnalysis)
        assert analysis

@pytest.mark.integration
def test_no_enabled_modules():

    # by default the analysis modules specified for the unit tests are disabled (globally)
    # so just starting up an engine should load no modules at all
    # even though there are modules enabled for the "test_groups" analysis mode
    engine = Engine(config=EngineConfiguration(analysis_pools={'test_groups': 1}))
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    assert len(engine.configuration_manager.analysis_modules) == 0

@pytest.mark.integration
def test_locally_enabled_modules():
    
    # if we enable modules locally then ONLY those should get loaded
    # first we change the config to globally enable all modules
    for section in get_config().keys():
        if not section.startswith('analysis_module_'):
            continue

        get_config()[section]['enabled'] = 'yes'

    engine = Engine(config=EngineConfiguration(analysis_pools={'test_groups': 1}))
    # this is the only module that should get loaded
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    # even though 5 are specified and globally enabled, only 1 is loaded
    assert len(engine.configuration_manager.analysis_modules) == 1
    assert engine.configuration_manager.analysis_modules[0].module_id == "basic_test"

@pytest.mark.integration
def test_no_analysis(root_analysis: RootAnalysis):

    # this test should return False instead of an Analysis
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_2')
    root_analysis.analysis_mode = 'test_single'
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)

    # so this should come back as False
    assert isinstance(observable.get_and_load_analysis(BasicTestAnalysis), bool)
    assert not observable.get_and_load_analysis(BasicTestAnalysis)

@pytest.mark.integration
def test_configurable_module(root_analysis: RootAnalysis):

    # some settings of an AnalysisModule can be specified in the configuration file
    # we should have the following configuration settings for this module
    #
    # [analysis_module_configurable_module_test]
    # module = saq.modules.test
    # class = ConfigurableModuleTestAnalyzer
    # enabled = no
    # 
    # valid_observable_types = ipv4,test
    # required_directives = archive
    #

    # wrong type, correct directive and tag
    user_observable = root_analysis.add_observable_by_spec(F_USER, 'username')
    assert user_observable
    user_observable.add_directive(DIRECTIVE_ARCHIVE)
    user_observable.add_tag('test')

    # right type, no directive or tag
    test_observable = root_analysis.add_observable_by_spec(F_TEST, 'test1')

    # right type with directive, no tag
    test_observable_with_directive = root_analysis.add_observable_by_spec(F_TEST, 'test2')
    assert test_observable_with_directive
    test_observable_with_directive.add_directive(DIRECTIVE_ARCHIVE)

    # right type, directive and tag
    test_observable_with_tag = root_analysis.add_observable_by_spec(F_TEST, 'test_with_tag')
    assert test_observable_with_tag
    test_observable_with_tag.add_directive(DIRECTIVE_ARCHIVE)
    test_observable_with_tag.add_tag('test')

    root_analysis.analysis_mode = 'test_single'
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_configurable_module_test', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    user_observable = root_analysis.get_observable(user_observable.uuid)
    assert user_observable
    analysis = user_observable.get_and_load_analysis(ConfigurableModuleTestAnalysis)

    # this should be empty since this module does not analyze user
    assert analysis is None

    test_observable = root_analysis.get_observable(test_observable.uuid)
    assert test_observable
    analysis = test_observable.get_and_load_analysis(ConfigurableModuleTestAnalysis)

    # this should also be empty since this module requires the directive
    assert analysis is None

    test_observable_with_directive = root_analysis.get_observable(test_observable_with_directive.uuid)
    assert test_observable_with_directive
    analysis = test_observable_with_directive.get_and_load_analysis(ConfigurableModuleTestAnalysis)

    # this should NOT have analysis since it is missing the tag requirement
    assert analysis is None

    test_observable_with_tag = root_analysis.get_observable(test_observable_with_tag.uuid)
    assert test_observable_with_tag
    analysis = test_observable_with_tag.get_and_load_analysis(ConfigurableModuleTestAnalysis)

    # this should have analysis since it meets all the requirements in the configuration settings
    assert analysis

@pytest.mark.integration
def test_time_range_grouped_analysis(root_analysis):

    observable_1 = root_analysis.add_observable_by_spec(F_TEST, 'test_1', parse_event_time('2019-04-16 12:00:00'))
    observable_2 = root_analysis.add_observable_by_spec(F_TEST, 'test_1', parse_event_time('2019-04-16 12:10:00'))
    observable_3 = root_analysis.add_observable_by_spec(F_TEST, 'test_1', parse_event_time('2019-04-16 14:00:00'))
    observable_4 = root_analysis.add_observable_by_spec(F_TEST, 'test_1', parse_event_time('2019-04-16 10:00:00'))
    root_analysis.analysis_mode = 'test_groups'
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_grouped_time_range')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable_1 = root_analysis.get_observable(observable_1.uuid)
    observable_2 = root_analysis.get_observable(observable_2.uuid)
    observable_3 = root_analysis.get_observable(observable_3.uuid)
    observable_4 = root_analysis.get_observable(observable_4.uuid)

    # observations 3 and 4 should have analysis
    assert bool(observable_3.get_and_load_analysis(GroupedByTimeRangeAnalysis))
    assert bool(observable_4.get_and_load_analysis(GroupedByTimeRangeAnalysis))

    # either 1 or 2 should have it but not both (logical xor)
    assert bool(observable_1.get_and_load_analysis(GroupedByTimeRangeAnalysis)) ^ bool(observable_2.get_and_load_analysis(GroupedByTimeRangeAnalysis))
    # and one of these should be a grouping target
    assert observable_1.grouping_target or observable_2.grouping_target

    # remember which one was the grouping target
    grouping_target = observable_1 if observable_1.grouping_target else observable_2

    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_grouping_target')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable_1 = root_analysis.get_observable(observable_1.uuid)
    observable_2 = root_analysis.get_observable(observable_2.uuid)
    grouping_target = root_analysis.get_observable(grouping_target.uuid)

    # either 1 or 2 should have it but not both (logical xor)
    assert bool(observable_1.get_and_load_analysis(GroupingTargetAnalysis)) ^ bool(observable_2.get_and_load_analysis(GroupingTargetAnalysis))
    # and the one that was previously marked as the grouping target is the one that should have the analysis
    assert bool(grouping_target.get_and_load_analysis(GroupingTargetAnalysis))

@pytest.mark.integration
def test_no_analysis_no_return(root_analysis):

    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_3')
    root_analysis.analysis_mode = "test_single"
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)

    # so what happens here is even though you return nothing from execute_analysis
    # execute_final_analysis defaults to returning False
    assert observable.get_and_load_analysis(BasicTestAnalysis) is False

    # you should also get a error log
    assert log_count('should return an AnalysisExecutionResult') == 1

@pytest.mark.integration
def test_delayed_analysis_single(root_analysis):

    observable = root_analysis.add_observable_by_spec(F_TEST, '0:00|0:01')
    root_analysis.analysis_mode = "test_groups"
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert analysis
    assert analysis.load_details()
    assert analysis.initial_request
    assert analysis.delayed_request 
    assert analysis.request_count == 2
    assert analysis.completed

@pytest.mark.integration
def test_delayed_analysis_single_instance(root_analysis):

    # same as previous test test_delayed_analysis_single except this module we're testing is instanced

    observable = root_analysis.add_observable_by_spec(F_TEST, '0:00|0:01')
    root_analysis.analysis_mode = "test_groups"
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis_instance')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis, instance='instance1')
    assert analysis
    assert analysis.load_details()
    assert analysis.initial_request
    assert analysis.delayed_request
    assert analysis.request_count == 2
    assert analysis.completed
    assert analysis.instance == 'instance1'

@pytest.mark.integration
def test_delayed_analysis_multiple():

    uuids = []
    
    for _ in range(3):
        root_uuid = str(uuid.uuid4())
        root = create_root_analysis(uuid=root_uuid, analysis_mode='test_groups', storage_dir=get_storage_dir(root_uuid))
        root.initialize_storage()
        observable = root.add_observable_by_spec(F_TEST, '0:00|0:01')
        root.save()
        root.schedule()
        uuids.append((root.uuid, observable.uuid))

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    for root_uuid, observable_uuid in uuids:
        root = load_root(get_storage_dir(root_uuid))
        analysis = root.get_observable(observable_uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
        assert isinstance(analysis, DelayedAnalysisTestAnalysis)
        assert analysis.load_details()
        assert analysis.initial_request
        assert analysis.delayed_request
        assert analysis.request_count == 2
        assert analysis.completed

@pytest.mark.integration
def test_delayed_analysis_timing():
    root_1 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root_1.initialize_storage()
    o_1 = root_1.add_observable_by_spec(F_TEST, '0:00|0:01')
    root_1.save()
    root_1.schedule()

    root_2 = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root_2.initialize_storage()
    o_2 = root_2.add_observable_by_spec(F_TEST, '0:05|0:10')
    root_2.save()
    root_2.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', "test_groups")
    # o_2 will delay (1 execution)
    # o_1 will delay, pick back up, and then change mode (3 executions)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    
    # the second one should finish before the first one
    root_1 = load_root(get_storage_dir(root_1.uuid))
    analysis_1 = root_1.get_observable(o_1.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert isinstance(analysis_1, DelayedAnalysisTestAnalysis)
    assert analysis_1.load_details()
    assert analysis_1.initial_request
    assert analysis_1.delayed_request
    assert analysis_1.request_count == 2
    assert analysis_1.completed


    root_2 = load_root(get_storage_dir(root_2.uuid))
    analysis_2 = root_2.get_observable(o_2.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert isinstance(analysis_2, DelayedAnalysisTestAnalysis)
    assert analysis_2.load_details()
    assert analysis_2.initial_request
    assert not analysis_2.delayed_request
    assert analysis_2.request_count == 1
    assert not analysis_2.completed
    
    #assert analysis_2.complete_time < analysis_1.complete_time


@pytest.mark.skip(reason="Skipping I/O counts for now.")
@pytest.mark.integration
@track_io
def test_io_count():
    assert _get_io_write_count() == 0
    assert _get_io_read_count() == 0

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save() 
    root.schedule()

    assert _get_io_write_count() == 1
    assert _get_io_read_count() == 0

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # at this point it should have loaded the root analysis
    # and then saved it again along with the details for the BasicTestAnalysis
    # 8/10/2021 - changed from 3 to 5 due to flushing the root during analysis
    # 10/19/2021 - reduced to 4
    assert _get_io_write_count() == 4
    assert _get_io_read_count() == 1

    root = load_root(get_storage_dir(root.uuid))
    root.load()
    assert _get_io_write_count() == 4
    assert _get_io_read_count() == 2
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert _get_io_read_count() == 2 # should not have loaded details yet...
    assert analysis.test_result
    assert _get_io_read_count() == 3

@pytest.mark.skip(reason="Skpping these I/O counts for now.")
@pytest.mark.integration
@track_io
def test_delayed_analysis_io_count():
    assert _get_io_write_count() == 0
    assert _get_io_read_count() == 0

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, '00:00|00:00')
    root.save() 
    root.schedule()

    assert _get_io_write_count() == 1
    assert _get_io_read_count() == 0

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # expect 5 writes at this point
    # (1) initial root analysis save
    # (2) initial module save
    # (3) root analysis completed save
    # (4) updated module save
    # (5) root analysis completed save
    # UPDATE 8/10/2021 - we now expect 9 writes
    # an additional 4 are added because we're flushing the entire RootAnalysis to disk
    # every time execute_analysis returns True
    # UPDATE 10/19/2021 - lowered to 6
    assert _get_io_write_count() == 7
    # and then 4 reads (one LOAD for each, iterated twice)
    assert _get_io_read_count() == 3

    root = load_root(get_storage_dir(root.uuid))
    assert root.load()
    assert _get_io_write_count() == 6
    assert _get_io_read_count() == 4
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    
    assert analysis
    assert _get_io_read_count() == 4 # should not have loaded details yet...
    assert analysis.delayed_request
    assert _get_io_read_count() == 5

@pytest.mark.system
def test_autorefresh():
    get_config()[CONFIG_ENGINE][CONFIG_ENGINE_AUTO_REFRESH_FREQUENCY] = '1'
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    wait_for_log_count('triggered reload of worker modules', 1)
    wait_for_log_count('detected death of process', 1)
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

@pytest.mark.integration
def test_final_analysis():
    """Test final analysis execution."""

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test')
    root.save() 
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should have a single observable now
    root = load_root(get_storage_dir(root.uuid))
    assert len(root.all_observables) == 1
    assert root.has_observable_by_spec(F_TEST, 'test')
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(FinalAnalysisTestAnalysis)
    assert analysis
    # we should have seen this twice since the modification of adding an analysis will triggert
    # final analysis again
    assert log_count('entering final analysis for ') == 2

@pytest.mark.skip(reason="Skipping I/O counts for now.")
@pytest.mark.integration
@track_io
def test_final_analysis_io_count():
    assert _get_io_write_count() == 0
    assert _get_io_read_count() == 0

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test')
    root.save() 
    root.schedule()

    assert _get_io_write_count() == 1
    assert _get_io_read_count() == 0

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # 8/10/2021 -- this used to be 3 but was changed to 6 when we started flushing the root during analysis
    # 10/19/2021 -- reduced to 5
    assert _get_io_write_count() == 5
    assert _get_io_read_count() == 1
    assert log_count('entering final analysis for ') == 2

@pytest.mark.skip(reason="Skipping I/O counts for now.")
@pytest.mark.integration
@track_io
def test_final_analysis_io_count_2():
    """Same thing as before but we test with multiple observables."""
    assert _get_io_write_count() == 0
    assert _get_io_read_count() == 0

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable_1 = root.add_observable_by_spec(F_TEST, 'test_01')
    observable_2 = root.add_observable_by_spec(F_TEST, 'test_02')
    root.save() 
    root.schedule()

    assert _get_io_write_count() == 1
    assert _get_io_read_count() == 0

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # 8/10/2021 - this used to be 4 but now it's 11 due to flushing the root during analysis
    # 10/19/2021 - reduced to 7
    assert _get_io_write_count() == 7
    assert _get_io_read_count() == 1
    assert log_count('entering final analysis for ') == 3

# ensure that post analysis is executed even if delayed analysis times out
@pytest.mark.integration
def test_delayed_analysis_timeout():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    test_observable = root.add_observable_by_spec(F_TEST, '0:00|0:00')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis_timeout', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # wait for delayed analysis to time out
    assert wait_for_log_count('has timed out', 1, 5)

    # post analysis should have executed
    assert wait_for_log_count('execute_post_analysis called', 1, 5)

@pytest.mark.integration
def test_delayed_analysis_recovery():

    # scenario: delayed analysis starts, ace engine stops and then starts back up
    # the delayed analysis should pick back up and complete

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode='test_groups', storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, '0:00|0:05')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    # wait until we see the delay in the queue
    #assert log_count('queue sizes workload 0 delayed 1') == 1

    # we should have one delayed analysis still in the queue
    assert get_db().query(DelayedAnalysis.id).count() == 1
    # and nothing in the workload queue
    assert get_db().query(Workload.id).count() == 0

    # start another engine back up
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert isinstance(analysis, DelayedAnalysisTestAnalysis)
    assert analysis.load_details()
    assert analysis.initial_request
    assert analysis.delayed_request
    assert analysis.request_count == 2
    assert analysis.completed

    # queue should be empty
    get_db().close()
    assert get_db().query(DelayedAnalysis.id).count() == 0
    assert get_db().query(Workload.id).count() == 0

@pytest.mark.integration
def test_wait_for_analysis():

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert test_observable.get_and_load_analysis(WaitAnalysis_B)

    assert log_count("depends on") == 1

@pytest.mark.integration
def test_wait_for_analysis_instance():
    # same as test_wait_for_analysis except we wait for instanced modules

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_7') # <-- test 7
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a_instance', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b_instance', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A, instance='instance1')
    assert test_observable.get_and_load_analysis(WaitAnalysis_B, instance='instance1')

    assert log_count("depends on") == 1

@pytest.mark.integration
def test_wait_for_analysis_instance_multi():

    # same as test_wait_for_analysis_instance except we wait for another instance of the same module

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_8') # <-- test 8
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a_instance', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_a_instance_2', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A, instance='instance1')
    assert test_observable.get_and_load_analysis(WaitAnalysis_A, instance='instance2')

    assert log_count("depends on") == 1

@pytest.mark.integration
def test_wait_for_disabled_analysis():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a_instance', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)

    assert log_count("requested to wait for disabled (or missing) module") == 1

@pytest.mark.integration
def test_wait_for_analysis_circ_dep():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_2')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert not test_observable.get_and_load_analysis(WaitAnalysis_B)

    assert log_count("CIRCULAR DEPENDENCY ERROR") == 1

@pytest.mark.integration
def test_wait_for_analysis_missing_analysis():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_3')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert test_observable.get_and_load_analysis(WaitAnalysis_B)

    # we would only see this log if A waited on B
    #assert log_count("did not generate analysis to resolve dep") == 1

@pytest.mark.integration
def test_wait_for_analysis_circ_dep_chained():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_4')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_c', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert not test_observable.get_and_load_analysis(WaitAnalysis_B)
    assert not test_observable.get_and_load_analysis(WaitAnalysis_C)

    assert log_count("CIRCULAR DEPENDENCY ERROR") == 1

@pytest.mark.integration
def test_wait_for_analysis_chained():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_5')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_c', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert test_observable.get_and_load_analysis(WaitAnalysis_B)
    assert test_observable.get_and_load_analysis(WaitAnalysis_C)

    assert log_count("CIRCULAR DEPENDENCY ERROR") == 0

@pytest.mark.integration
def test_wait_for_analysis_target_delayed():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_6')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)
    analysis = test_observable.get_and_load_analysis(WaitAnalysis_B)
    assert isinstance(analysis, WaitAnalysis_B)
    assert analysis.delayed

@pytest.mark.integration
def test_wait_for_analysis_source_delayed():
    # XXX not sure what this is actually testing for
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_wait_for_analysis_source_delayed')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert test_observable.get_and_load_analysis(WaitAnalysis_B)

@pytest.mark.integration
def test_wait_for_analysis_source_and_target_delayed():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_wait_for_analysis_source_and_target_delayed')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    # A is waiting for B which is delayed
    assert not test_observable.get_and_load_analysis(WaitAnalysis_A)
    analysis = test_observable.get_and_load_analysis(WaitAnalysis_B)
    assert isinstance(analysis, WaitAnalysis_B)
    assert analysis.delayed

@pytest.mark.integration
def test_wait_for_analysis_rejected():
    
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_engine_032a')
    test_observable.exclude_analysis(WaitAnalyzerModule_B)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_wait_a', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_b', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_test_wait_c', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert test_observable.get_and_load_analysis(WaitAnalysis_A)
    assert not test_observable.get_and_load_analysis(WaitAnalysis_B)
    assert test_observable.get_and_load_analysis(WaitAnalysis_C)

@pytest.mark.integration
def test_post_analysis_after_false_return():
    # the execute_post_analysis function should be called regardless of what happened during analysis
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable

    assert not test_observable.get_and_load_analysis(PostAnalysisTestResult)
    assert log_count('execute_post_analysis called') == 1

@pytest.mark.integration
def test_maximum_cumulative_analysis_warning_time():
    # setting this to zero should cause it to happen right away
    get_config()[CONFIG_GLOBAL][CONFIG_GLOBAL_MAXIMUM_CUMULATIVE_ANALYSIS_WARNING_TIME] = '0'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    assert log_count('ACE has been analyzing') == 1

@pytest.mark.integration
def test_maximum_cumulative_analysis_warning_time_analysis_mode():
    # same thing as before except we set the timeout for just the analysis mode
    # setting this to zero should cause it to happen right away
    get_config()['analysis_mode_test_groups']['maximum_cumulative_analysis_warning_time'] = '0'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    assert log_count('ACE has been analyzing') == 1

@pytest.mark.integration
def test_maximum_cumulative_analysis_fail_time():
    # setting this to zero should cause it to happen right away
    get_config()['global']['maximum_cumulative_analysis_fail_time'] = '0'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count('ACE took too long to analyze') == 2

    # Even when the analysis times out, we still want to fire off execute_post_analysis()
    assert log_count('executing post analysis routines') == 1

@pytest.mark.integration
def test_maximum_cumulative_analysis_fail_time_ignore():
    # setting this to zero should cause it to happen right away
    get_config()['global']['maximum_cumulative_analysis_fail_time'] = '0'

    # setting this should cause this analysis mode to ignore the cumulative fail time
    get_config()['service_engine']['analysis_modes_ignore_cumulative_timeout'] = 'test_groups'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count('ACE took too long to analyze') == 0
    assert log_count('ACE is ignoring cumulative timeout') >= 1

    # Even when the analysis times out, we still want to fire off execute_post_analysis()
    assert log_count('executing post analysis routines') == 1

@pytest.mark.integration
def test_maximum_cumulative_analysis_fail_time_analysis_mode():
    # same thing as before except we set the timeout for just the analysis mode
    # setting this to zero should cause it to happen right away
    get_config()['analysis_mode_test_groups']['maximum_cumulative_analysis_fail_time'] = '0'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count('ACE took too long to analyze') == 2

    # Even when the analysis times out, we still want to fire off execute_post_analysis()
    assert log_count('executing post analysis routines') == 1

@pytest.mark.integration
def test_maximum_analysis_time_global():
    # setting this to zero should cause it to happen right away
    get_config()['global']['maximum_analysis_time'] = '0'
    # this needs to be set explicitly because it defaults to the global maximum if not set
    get_config()['analysis_module_basic_test']['maximum_analysis_time'] = '60'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_4')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # 6/10/2025 - reduced to 1 since execute_analysis now returns COMPLETE
    assert log_count('excessive time - analysis module') == 1

    # Even when the analysis times out, we still want to fire off execute_post_analysis()
    assert log_count('executing post analysis routines') == 1

@pytest.mark.integration
def test_maximum_analysis_time_analysis_mode():
    # same thing as before except we set the timeout for just the analysis mode
    # setting this to zero should cause it to happen right away
    get_config()['analysis_mode_test_groups']['maximum_analysis_time'] = '0'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_4')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # 6/10/2025 - reduced to 1 since execute_analysis now returns COMPLETE
    assert log_count('excessive time - analysis module') == 1

    # Even when the analysis times out, we still want to fire off execute_post_analysis()
    assert log_count('executing post analysis routines') == 1

@pytest.mark.integration
def test_is_module_enabled():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_dependency_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    
    from saq.modules.test import DependencyTestAnalysis, KEY_SUCCESS, KEY_FAIL
    analysis = test_observable.get_and_load_analysis(DependencyTestAnalysis)
    assert isinstance(analysis, DependencyTestAnalysis)
    assert analysis.load_details()
    for key in analysis.details[KEY_SUCCESS].keys():
        assert analysis.details[KEY_SUCCESS][key]
    for key in analysis.details[KEY_FAIL].keys():
        assert not analysis.details[KEY_FAIL][key]

@pytest.mark.integration
def test_analysis_mode_priority():

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()
    test_1_uuid = root.uuid

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_2')
    root.save()
    root.schedule()
    test_2_uuid = root.uuid

    engine = Engine(config=EngineConfiguration(analysis_mode_priority="test_groups"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    # we should see test_2_uuid get selected BEFORE test_1_uuid gets selected
    results = [_.getMessage() for _ in search_log('got work item')]
    assert len(results) == 1
    assert results.index('got work item RootAnalysis({})'.format(test_2_uuid)) == 0

@pytest.mark.skip(reason="This test is flaky and needs to be rewritten")
@pytest.mark.integration
def test_analysis_mode_no_priority():

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()
    test_1_uuid = root.uuid

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_2')
    root.save()
    root.schedule()
    test_2_uuid = root.uuid

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # since we don't have any kind of priority set they should get selected in order they were inserted (FIFO)
    # so we should see test_1_uuid get selected BEFORE test_2_uuid gets selected
    results = [_.getMessage() for _ in search_log('got work item')]
    assert len(results) == 1
    assert results.index('got work item RootAnalysis({})'.format(test_1_uuid)) == 0

@pytest.mark.integration
def test_error_reporting():
    # trigger the failure this way
    get_config()['global']['maximum_cumulative_analysis_fail_time'] = '0'

    # remember what was already in the error reporting directory
    def _enum_error_reporting():
        return set(os.listdir(os.path.join(get_data_dir(), 'error_reports')))

    existing_reports = _enum_error_reporting()

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_3')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(copy_analysis_on_error=True))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # look at what is in the error reporting directory now
    # exclude what we found before to find the new stuff
    new_reports = _enum_error_reporting() - existing_reports

    # we should have a single error report
    assert len(new_reports) == 1

    # one should be a file
    file_path = None
    for _file in new_reports:
        path = os.path.join(os.path.join(get_data_dir(), 'error_reports', _file))
        if os.path.isfile(path):
            file_path = path

    assert file_path

@pytest.mark.integration
def test_file_error_reporting():
    get_config()[CONFIG_ENGINE][CONFIG_ENGINE_COPY_FILE_ON_ERROR] = 'yes'

    # remember what was already in the error reporting directory
    def _enum_error_reporting():
        return set(os.listdir(os.path.join(get_data_dir(), 'error_reports')))

    assert len(_enum_error_reporting()) == 0

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    target_path = root.create_file_path('test.txt')
    with open(target_path, 'w') as fp:
        fp.write('Hello, world!')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should have a single error report and a single storage directory in the error reporting directory
    error_reports = _enum_error_reporting()
    assert len(error_reports) == 2

    # one should be a file and the other a directory
    file_path = None
    dir_path = None
    for _file in error_reports:
        path = os.path.join(os.path.join(get_data_dir(), 'error_reports', _file))
        if os.path.isfile(path):
            file_path = path
        if os.path.isdir(path):
            dir_path = path

    assert file_path
    assert dir_path

    # check that everything we expect to exist in the dir exists
    with open(os.path.join(dir_path, 'test.txt'), 'r') as fp:
        assert fp.read() == 'Hello, world!'

@pytest.mark.integration
def test_stats():
    # clear engine statistics
    if os.path.exists(os.path.join(g(G_MODULE_STATS_DIR), 'ace')):
        shutil.rmtree(os.path.join(g(G_MODULE_STATS_DIR), 'ace'))

    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # there should be one subdir in the engine's stats dir
    assert len(os.listdir(os.path.join(g(G_MODULE_STATS_DIR), 'ace'))) == 1
    subdir = os.listdir(os.path.join(g(G_MODULE_STATS_DIR), 'ace'))
    subdir = subdir[0]

    # this should have a single stats file in it
    stats_files = os.listdir(os.path.join(os.path.join(g(G_MODULE_STATS_DIR), 'ace', subdir)))
    assert len(stats_files) == 1

    # and it should not be empty
    assert os.path.getsize(os.path.join(os.path.join(g(G_MODULE_STATS_DIR), 'ace', subdir, stats_files[0]))) > 0

@pytest.mark.integration
def test_exclusion():

    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_6')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis
    # we should have two that were both excluded in different ways
    assert len(analysis.observables) == 2
    for new_observable in analysis.observables:
        new_observable = analysis.observables[0]
        new_analysis = new_observable.get_and_load_analysis(BasicTestAnalysis)
        assert not new_analysis

@pytest.mark.integration
def test_limited_analysis():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    observable.limit_analysis('basic_test')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_engine_locking')
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable

    # there should only be one analysis performed
    assert len(observable.all_analysis) == 1
    
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

    assert len(search_log('analysis for test(test_1) limited to 1 modules (basic_test)')) > 0

@pytest.mark.integration
def test_limited_analysis_invalid():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    observable.limit_analysis('basic_tast') # mispelled test
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_engine_locking')
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable

    # there should be no analysis
    assert len(observable.all_analysis) == 0
    
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis is None

    assert len(search_log('specified unknown limited analysis')) > 0

@pytest.mark.integration
def test_cleanup_alt_workdir():
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode='test_cleanup', storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    root.save()
    root.schedule()

    engine = Engine()
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert not os.path.isdir(workload_storage_dir(root.uuid))

@pytest.mark.integration
def test_no_cleanup():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_empty')
    root.initialize_storage()
    root.save()
    root.schedule()

    engine = Engine()
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert os.path.isdir(root.storage_dir)

@pytest.mark.integration
def test_cleanup_with_delayed_analysis():
    # we are set to cleanup, however, we don't because we have delayed analysis
    get_config()['analysis_mode_test_groups']['cleanup'] = 'yes'
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, '00:00|00:01')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_delayed_analysis', "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert not os.path.isdir(root.storage_dir)
    assert log_count('not cleaning up RootAnalysis({}) (found outstanding work)'.format(root.uuid)) == 1

@pytest.mark.integration
def test_local_analysis_mode_single():

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_groups']))
    engine.configuration_manager.enable_module('analysis_module_basic_test', "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

@pytest.mark.integration
def test_excluded_analysis_mode():

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=[], excluded_analysis_modes=['test_groups']))

    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis is None

@pytest.mark.integration
def test_local_analysis_mode_missing_default():

    # when we specify a default analysis mode that is not in the locally supported modes of the engine
    # it should automatically get added to the list of locally supported modes

    # we specify test_single as the supported local analysis mode, but the default is test_empty
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.analysis_mode = 'test_single'
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_empty'], default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

    # both test_empty and test_single should be in this list
    assert len(engine.config.local_analysis_modes) == 2
    assert 'test_single' in engine.config.local_analysis_modes
    assert 'test_empty' in engine.config.local_analysis_modes

@pytest.mark.integration
def test_local_analysis_mode_missing_pool():

    # test_empty is specified as the only supported mode
    # but we specify a pool for test_single
    # this is a configuration error
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_empty'], default_analysis_mode="test_empty", analysis_pools={'test_single': 1}))

    assert log_count('attempted to add analysis pool for mode test_single which is not supported by this engine') ==  1

@pytest.mark.integration
def test_local_analysis_mode_not_local():

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    # but we target test_single for this analysis
    root.analysis_mode = 'test_single'
    root.save()
    root.schedule()

    # we say we only support test_empty analysis modes
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_empty'], default_analysis_mode="test_empty"))
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_empty')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # this should exit out since the workload entry is for test_single analysis mode
    # but we don't support that with this engine so it shouldn't see it
    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert isinstance(observable, Observable)
    # should not have any analysis
    assert not observable.analysis

@pytest.mark.integration
def test_target_nodes():

    # only pull work from the local node
    get_config()['service_engine']['target_nodes'] = 'LOCAL'

    # initialize this node
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # schedule work on the current node
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    existing_node = g(G_SAQ_NODE)
    existing_node_id = g_int(G_SAQ_NODE_ID)

    # now start another engine on a different "node"
    get_config()['global']['node'] = 'second_host'
    reset_node('second_host')
    set_g(G_SAQ_NODE_ID, None)

    assert not g(G_SAQ_NODE) == existing_node
    assert not g_int(G_SAQ_NODE_ID) == existing_node_id

    engine = Engine()
    assert engine.node_manager.target_nodes == [g(G_SAQ_NODE)]
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should still have that workload in the database
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM workload")
        assert cursor.fetchone()[0] == 1

    # change our node back
    get_config()['global']['node'] = existing_node
    reset_node(existing_node)
    set_g(G_SAQ_NODE_ID, None)

    # run again -- we should pick it up this time
    engine = Engine()
    assert engine.node_manager.target_nodes == [g(G_SAQ_NODE)]
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # workload should be clear
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM workload")
        assert cursor.fetchone()[0] == 0

@pytest.mark.skip(reason="come back to this")
@pytest.mark.integration
def test_local_analysis_mode_remote_pickup(mock_api_call, monkeypatch):

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    # but we target test_single for this analysis
    root.analysis_mode = 'test_single'
    root.save()
    root.schedule()

    # remember the old storage dir
    old_storage_dir = root.storage_dir

    # we say we only support test_empty analysis modes
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_empty'], analysis_pools={'test_empty': 1}, default_analysis_mode="test_empty"))

    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # make sure our stuff is still there
    assert os.path.exists(old_storage_dir)

    # now start another engine on a different "node"
    get_config()['global']['node'] = 'second_host'
    reset_node('second_host')
    get_config()['analysis_mode_test_single']['cleanup'] = 'no'

    # we trick the api server into using the old storage dir
    import aceapi.engine
    def mock_storage_dir_from_uuid(uuid):
        return old_storage_dir

    monkeypatch.setattr(aceapi.engine, "storage_dir_from_uuid", mock_storage_dir_from_uuid)

    engine = Engine(config=EngineConfiguration(local_analysis_modes=["test_single"], analysis_pools={"test_single": 1}, default_analysis_mode="test_single"))

    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # look for the log to move the work target
    assert log_count('downloading work target {} from '.format(root.uuid)) == 1
    assert log_count('completed analysis RootAnalysis({})'.format(root.uuid)) ==  1

    # now the old storage directory should be gone
    assert not os.path.exists(old_storage_dir)

    # but there should be a new one in the new "node"
    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

@pytest.mark.integration
def test_local_analysis_mode_remote_pickup_invalid_company_id(mock_api_call):

    # TestCase - we've got nothing to do locally but there is work
    # on a remote server, but that work is assigned to a different company
    # we do NOT grab that work

    # first we add a new company
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO company ( name ) VALUES ( 'unittest' )")
        db.commit()

        # get the new company_id
        cursor.execute("SELECT id FROM company WHERE name = 'unittest'")
        row = cursor.fetchone()
        assert row
        other_company_id = row[0]

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    # but we target test_single for this analysis
    root.analysis_mode = 'test_single'
    root.company_id = other_company_id
    root.save()
    root.schedule()

    # remember the old storage dir
    old_storage_dir = root.storage_dir

    # we say we only support test_empty analysis modes
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_empty'], analysis_pools={'test_empty': 1}, default_analysis_mode="test_empty"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # make sure our stuff is still there
    assert os.path.exists(old_storage_dir)

    # now start another engine on a different "node"
    get_config()['global']['node'] = 'second_host'
    reset_node('second_host')
    get_config()['analysis_mode_test_single']['cleanup'] = 'no'

    # and this node handles the test_single mode
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_single'], analysis_pools={'test_single': 1}, default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # make sure our stuff is still there
    assert os.path.exists(old_storage_dir)

@pytest.mark.integration
def test_status_update():
    
    # start an empty engine and wait for the node update
    engine = Engine()
    engine.node_manager.update_node_status()

    assert log_count('updated node') == 1
    
    # do we have an entry in the nodes database table?
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name, location, company_id, last_update FROM nodes WHERE id = %s", (g_int(G_SAQ_NODE_ID),))
        row = cursor.fetchone()
        assert row
        assert row[0] == g(G_SAQ_NODE)
        assert row[1] == g(G_API_PREFIX)
        assert row[2] == g_int(G_COMPANY_ID)

@pytest.mark.integration
def test_node_modes_update():

    # when an Engine starts up it updates the node_modes database with the list of analysis modes it locally supports
    # configure to support two modes
    engine = Engine(config=EngineConfiguration(local_analysis_modes=["test_empty", "test_single"], default_analysis_mode="test_empty"))

    # we should have two entries in the node_modes database for the current node_id
    assert set(get_node_included_analysis_modes()) == set(["test_empty", "test_single"])
    assert not node_supports_any_analysis_mode()

    # then we do the same check for an engine with analysis mode exclusion configured
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[], excluded_analysis_modes=["test_empty"]))

    # we should have NO entries in the node_modes database for the current node_id
    assert not get_node_included_analysis_modes()
    assert node_supports_any_analysis_mode()
    assert get_node_excluded_analysis_modes() == ["test_empty"]

@pytest.mark.integration
def test_node_modes_update_any():

    # when local_analysis_modes is empty, it assumes you want ALL analysis modes
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[]))

    assert not get_node_included_analysis_modes()
    assert node_supports_any_analysis_mode()

@pytest.mark.integration
def test_primary_node():

    # test having a node become the primary node
    get_config()['service_engine']['node_status_update_frequency'] = '0'
    engine = Engine()
    engine.node_manager.execute_primary_node_routines()
    
    assert log_count('this node {} has become the primary node'.format(g(G_SAQ_NODE))) == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (g_int(G_SAQ_NODE_ID),))
        assert cursor.fetchone()

@pytest.mark.integration
def test_primary_node_contest():
    # test having a node become the primary node
    # and then another node NOT becoming a primary node because there already is one
    get_config()['service_engine']['node_status_update_frequency'] = '0'
    engine = Engine()
    engine.node_manager.execute_primary_node_routines()
    
    assert log_count('this node {} has become the primary node'.format(g(G_SAQ_NODE))) == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (g_int(G_SAQ_NODE_ID),))
        assert cursor.fetchone()

    reset_node('another_node')
    engine = Engine()
    engine.node_manager.execute_primary_node_routines()

    assert log_count('node {} is not primary'.format(g(G_SAQ_NODE))) == 1

@pytest.mark.integration
def test_primary_node_contest_winning():
    # test having a node become the primary node
    # after another node times out
    get_config()['service_engine']['node_status_update_frequency'] = '0'
    engine = Engine()
    engine.node_manager.execute_primary_node_routines()
    
    assert log_count('this node {} has become the primary node'.format(g(G_SAQ_NODE))) == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT name FROM nodes WHERE id = %s AND is_primary = 1", (g_int(G_SAQ_NODE_ID),))
        assert cursor.fetchone()

    # update the node to make it look like it last updated a while ago
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE nodes SET last_update = ADDTIME(last_update, '-1:00:00') WHERE id = %s", (g_int(G_SAQ_NODE_ID),))
        db.commit()

    reset_node('another_node')

    engine = Engine()
    engine.node_manager.execute_primary_node_routines()

    assert log_count('this node {} has become the primary node'.format(g(G_SAQ_NODE))) == 1

@pytest.mark.integration
def test_primary_node_clear_locks(monkeypatch):
    target = str(uuid.uuid4())
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(target, lock_uuid)
    monkeypatch.setattr(g_obj(G_LOCK_TIMEOUT_SECONDS), "value", 0)
    # test having a node become the primary node
    # and then clearing out an expired lock
    engine = Engine()
    engine.node_manager.execute_primary_node_routines()
    
    assert log_count('this node {} has become the primary node'.format(g(G_SAQ_NODE))) == 1
    assert log_count('removed 1 expired locks') == 1

    # make sure the lock is gone
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s", (target,))
        assert cursor.fetchone() is None

@pytest.mark.system
def test_engine_worker_recovery():
    
    # make sure the engine detects dead workers and replaces them
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_worker_death')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine_process = engine.start_nonblocking()
    assert engine_process.pid
    engine.wait_for_start()
    # we should see it die
    wait_for_log_count('detected death of', 1, 5)
    # and then we should have seen two workers start
    wait_for_log_count('started worker', 2, 5)
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

@pytest.mark.system
def test_failed_analysis_module():
    
    # make sure that when an analysis module causes the entire analysis process to crash
    # ACE deals with the situation and recovers
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_worker_death')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    # basic test should run before low_priority does
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine_process = engine.start_nonblocking()
    assert engine_process.pid
    engine.wait_for_start()
    # we should see it die
    wait_for_log_count('detected death of', 1, 5)
    # and then we should have seen two workers start
    wait_for_log_count('started worker', 2, 5)
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()
    observable = root.get_observable(observable.uuid)
    assert observable

    # we should have recorded a failed analysis
    from saq.modules.test import BasicTestAnalysis
    assert root.is_analysis_failed(BasicTestAnalysis, observable)

    # the low priority analysis module should have still executed
    from saq.modules.test import LowPriorityAnalysis
    analysis = observable.get_and_load_analysis(LowPriorityAnalysis)
    assert analysis

@pytest.mark.system
def test_analysis_module_timeout():

    # deal with analysis modules that never return from their execute_analyis() call

    get_config()['analysis_module_basic_test']['maximum_analysis_time'] = '0'

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_worker_timeout')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    # basic test should run before low_priority does
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine_process = engine.start_nonblocking()
    assert engine_process.pid
    engine.wait_for_start()
    # we should see it die
    wait_for_log_count('detected death of', 1, 5)
    # and then we should have seen two workers start
    wait_for_log_count('started worker', 2, 5)
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()
    observable = root.get_observable(observable.uuid)
    assert observable

    # we should have recorded a failed analysis
    from saq.modules.test import BasicTestAnalysis
    analysis = observable.get_and_load_analysis(BasicTestAnalysis)
    assert analysis is None
    assert root.is_analysis_failed(BasicTestAnalysis, observable)

    # the low priority analysis module should have still executed
    from saq.modules.test import LowPriorityAnalysis
    analysis = observable.get_and_load_analysis(LowPriorityAnalysis)
    assert analysis

@pytest.mark.system
def test_copy_terminated_analysis_cause():

    # when an analysis module times out that is analyzing a file
    # we make a copy of that file

    get_config()['analysis_module_basic_test']['maximum_analysis_time'] = '0'
    get_config()['service_engine']['copy_terminated_analysis_causes'] = 'yes'

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    target_path = root.create_file_path('test_worker_timeout')
    with open(target_path, 'w') as fp:
        fp.write('Hello, world!')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    # we should see it die
    wait_for_log_count('detected death of', 1, 5)
    # and then we should have seen two workers start
    wait_for_log_count('started worker', 2, 5)
    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()
    observable = root.get_observable(observable.uuid)
    assert observable

    # we should have copied the file now
    failed_analysis_dir = os.path.join(get_data_dir(), 'review', 'failed_analysis', 
            datetime.now().strftime('%Y'), 
            datetime.now().strftime('%m'), 
            datetime.now().strftime('%d'),
            root.uuid)

    assert os.path.isdir(failed_analysis_dir)
    
    # there should be a details file that uses the observable uuid in the file name
    assert len(glob(f'{failed_analysis_dir}/details-*')) == 1

    # and we should have a copy of the file
    target_path = os.path.join(failed_analysis_dir, 'test_worker_timeout')
    with open(target_path, 'r') as fp:
        assert fp.read() == 'Hello, world!'

@pytest.mark.system
def test_analysis_module_timeout_root_flushed():

    # this test ensures that analysis is flushed as it goes along
    # so that if an analysis module causes the worker process to die
    # we don't lose the work we've already done so far

    get_config()['analysis_module_generate_file']['priority'] = '0'
    get_config()['analysis_module_basic_test']['priority'] = '10'
    get_config()['analysis_module_basic_test']['maximum_analysis_time'] = '0'

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_generate_file')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    # basic test should run before low_priority does
    engine.configuration_manager.enable_module('analysis_module_generate_file')
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()
    # we should see it die
    wait_for_log_count('detected death of', 1, 5)
    # and then we should have seen two workers start
    wait_for_log_count('started worker', 2, 5)
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()
    observable = root.get_observable(observable.uuid)
    assert observable

    # we should only see this message once
    assert log_count("analysis GenerateFileAnalysis is completed") == 1

@pytest.mark.integration
def test_local_mode():

    engine = Engine(config=EngineConfiguration(engine_type=EngineType.LOCAL))
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.initialize_single_threaded_worker(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "test_1")
    root.save()

    assert engine.single_threaded_worker is not None
    engine.single_threaded_worker.workload_manager.add_workload(root)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    assert isinstance(observable.get_and_load_analysis(BasicTestAnalysis), BasicTestAnalysis)

@pytest.mark.integration
def test_clear_outstanding_locks():
    
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, 'test_never_return')
    root.save()
    root.schedule()

    engine = Engine()

    # create an arbitrary lock
    assert acquire_lock(str(uuid.uuid4()), str(uuid.uuid4()), f'{g(G_SAQ_NODE)}-unittest-12345')
    assert acquire_lock(str(uuid.uuid4()), str(uuid.uuid4()), 'some_other_node.local-unittest-12345')
    
    # should have two locks now
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM locks")
        assert cursor.fetchone()[0] == 2
        db.commit()

    # initialize the engine again
    engine = Engine()

    # should see a logging message about locks being deleted
    assert log_count('clearing 1 locks from previous execution') == 1

    with get_db_connection() as db:
        cursor = db.cursor()
        # we should have one lock left, belong to the "other node"
        cursor.execute("SELECT lock_owner FROM locks")
        assert cursor.fetchone()[0] == 'some_other_node.local-unittest-12345'

@pytest.mark.integration
def test_action_counters():
    
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test_action_counter_1')
    t2 = root.add_observable_by_spec(F_TEST, 'test_action_counter_2')
    t3 = root.add_observable_by_spec(F_TEST, 'test_action_counter_3')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we have an action count limit of 2, so 2 of these should have analysis and 1 should not
    root = load_root(get_storage_dir(root.uuid))

    t1 = root.get_observable(t1.uuid)
    t2 = root.get_observable(t2.uuid)
    t3 = root.get_observable(t3.uuid)

    assert t1
    assert t2
    assert t3

    analysis_count = 0
    for _ in [ t1, t2, t3 ]:
        if _.get_and_load_analysis(BasicTestAnalysis):
            analysis_count += 1

    assert analysis_count == 2

@pytest.mark.integration
def test_module_priority():
    
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_high_priority')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should see the high priority execute before the low priority
    hp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(HighPriorityAnalyzer)')
    assert len(hp_log_entry) == 1
    hp_log_entry = hp_log_entry[0]

    lp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(LowPriorityAnalyzer)')
    assert len(lp_log_entry) == 1
    lp_log_entry = lp_log_entry[0]
    
    assert hp_log_entry.created < lp_log_entry.created

    # swap the priorities
    get_config()['analysis_module_high_priority']['priority'] = '1'
    get_config()['analysis_module_low_priority']['priority'] = '0'

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_high_priority')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should see the high priority execute before the low priority
    hp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(HighPriorityAnalyzer)')
    assert len(hp_log_entry) == 2
    hp_log_entry = hp_log_entry[1]

    lp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(LowPriorityAnalyzer)')
    assert len(lp_log_entry) == 2
    lp_log_entry = lp_log_entry[1]
    
    assert lp_log_entry.created < hp_log_entry.created

    # test a high priority analysis against an analysis without a priority
    get_config()['analysis_module_high_priority']['priority'] = '0'
    del get_config()['analysis_module_low_priority']['priority']

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()

    get_config()['analysis_module_high_priority']['priority'] = '-1'
    get_config()['analysis_module_low_priority']['priority'] = '1'
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_high_priority')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine.configuration_manager.enable_module('analysis_module_no_priority')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should see the high priority execute before the low priority
    hp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(HighPriorityAnalyzer)')
    assert len(hp_log_entry) == 3
    hp_log_entry = hp_log_entry[2]

    lp_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(LowPriorityAnalyzer)')
    assert len(lp_log_entry) == 3
    lp_log_entry = lp_log_entry[2]

    np_log_entry = search_log('analyzing test(test) with AnalysisModuleAdapter(NoPriorityAnalyzer)')
    assert len(np_log_entry) == 1
    np_log_entry = np_log_entry[0]
    
    assert hp_log_entry.created < lp_log_entry.created
    assert lp_log_entry.created < np_log_entry.created

@pytest.mark.integration
def test_post_analysis_multi_mode():
    
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode='test_groups', storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_groups', 'test_single', 'test_empty']))
    engine.configuration_manager.enable_module('analysis_module_post_analysis_multi_mode', ['test_groups', 'test_single', 'test_empty'])
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # at the end of analysis in test_groups mode post_analysis will execute and change the mode to test_single
    # it will happen again and change the mode to test_empty but will return True indicating post analysis has completed

    assert log_count('execute_post_analysis called') == 3
    assert log_count('executing post analysis routines for') == 3

@pytest.mark.integration
def test_post_analysis_delayed_analysis():

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, analysis_mode='test_single', storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test_delayed')
    root.save()
    root.schedule()
    
    engine = Engine(config=EngineConfiguration(local_analysis_modes=["test_single"]))
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count('execute_post_analysis called') == 1
    assert log_count('executing post analysis routines for') == 1

@pytest.mark.integration
def test_alt_workload_move():

    # when an analysis moves into alert (correlation) mode and we are using an alt workload dir
    # then that analysis should move into the saq.DATA_DIR directory
    
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    t1 = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_forced_detection', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # root should have moved
    assert not os.path.exists(workload_storage_dir(root.uuid))
    root = load_root(get_storage_dir(root.uuid))
    assert root

@pytest.mark.integration
def test_analysis_reset():
    
    root = create_root_analysis()
    root.initialize_storage()
    o1 = root.add_observable_by_spec(F_TEST, 'test_add_file')
    o2 = root.add_observable_by_spec(F_TEST, 'test_action_counter')
    root.save()
    root.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')  
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root = load_root(get_storage_dir(root.uuid))
    o1 = root.get_observable(o1.uuid)
    assert o1
    analysis = o1.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

    # this analysis should have two file observables
    file_observables = analysis.find_observables(lambda o: o.type == F_FILE)
    assert len(file_observables) == 2

    # make sure the files are actually there
    for _file in file_observables:
        assert _file.exists

    # we should also have a non-empty state
    assert bool(root.state)

    # and we should have some action counters
    assert bool(root.action_counters)

    # reset the analysis
    root.reset()

    # the original observable should still be there
    o1 = root.get_observable(o1.uuid)
    assert o1
    analysis = o1.get_and_load_analysis(BasicTestAnalysis)
    # but it should NOT have analysis
    assert analysis is None

    # and that should be the only observable
    assert len(root.all_observables) == 2

    # and those two files should not exist anymore
    for _file in file_observables:
        assert not _file.exists

@pytest.mark.unit
def test_analysis_reset_locked():

    from saq.database import acquire_lock, release_lock, LockedException

    root = create_root_analysis()
    root.initialize_storage()
    o1 = root.add_observable_by_spec(F_TEST, 'test_add_file')
    o2 = root.add_observable_by_spec(F_TEST, 'test_action_counter')
    root.save()
    root.schedule()

    # lock the analysis we created
    lock_uuid = str(uuid.uuid4())
    acquire_lock(root.uuid, lock_uuid)

    # now try to reset it
    with pytest.raises(LockedException):
        root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
        root.load()
        root.reset()

    # unlock the analysis we created
    release_lock(root.uuid, lock_uuid)

    # the reset should work this time
    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()
    root.reset()

@pytest.mark.integration
def test_watched_files():

    # make sure we check every time
    get_config()['global']['check_watched_files_frequency'] = '0'

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')  
    engine.configuration_manager.load_modules()

    # the module creates the file we're going to watch, so wait for that to appear
    watched_file_path = os.path.join(g(G_TEMP_DIR), 'watched_file')
    assert os.path.exists(watched_file_path)
    # and then wait for it to start watching it
    assert log_count(f"watching file {watched_file_path}") == 1
    assert log_count(f"detected change to {watched_file_path}") == 1

    # go ahead and modify it
    with open(watched_file_path, 'w') as fp:
        fp.write("data has changed")
    
    root = create_root_analysis()
    root.initialize_storage()
    o1 = root.add_observable_by_spec(F_TEST, 'test_watched_file')
    root.save()
    root.schedule()

    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count(f"detected change to {watched_file_path}") == 2
    assert log_count(f"watched_file_modified: {watched_file_path}") == 2

@pytest.mark.integration
def test_archive():

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_detection')
    file_path = root.create_file_path("test")
    with open(file_path, "w") as fp:
        fp.write("text")

    root_file_observable = root.add_file_observable(file_path)
    test_file_observable = root.add_observable_by_spec(F_TEST, 'test_add_file')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True # XXX kind of a hack?
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(root.uuid)
    assert isinstance(alert, Alert)

    test_observable = alert.root_analysis.get_observable(test_observable.uuid)
    assert test_observable
    basic_analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(basic_analysis, BasicTestAnalysis)
    assert basic_analysis.load_details()
    assert basic_analysis.details

    test_file_observable = alert.root_analysis.get_observable(test_file_observable.uuid)
    assert test_file_observable
    basic_analysis = test_file_observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(basic_analysis, BasicTestAnalysis)
    assert basic_analysis.load_details()
    assert basic_analysis.details
    additional_file_observable = basic_analysis.get_observable_by_type(F_FILE)
    assert additional_file_observable

    alert.archive()
    alert.sync()

    # need to clear the sqlalchemy identity cache
    get_db().close()

    alert = load_alert(str(alert.uuid))
    assert isinstance(alert, Alert)
    assert alert.archived is True
    
    test_observable = alert.root_analysis.get_observable(test_observable.uuid)
    assert test_observable
    basic_analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(basic_analysis, BasicTestAnalysis)
    # the analysis details should be empty
    assert basic_analysis.details == {}
    # but the summary should be OK
    assert bool(basic_analysis.summary)
    
    root_file_observable = alert.root_analysis.get_observable(root_file_observable.uuid)
    assert isinstance(root_file_observable, FileObservable)
    # the file that came with the alert should still be there
    assert root_file_observable.exists
    
    additional_file_observable = alert.root_analysis.get_observable(additional_file_observable.uuid)
    assert isinstance(additional_file_observable, FileObservable)
    # but the one that was added during analysis should NOT be there
    assert not additional_file_observable.exists

@pytest.mark.integration
def test_cleanup():
    
    fp_root = create_root_analysis(analysis_mode='test_single', uuid=str(uuid.uuid4()))
    fp_root.initialize_storage()
    test_observable = fp_root.add_observable_by_spec(F_TEST, 'test_detection')
    fp_root.save()
    fp_root.schedule()

    ignore_root = create_root_analysis(analysis_mode='test_single', uuid=str(uuid.uuid4()))
    ignore_root.initialize_storage()
    test_observable = ignore_root.add_observable_by_spec(F_TEST, 'test_detection')
    ignore_root.save()
    ignore_root.schedule()

    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True # XXX kind of a hack?
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    alert = load_alert(fp_root.uuid)

    # we'll set the time of the disposition to one day past the configured limit
    alert.disposition = DISPOSITION_FALSE_POSITIVE
    alert.disposition_time = datetime.now() - timedelta(days=get_config()['global'].getint('fp_days') + 1)
    alert.sync()

    get_db().remove()

    alert = load_alert(ignore_root.uuid)

    # we'll set the time of the disposition to one day past the configured limit
    alert.disposition = DISPOSITION_IGNORE
    alert.disposition_time = datetime.now() - timedelta(days=get_config()['global'].getint('ignore_days') + 1)
    alert.sync()

    get_db().remove()

    # calling cleanup will cause the alert to get archived
    cleanup_alerts()

    get_db().remove()
    
    # now this alert should be archived
    alert = load_alert(fp_root.uuid)
    assert alert.archived

    # and this alert should be gone
    assert load_alert(ignore_root.uuid) is None
    assert not os.path.exists(ignore_root.storage_dir)

@pytest.mark.integration
def test_analysis_mode_dispositioned():

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_detection')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True # XXX kind of a hack?
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should have a single alert
    assert load_alert(root.uuid) is not None
    # and an empty workload
    assert get_db().query(Workload.id).count() == 0

    # set the disposition of this alert
    set_dispositions([root.uuid],
                        DISPOSITION_FALSE_POSITIVE, 
                        get_db().query(User).first().id)

    # check the disposition
    get_db().close()
    alert = load_alert(root.uuid)
    assert isinstance(alert, Alert)
    assert alert.disposition == DISPOSITION_FALSE_POSITIVE

    # we should have an entry in the workload for this now
    assert get_db().query(Workload.id).count() == 1
    workload_entry = get_db().query(Workload).first()
    assert isinstance(workload_entry, Workload)
    assert workload_entry.uuid == root.uuid
    assert workload_entry.analysis_mode == ANALYSIS_MODE_DISPOSITIONED

    # start the engine back up with this mode enabled
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_DISPOSITIONED]))
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # workload should be clear again
    get_db().close()
    assert get_db().query(Workload.id).count() == 0

    # analysis mode should have changed
    alert = load_alert(root.uuid)
    assert isinstance(alert, Alert)
    assert alert.root_analysis.analysis_mode == ANALYSIS_MODE_DISPOSITIONED

    # add another observable and add it back to the workload under correlation mode
    observable_2 = alert.root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    alert.root_analysis.analysis_mode = 'test_single'
    alert.sync()
    add_workload(alert.root_analysis) # why am I not calling schedule here?

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # make sure observable_2 got analyzed
    get_db().close()
    
    alert = load_alert(root.uuid)
    assert isinstance(alert, Alert)
    observable_2 = alert.root_analysis.get_observable(observable_2.uuid)
    assert observable_2
    analysis = observable_2.get_and_load_analysis(BasicTestAnalysis)
    assert analysis

@pytest.mark.integration
def test_analysis_mode_dispositioned_ignore():

    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_detection')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True # XXX kind of a hack?
    engine.configuration_manager.enable_module('analysis_module_basic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should have a single alert
    assert load_alert(root.uuid) is not None
    # and an empty workload
    assert get_db().query(Workload.id).count() == 0

    # set the disposition of this alert
    set_dispositions([root.uuid],
                        DISPOSITION_IGNORE, 
                        get_db().query(User).first().id)

    # check the disposition
    get_db().close()
    load_alert(root.uuid).disposition == DISPOSITION_IGNORE

    # we should NOT have an entry because IGNORED alerts are not analyzed
    assert get_db().query(Workload.id).count() == 0

@pytest.mark.integration
def test_observable_whitelisting():

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    assert test_observable
    add_observable_tag_mapping(test_observable, 'whitelisted')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test', "test_single")
    engine.configuration_manager.enable_module('analysis_module_user_defined_tagging', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should only see the user-defined tagging analysis
    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert len(test_observable.analysis) == 1
    assert test_observable.all_analysis[0].module_path == 'saq.modules.tag:UserDefinedTaggingAnalysis'


    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test_1')
    assert test_observable
    # remove the whitelisting
    remove_observable_tag_mapping(test_observable, 'whitelisted')
    assert not test_observable.has_tag('whitelisted')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_basic_test', "test_single")
    engine.configuration_manager.enable_module('analysis_module_user_defined_tagging', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should see any one analysis for this observable
    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    assert len(test_observable.analysis) == 2

# XXX review this for due to changes to F_FILE
@pytest.mark.integration
def test_file_observable_whitelisting():

    # add a user-defined whitelisting
    #add_observable_tag_mapping(F_FILE, "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3", None, 'whitelisted')

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_file = root.create_file_path("test")
    with open(test_file, "w") as fp:
        fp.write("Hello, world!")

    file_observable = root.add_file_observable(test_file)
    assert file_observable
    add_observable_tag_mapping(file_observable, 'whitelisted')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_generic_test', 'test_single')
    engine.configuration_manager.enable_module('analysis_module_user_defined_tagging', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should NOT see any analysis for this observable
    root = load_root(get_storage_dir(root.uuid))
    file_observable = root.get_observable(file_observable.uuid)
    assert file_observable
    assert file_observable.has_tag('whitelisted')
    assert len(file_observable.analysis) == 1
    assert file_observable.all_analysis[0].module_path == 'saq.modules.tag:UserDefinedTaggingAnalysis'

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_file = root.create_file_path("test2")
    with open(test_file, "w") as fp:
        fp.write("Hello, world!")

    file_observable = root.add_file_observable(test_file)
    assert file_observable
    # remove the whitelisting
    remove_observable_tag_mapping(file_observable, 'whitelisted')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_generic_test', 'test_single')
    engine.configuration_manager.enable_module('analysis_module_user_defined_tagging', "test_single")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should see analysis for this observable
    root = load_root(get_storage_dir(root.uuid))
    file_observable = root.get_observable(file_observable.uuid)
    assert file_observable
    assert not file_observable.has_tag('whitelisted')
    assert len(file_observable.analysis) == 2

@pytest.mark.integration
def test_module_instance():
    root = create_root_analysis(analysis_mode='test_groups')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'blah')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_groups', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.enable_module('analysis_module_instance_1', 'test_groups')
    engine.configuration_manager.enable_module('analysis_module_instance_2', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert log_count('loading module ') == 2

    root = load_root(get_storage_dir(root.uuid))
    test_observable = root.get_observable(test_observable.uuid)
    assert isinstance(test_observable, Observable)
    
    analysis_instance_1 = test_observable.get_and_load_analysis(TestInstanceAnalysis, instance='instance1')
    assert isinstance(analysis_instance_1, Analysis)
    assert analysis_instance_1.load_details()
    assert analysis_instance_1.details == {'sql': 'SELECT * FROM whatever'}


    analysis_instance_2 = test_observable.get_and_load_analysis(TestInstanceAnalysis, instance='instance2')
    assert isinstance(analysis_instance_2, Analysis)
    assert analysis_instance_2.load_details()
    assert analysis_instance_2.details == {'sql': 'SELECT * FROM thatonething'}

@pytest.mark.integration
def test_automation_limit():

    get_config()['analysis_module_generic_test']['automation_limit'] = '1'

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable_1 = root.add_observable_by_spec(F_TEST, 'test_1')
    observable_2 = root.add_observable_by_spec(F_TEST, 'test_2')
    root.analysis_mode = 'test_single'
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_generic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    assert len(root.get_analysis_by_type(GenericTestAnalysis)) == 1

    # do the same as before but add the directives that tells to engine to ignore the limits

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable_1 = root.add_observable_by_spec(F_TEST, 'test_1')
    observable_2 = root.add_observable_by_spec(F_TEST, 'test_2')
    observable_1.add_directive(DIRECTIVE_IGNORE_AUTOMATION_LIMITS)
    observable_2.add_directive(DIRECTIVE_IGNORE_AUTOMATION_LIMITS)
    root.analysis_mode = 'test_single'
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_generic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    # in this case both of them should have been analyzed
    assert len(root.get_analysis_by_type(GenericTestAnalysis)) == 2

@pytest.mark.integration
def test_missing_analysis():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_single')
    root.initialize_storage()
    test_observable = root.add_observable_by_spec(F_TEST, 'test')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(default_analysis_mode="test_single"))
    engine.configuration_manager.enable_module('analysis_module_generic_test', 'test_single')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # the idea here is a module was removed but it wasn't added to the deprecated analysis modules list
    # we'll fake that by editing the JSON
    with open(root.json_path, 'r') as fp:
        analysis_json = json.load(fp)

    analysis_json['observable_store'][test_observable.uuid]['analysis']['saq.modules.test:DoesNotExist'] = \
        analysis_json['observable_store'][test_observable.uuid]['analysis']['saq.modules.test:GenericTestAnalysis'].copy()
    del analysis_json['observable_store'][test_observable.uuid]['analysis']['saq.modules.test:GenericTestAnalysis']
    with open(root.json_path, 'w') as fp:
        json.dump(analysis_json, fp)

    # now when we try to load it we should have a missing analysis module
    root = load_root(get_storage_dir(root.uuid))

    test_observable = root.get_observable(test_observable.uuid)
    assert test_observable
    analysis = test_observable.get_and_load_analysis('saq.modules.test:DoesNotExist')
    assert isinstance(analysis, UnknownAnalysis)
    # analysis is still able to be loaded
    assert analysis.load_details()
    # the class that gets loaded is different
    # but the summary should still be the same
    assert analysis.summary == str(test_observable.value)

# XXX review this
@pytest.mark.integration
def test_cancel_analysis():
    # first we verify that we get 3 different analysis results for these 3 analysis modules like normal
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable

    # there should be 3 analysis
    assert len(observable.all_analysis) == 3
    assert log_count('execute_post_analysis called') == 1

    # now do the same thing but have the basic analysis module cancel the analysis
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_cancel')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.configuration_manager.enable_module('analysis_module_test_final_analysis')
    engine.configuration_manager.enable_module('analysis_module_test_post_analysis')
    engine.configuration_manager.enable_module('analysis_module_low_priority')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable

    # there should be no analysis
    assert len(observable.all_analysis) == 0
    # and this should still be 1 since it didn't run again
    # XXX review this
    #assert log_count('execute_post_analysis called') == 1

@pytest.mark.integration
def test_file_size_limit():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()

    # create a file with one byte
    target_path = root.create_file_path("target.txt")
    with open(target_path, 'w') as fp:
        fp.write('a')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_file_size_limit')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(FileSizeLimitAnalysis)
    # this should have worked because the size of the file is within the limit
    assert isinstance(analysis, FileSizeLimitAnalysis)

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()

    # exceed the limit
    target_path = root.create_file_path("target.txt")
    with open(target_path, 'w') as fp:
        fp.write('aaa')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_file_size_limit')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(FileSizeLimitAnalysis)
    # this should have not worked since the size of the file is too big
    assert analysis is None

    # file does not exist
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()

    target_path = root.create_file_path("target.txt")
    with open(target_path, 'w') as fp:
        fp.write('aaa')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()

    os.remove(observable.full_path)

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_file_size_limit')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(FileSizeLimitAnalysis)
    # file was missing
    # you'd think it would be None but the way it works today is that
    # we continue even if the file does not exist
    assert isinstance(analysis, FileSizeLimitAnalysis)

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()

    # delete the configuration option
    del get_config()['analysis_module_test_file_size_limit']['file_size_limit']
    target_path = root.create_file_path("target.txt")
    with open(target_path, 'w') as fp:
        fp.write('aaa')

    observable = root.add_file_observable(target_path)
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_test_file_size_limit')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    analysis = observable.get_and_load_analysis(FileSizeLimitAnalysis)
    # the default is no limit
    assert isinstance(analysis, FileSizeLimitAnalysis)
