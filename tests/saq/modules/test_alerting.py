import os
import signal
import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_DISPOSITIONED, CONFIG_ENGINE, CONFIG_ENGINE_ALERT_DISPOSITION_CHECK_FREQUENCY, DISPOSITION_DELIVERY, DISPOSITION_FALSE_POSITIVE, F_TEST
from saq.database.model import Alert, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis, log_count, wait_for_log_count, wait_for_process

@pytest.mark.integration
def test_detection(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_7')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['test_groups', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    # make sure we detected the change in modes
    alert = load_alert(root_analysis.uuid)
    assert isinstance(alert, Alert)
    assert alert.root_analysis.analysis_mode == ANALYSIS_MODE_CORRELATION

    assert log_count('analysis mode for RootAnalysis({}) changed from test_groups to correlation'.format(root_analysis.uuid)) == 1
    assert log_count('completed analysis RootAnalysis({})'.format(root_analysis.uuid)) == 1

@pytest.mark.integration
def test_no_detection(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_1')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert not load_alert(root_analysis.uuid)
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    # the analysis mode should be the same
    assert root_analysis.analysis_mode == 'test_groups'

    # make sure we detected the change in modes
    assert log_count('analysis mode for RootAnalysis({}) changed from test_empty to correlation'.format(root_analysis.uuid)) == 0
    assert log_count('completed analysis RootAnalysis({})'.format(root_analysis.uuid)) == 1

@pytest.mark.integration
def test_existing_alert(root_analysis):
    root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_7')
    root_analysis.save()
    root_analysis.schedule()

    # go ahead and insert the alert
    ALERT(root_analysis)

    # now analyze the alert that's already in the database
    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert load_alert(root_analysis.uuid)

    # and we should have a warning about the alert already existing
    #self.assertEqual(log_count('uuid {} already exists in alerts table'.format(root.uuid)), 1)

@pytest.mark.integration
def test_whitelisted(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, 'test_8')
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert not load_alert(root_analysis.uuid)

    # and we should have a warning about the alert already existing
    #self.assertEqual(log_count('uuid {} already exists in alerts table'.format(root.uuid)), 1)

@pytest.mark.system
def test_alert_dispositioned():

    from saq.database import Alert, User, Workload, set_dispositions

    # test the following scenario
    # 1) alert is generated
    # 2) ace begins to analyze the alert in correlation mode
    # 3) user sets the disposition of the alert WHILE ace is analyzing it
    # 4) ace detects the disposition and stops analyzing the alert
    # 5) ace picks up the alert in ANALYSIS_MODE_DISPOSITIONED mode

    get_config()[CONFIG_ENGINE][CONFIG_ENGINE_ALERT_DISPOSITION_CHECK_FREQUENCY] = 0 # check every time
    
    # create an analysis that turns into an alert
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_detection')
    observable_pause = root.add_observable_by_spec(F_TEST, 'pause_3')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(pool_size_limit=1, local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test', ['test_single', ANALYSIS_MODE_CORRELATION])
    engine.configuration_manager.enable_module('analysis_module_low_priority', ANALYSIS_MODE_CORRELATION) # low will run after pause ensuring a check of disposition during analysis
    engine.configuration_manager.enable_module('analysis_module_pause', ANALYSIS_MODE_CORRELATION) # we'll set the disposition during the pause
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    # wait until we're processing the alert
    wait_for_log_count("processing This is only a test. mode correlation", 1, 10)

    # set the disposition of this alert
    set_dispositions([root.uuid],
                        DISPOSITION_FALSE_POSITIVE, 
                        get_db().query(User).first().id)

    # look for analysis_module_alert_disposition_analyzer to cancel the analysis
    wait_for_log_count("stopping analysis on dispositioned alert", 1)

    # now wait for it to stop
    assert engine_process.pid is not None
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    get_db().close()
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert
    alert.load()

    observable_pause = alert.root_analysis.get_observable(observable_pause.uuid)
    assert observable_pause
    # since LowPriorityAnalysis executes *after* analysis_module_pause, it
    # should NOT have executed on this observable
    low_pri_analysis = observable_pause.get_and_load_analysis('LowPriorityAnalysis')
    assert low_pri_analysis is None

    # the mode should have changed to dispositioned 
    # XXX never worked
    #assert alert.analysis_mode == ANALYSIS_MODE_DISPOSITIONED
    # and we should have a workload entry for this as well
    get_db().close()
    assert get_db().query(Workload).filter(
                            Workload.uuid == alert.uuid, 
                            Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED).first()

    # now with the analysis in correlation mode, if we start up the analysis again it should *NOT* analyze
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert
    alert.load()
    alert.root_analysis.schedule()

    engine = Engine(config=EngineConfiguration(pool_size_limit=1, local_analysis_modes=[ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test', ['test_single', ANALYSIS_MODE_CORRELATION])
    engine.configuration_manager.enable_module('analysis_module_low_priority', ANALYSIS_MODE_CORRELATION)
    engine.configuration_manager.enable_module('analysis_module_pause', ANALYSIS_MODE_CORRELATION)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    wait_for_log_count('skipping analysis on dispositioned alert', 1)

    get_db().close()
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert
    alert.load()

    observable_pause = alert.root_analysis.get_observable(observable_pause.uuid)
    assert observable_pause
    # since LowPriorityAnalysis executes *after* analysis_module_pause, it
    # should NOT have executed on this observable
    low_pri_analysis = observable_pause.get_and_load_analysis('LowPriorityAnalysis')
    assert low_pri_analysis is None

@pytest.mark.system
def test_alert_continue_specific_disposition():
    from saq.database import Alert, User, Workload, set_dispositions

    # test the following scenario
    # 1) alert is generated
    # 2) ace begins to analyze the alert in correlation mode
    # 3) user sets the disposition of the alert WHILE ace is analyzing it (to one that is configured to NOT stop analysis)
    # 4) ace detects the disposition and continues analyzing the alert until finished
    # 5) ace picks up the alert in ANALYSIS_MODE_DISPOSITIONED mode

    get_config()['service_engine']['alert_disposition_check_frequency'] = 0  # check every time
    get_config()['service_engine']['stop_analysis_on_any_alert_disposition'] = False
    get_config()['service_engine']['stop_analysis_on_dispositions'] = ['FALSE_POSITIVE', 'IGNORE']

    # create an analysis that turns into an alert
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, 'test_detection')
    observable_pause = root.add_observable_by_spec(F_TEST, 'pause_3')
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(pool_size_limit=1, local_analysis_modes=['test_single', ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.config.alerting_enabled = True
    engine.configuration_manager.enable_module('analysis_module_basic_test', ['test_single', ANALYSIS_MODE_CORRELATION])
    engine.configuration_manager.enable_module('analysis_module_low_priority',
                            ANALYSIS_MODE_CORRELATION)  # low will run after pause ensuring a check of disposition during analysis
    engine.configuration_manager.enable_module('analysis_module_pause',
                            ANALYSIS_MODE_CORRELATION)  # we'll set the disposition during the pause
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    # wait until we're processing the alert
    wait_for_log_count("processing This is only a test. mode correlation", 1, 10)

    # set the disposition of this alert
    set_dispositions([root.uuid],
                        DISPOSITION_DELIVERY,
                        get_db().query(User).first().id)

    # look for analysis_module_alert_disposition_analyzer to cancel the analysis
    wait_for_log_count("but continuing analysis", 1)

    # now wait for it to stop
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    get_db().close()
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert
    alert.load()

    observable_pause = alert.root_analysis.get_observable(observable_pause.uuid)
    assert observable_pause
    # since LowPriorityAnalysis executes *after* analysis_module_pause, it
    # should have executed on this observable since we did not stop analysis
    low_pri_analysis = observable_pause.get_and_load_analysis('LowPriorityAnalysis')
    assert low_pri_analysis

    # the mode should have changed to dispositioned
    assert alert.root_analysis.analysis_mode, ANALYSIS_MODE_DISPOSITIONED
    # and we should have a workload entry for this as well
    get_db().close()
    assert get_db().query(Workload).filter(
        Workload.uuid == alert.uuid,
        Workload.analysis_mode == ANALYSIS_MODE_DISPOSITIONED).first()