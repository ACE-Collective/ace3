# vim: sw=4:ts=4:et:cc=120
#
# tests for the cumulative analysis time budget the engine keeps in
# root.state["total_analysis_time_seconds"] -- the baseline the cumulative
# warning/fail timeouts measure against (see docs/ENGINE.md 12.1, 19.6)
#

from datetime import datetime
import uuid
from unittest.mock import MagicMock

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import F_TEST, STATE_TOTAL_ANALYSIS_TIME_SECONDS
from saq.engine.core import Engine
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.enums import EngineExecutionMode
from saq.engine.executor import AnalysisExecutor
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis, log_count

#
# unit tests over the budget lifetime: a RootAnalysis work item starts a fresh
# budget, a DelayedAnalysisRequest resumption continues the one its originating
# pass started.
#

def _executor() -> AnalysisExecutor:
    """An AnalysisExecutor with everything but execute() itself stubbed out."""
    configuration_manager = MagicMock()
    configuration_manager.analysis_modules = []
    executor = AnalysisExecutor(
        configuration_manager=configuration_manager,
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
    )
    # we only care about what execute() does to root.state
    executor._execute_recursive_analysis = MagicMock()
    executor._execute_post_analysis = MagicMock()
    return executor

@pytest.mark.unit
def test_root_work_item_starts_a_fresh_budget(root_analysis):
    root_analysis.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] = 500

    _executor().execute(root_analysis)

    assert root_analysis.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] == 0

@pytest.mark.unit
def test_delayed_analysis_request_continues_the_budget(root_analysis):
    root_analysis.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] = 500

    request = DelayedAnalysisRequest(
        uuid=root_analysis.uuid,
        observable_uuid=str(uuid.uuid4()),
        analysis_module_str="analysis_module_basic_test",
        next_analysis=datetime.now(),
        storage_dir=root_analysis.storage_dir)
    request.root = root_analysis

    _executor().execute(request)

    assert root_analysis.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] == 500

@pytest.mark.unit
def test_budget_defaults_to_zero_when_missing(root_analysis):
    # a root saved before this key existed, resumed as a delayed request
    assert STATE_TOTAL_ANALYSIS_TIME_SECONDS not in root_analysis.state

    request = DelayedAnalysisRequest(
        uuid=root_analysis.uuid,
        observable_uuid=str(uuid.uuid4()),
        analysis_module_str="analysis_module_basic_test",
        next_analysis=datetime.now(),
        storage_dir=root_analysis.storage_dir)
    request.root = root_analysis

    _executor().execute(request)

    assert root_analysis.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] == 0

#
# integration tests: the time actually spent analyzing is recorded, survives the
# save/load round trip, and accumulates across delayed analysis resumptions.
#

@pytest.mark.integration
def test_total_analysis_time_seconds_recorded():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, 'test_1')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    assert root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] > 0

@pytest.mark.integration
def test_total_analysis_time_seconds_accumulates_across_delayed_analysis():
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, '0:00|0:10')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('test_delayed_analysis', 'test_groups')

    # the first pass requests delayed analysis
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    root = load_root(get_storage_dir(root.uuid))
    assert root.delayed
    first_pass = root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS]
    assert first_pass > 0

    # the second pass resumes it, and must pick the budget back up where the
    # first pass left it rather than starting over at zero
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    root = load_root(get_storage_dir(root.uuid))
    assert root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] > first_pass

@pytest.mark.integration
def test_total_analysis_time_seconds_resets_for_new_work_item():
    # the budget covers one logical analysis run: a root work item (a mode
    # transition, a disposition pass, analyst requested analysis) starts over
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, 'test_1')
    root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] = 9999
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('basic_test', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    assert 0 < root.state[STATE_TOTAL_ANALYSIS_TIME_SECONDS] < 60

@pytest.mark.integration
def test_cumulative_fail_time_trips_across_delayed_analysis():
    # neither pass exceeds the cumulative fail time on its own, but together
    # they do -- which is only visible if the first pass is remembered
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 3

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode='test_groups')
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, '2')
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('test_slow_delayed_analysis', 'test_groups')

    # spends ~2 seconds and then requests delayed analysis
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    assert log_count('ACE took too long to analyze') == 0

    # spends another ~2 seconds, which puts the run over the 3 second limit
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    assert log_count('ACE took too long to analyze') > 0
