# vim: sw=4:ts=4:et:cc=120
#
# the engine tells a module when it drops the module's pending delayed analysis: the root's analysis
# aborted, so its delayed requests are cleared and continue_analysis is never called for them
#

import logging
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config
from saq.constants import F_TEST
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.engine.tracking import NullTrackingWriter
from saq.modules.base_module import AnalysisModule
from saq.modules.test import (
    KEY_ABANDONED,
    KEY_DELAYED_REQUEST,
    KEY_REQUEST_COUNT,
    BasicTestAnalysis,
    DelayedAnalysisTestAnalysis,
    DelayedAnalysisTestModule,
)
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis, log_count


def _executor() -> AnalysisExecutor:
    """A real AnalysisExecutor with no analysis modules loaded."""
    return AnalysisExecutor(
        configuration_manager=ConfigurationManager(EngineConfiguration()),
        delayed_analysis_interface=None,
        tracking_message_manager=NullTrackingWriter("test"),
    )


def _add(root: RootAnalysis, value: str, delayed: bool = True) -> tuple:
    observable = root.add_observable_by_spec(F_TEST, value)
    analysis = BasicTestAnalysis()
    observable.add_analysis(analysis)
    analysis.delayed = delayed
    return observable, analysis


@pytest.mark.unit
def test_a_module_ignores_a_dropped_delay_by_default():
    root = RootAnalysis()
    observable, analysis = _add(root, "pending")
    module = Mock(spec=AnalysisModule)

    assert AnalysisModule.delayed_analysis_abandoned(module, observable, analysis) is None
    assert analysis.delayed
    assert module.method_calls == []


@pytest.mark.unit
def test_each_pending_delay_is_handed_to_its_module():
    root = RootAnalysis()
    first = _add(root, "first")
    second = _add(root, "second")
    _add(root, "finished", delayed=False)
    module = Mock()
    executor = _executor()

    with patch.object(executor, "_get_analysis_module_by_generated_analysis", return_value=module) as lookup:
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))

    lookup.assert_called_with(first[1].module_path)
    calls = [c.args for c in module.delayed_analysis_abandoned.call_args_list]
    assert len(calls) == 2 and first in calls and second in calls


@pytest.mark.unit
def test_a_dropped_delay_is_handed_over_once():
    root = RootAnalysis()
    first = _add(root, "first")
    second = _add(root, "second")
    module = Mock()
    executor = _executor()

    with patch.object(executor, "_get_analysis_module_by_generated_analysis", return_value=module):
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))
        # a later pass of the same root aborts too
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))

    calls = [c.args for c in module.delayed_analysis_abandoned.call_args_list]
    assert len(calls) == 2 and first in calls and second in calls
    assert not root.delayed


@pytest.mark.unit
def test_a_delay_whose_module_is_not_loaded_is_skipped(caplog):
    root = RootAnalysis()
    _add(root, "orphaned")
    executor = _executor()

    # no module is loaded, so none generates BasicTestAnalysis
    with caplog.at_level(logging.ERROR):
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))

    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    # the delay is dropped all the same
    assert not root.delayed


@pytest.mark.unit
def test_a_module_that_fails_is_logged_and_the_others_are_still_told(caplog):
    root = RootAnalysis()
    failing = _add(root, "failing")
    other = _add(root, "other")
    told = []

    def handle(observable, analysis):
        if observable.value == "failing":
            raise RuntimeError("could not stop it")
        told.append((observable, analysis))

    module = Mock(**{"delayed_analysis_abandoned.side_effect": handle})
    module.name = "test_module"
    executor = _executor()

    with patch.object(executor, "_get_analysis_module_by_generated_analysis", return_value=module), \
         caplog.at_level(logging.ERROR):
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))

    assert told == [other]
    assert not failing[1].delayed
    (record,) = [r for r in caplog.records if r.exc_info and "could not stop it" in str(r.exc_info[1])]
    assert record.levelno == logging.ERROR
    assert record.root_uuid == root.uuid
    assert record.observable_uuid == failing[0].uuid
    assert record.module_name == "test_module"


@pytest.mark.unit
@pytest.mark.parametrize("completed,told", [(False, True), (True, False)])
def test_the_resumed_analysis_is_handed_over_unless_it_completed(completed, told):
    root = RootAnalysis()
    observable, analysis = _add(root, "resumed", delayed=False)
    analysis.completed = completed
    request = DelayedAnalysisRequest(root.uuid, observable.uuid, "basic_test", datetime.now(), "unused")
    request.root = root
    request.analysis = analysis
    module = Mock()
    executor = _executor()

    with patch.object(executor, "_get_analysis_module_by_generated_analysis", return_value=module):
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=request))

    assert module.delayed_analysis_abandoned.called is told


@pytest.mark.unit
def test_a_failure_walking_the_tree_is_logged_and_not_raised(caplog):
    root = Mock(spec=RootAnalysis, uuid="root-uuid")
    type(root).all_observables = property(Mock(side_effect=RuntimeError("tree is broken")))
    executor = _executor()

    with caplog.at_level(logging.ERROR):
        executor.notify_delayed_analysis_abandoned(EngineExecutionContext(work_item=root))

    (record,) = [r for r in caplog.records if r.exc_info and "tree is broken" in str(r.exc_info[1])]
    assert record.root_uuid == "root-uuid"


@pytest.mark.integration
def test_an_aborted_analysis_tells_the_module_its_delay_was_dropped():
    root = create_root_analysis(analysis_mode="test_groups")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "0:00|0:30")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")

    # the first pass delays the analysis
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    assert load_root(get_storage_dir(root.uuid)).delayed

    # the pass that resumes it is past the cumulative limit before the module runs again, so the
    # root's analysis aborts and its delayed request is cleared
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 0
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    assert log_count("ACE took too long to analyze") > 0

    root = load_root(get_storage_dir(root.uuid))
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert analysis.details[KEY_ABANDONED] is True
    # the module was told without being resumed, and with the details the first pass saved
    assert analysis.details[KEY_DELAYED_REQUEST] is False
    assert analysis.details[KEY_REQUEST_COUNT] == 1


@pytest.mark.integration
def test_a_delay_dropped_by_an_abort_is_not_handed_over_again():
    root = create_root_analysis(analysis_mode="test_groups")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "0:00|0:30")
    # a second delay on the root, not the one the resumed pass resumes
    pending = root.add_observable_by_spec(F_TEST, "5:00|10:00")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    get_config().global_settings.maximum_cumulative_analysis_fail_time = 0
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    aborts = log_count("ACE took too long to analyze")
    assert aborts > 0

    root = load_root(get_storage_dir(root.uuid))
    assert not root.delayed

    # a later pass of the same root (a mode change, a re-analysis) aborts too
    with patch.object(DelayedAnalysisTestModule, "delayed_analysis_abandoned") as hook:
        root.schedule()
        engine = Engine()
        engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")
        engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert log_count("ACE took too long to analyze") > aborts
    hook.assert_not_called()
    analysis = load_root(get_storage_dir(root.uuid)).get_observable(pending.uuid).get_and_load_analysis(
        DelayedAnalysisTestAnalysis
    )
    assert analysis.details[KEY_ABANDONED] is True
