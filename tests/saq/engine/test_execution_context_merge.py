"""Tests for the single per-work-item execution context (see docs/ENGINE.md §19.15).

``Worker.execute`` built an ``EngineExecutionContext`` for the work item, and
``AnalysisExecutor.execute`` built a *second*, unsynchronized
``AnalysisExecutionContext`` for the same work item two layers down, because the
orchestrator handed it the work item rather than the context it already had:

    def _execute_analysis(self, execution_context: EngineExecutionContext):
        context = self.analysis_executor.execute(execution_context.work_item)

The consequence was a dead guard. ``execute()`` opened with

    context = AnalysisExecutionContext(analysis_target)
    self._current_context = context
    ...
    # don't even start if we're already cancelled
    if not context.cancel_analysis_flag:
        self._execute_recursive_analysis(context)

on a ``context`` it had constructed itself two lines earlier, so the flag could
never be True. Cancellation had to be routed sideways through
``AnalysisExecutor._current_context``, which is non-None *only while*
``execute()`` runs -- exactly the window that was already safe. A lock lost
during ``Worker.execute``'s setup, during ``_process_work_item``
(``root.load()`` / ``DelayedAnalysisRequest.load()`` -- real I/O) or during
``_check_disposition`` (a database round trip) was logged and then silently
discarded, and the full analysis ran on a root the worker no longer owned.

``EngineExecutionContext.total_analysis_time`` was likewise never written and
``EngineExecutionContext.cancel_analysis()`` set a flag nothing read.

The fix collapses the two into one ``EngineExecutionContext``, created once by
the worker and passed down, and routes lock-loss cancellation through
``Worker.current_execution_context`` (an attribute that previously was only ever
assigned ``None``).
"""

from datetime import datetime
import uuid as uuidlib
from unittest.mock import MagicMock, Mock, patch

import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.constants import F_TEST, LockManagerType, WorkloadManagerType
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.delayed_analysis import DelayedAnalysisRequest
from saq.engine.enums import EngineExecutionMode
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis

#
# unit tests
# ----------------------------------------------------------------------------


def _executor() -> AnalysisExecutor:
    """An AnalysisExecutor with everything but execute() itself stubbed out.

    Same recipe as tests/saq/engine/test_cumulative_analysis_time.py -- we only
    care about whether execute() decides to run the recursive analysis.
    """
    configuration_manager = MagicMock()
    configuration_manager.analysis_modules = []
    executor = AnalysisExecutor(
        configuration_manager=configuration_manager,
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
    )
    executor._execute_recursive_analysis = MagicMock()
    executor._execute_post_analysis = MagicMock()
    return executor


def _orchestrator(analysis_executor) -> AnalysisOrchestrator:
    """A real AnalysisOrchestrator over the given executor."""
    configuration_manager = MagicMock()
    return AnalysisOrchestrator(
        configuration_manager=configuration_manager,
        analysis_executor=analysis_executor,
        workload_manager=MagicMock(),
        lock_manager=MagicMock(),
    )


def _metrics_disabled():
    """get_engine_config() stand-in with metrics logging off."""
    engine_config = MagicMock()
    engine_config.metrics_logging.enabled = False
    return engine_config


def _worker() -> Worker:
    """A real Worker with its collaborators replaced.

    Worker builds its lock manager, workload manager and orchestrator in
    __init__ with no injection point, so they are reassigned afterwards.
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = False
    configuration_manager.config.auto_refresh_frequency = 0

    worker = Worker(
        name="test_worker_execution_context_merge",
        configuration_manager=configuration_manager,
        node_manager=Mock(spec=NodeManagerInterface),
    )

    worker.workload_manager = MagicMock()
    worker.lock_manager = MagicMock()
    worker.analysis_orchestrator = MagicMock()
    worker.tracking_message_manager = MagicMock()
    return worker


@pytest.mark.unit
def test_executor_receives_the_worker_context(root_analysis):
    """The orchestrator hands the executor the context it already has.

    It used to hand over execution_context.work_item, which is what made the
    executor build a second context of its own.
    """
    execution_context = EngineExecutionContext(root_analysis)
    analysis_executor = Mock(spec=AnalysisExecutor)
    orchestrator = _orchestrator(analysis_executor)

    with patch(
        "saq.engine.analysis_orchestrator.get_engine_config",
        return_value=_metrics_disabled(),
    ):
        orchestrator._execute_analysis(execution_context)

    analysis_executor.execute.assert_called_once()
    assert analysis_executor.execute.call_args.args[0] is execution_context


@pytest.mark.unit
def test_cancel_set_before_execute_skips_analysis(root_analysis):
    """The 'don't even start if we're already cancelled' guard is live.

    The tree is still closed out -- post analysis runs either way, exactly as it
    does for a cancel that lands mid-loop.
    """
    executor = _executor()
    execution_context = EngineExecutionContext(root_analysis)
    execution_context.cancel_analysis()

    executor.execute(execution_context)

    executor._execute_recursive_analysis.assert_not_called()
    executor._execute_post_analysis.assert_called_once()


@pytest.mark.unit
def test_uncancelled_context_still_analyzes(root_analysis):
    """The other side of the guard: nothing changed for the normal path."""
    executor = _executor()
    execution_context = EngineExecutionContext(root_analysis)

    executor.execute(execution_context)

    executor._execute_recursive_analysis.assert_called_once()
    assert executor._execute_recursive_analysis.call_args.args[0] is execution_context


@pytest.mark.unit
def test_cancel_arriving_during_work_item_load_is_honored(root_analysis):
    """A lock lost while _process_work_item is loading the root must stick.

    This is the window the two contexts left open: the executor's context did
    not exist yet, so cancel_current_analysis() was a silent no-op and the whole
    analysis then ran on a root this worker no longer owned.
    """
    executor = _executor()
    orchestrator = _orchestrator(executor)
    execution_context = EngineExecutionContext(root_analysis)

    def cancel_while_loading(ctx):
        # as if the keepalive thread noticed the lock was gone during root.load()
        ctx.cancel_analysis()
        return True

    orchestrator._process_work_item = cancel_while_loading
    orchestrator._check_disposition = MagicMock(return_value=False)
    orchestrator._handle_post_analysis_logic = MagicMock()

    with patch(
        "saq.engine.analysis_orchestrator.get_engine_config",
        return_value=_metrics_disabled(),
    ):
        orchestrator.orchestrate_analysis(execution_context)

    executor._execute_recursive_analysis.assert_not_called()


@pytest.mark.unit
def test_lock_loss_cancels_the_current_context(root_analysis):
    """_handle_lock_lost cancels the context the worker is holding."""
    worker = _worker()
    execution_context = EngineExecutionContext(root_analysis)
    worker.current_execution_context = execution_context

    worker._handle_lock_lost()

    assert execution_context.cancel_analysis_flag is True


@pytest.mark.unit
def test_lock_loss_with_no_work_item_is_a_no_op():
    """current_execution_context is declared, so a stray callback cannot blow up.

    It was previously only ever *assigned* None, never initialized -- a
    _handle_lock_lost() before the first execute() had nothing to read.
    """
    worker = _worker()

    assert worker.current_execution_context is None

    worker._handle_lock_lost()

    assert worker.current_execution_context is None


@pytest.mark.unit
def test_root_resolves_lazily_for_a_delayed_request(tmp_path):
    """root stays a property, because the context now outlives the load.

    The context is built in Worker.execute, before _process_work_item calls
    DelayedAnalysisRequest.load(), and load() *constructs* the RootAnalysis. A
    snapshot attribute captured at construction would pin None forever.
    """
    request = DelayedAnalysisRequest(
        uuid=str(uuidlib.uuid4()),
        observable_uuid=str(uuidlib.uuid4()),
        analysis_module_str="analysis_module_basic_test",
        next_analysis=datetime.now(),
        storage_dir=str(tmp_path),
    )
    execution_context = EngineExecutionContext(request)

    assert execution_context.is_delayed_analysis
    assert execution_context.delayed_analysis_request is request
    # not loaded yet: must return None rather than raise, because
    # orchestrate_analysis tests `if execution_context.root is None`
    assert execution_context.root is None

    # as load() does
    request.root = RootAnalysis(storage_dir=str(tmp_path))

    assert execution_context.root is request.root


@pytest.mark.unit
def test_root_work_item_is_not_delayed_analysis(root_analysis):
    """The RootAnalysis half of the same property set."""
    execution_context = EngineExecutionContext(root_analysis)

    assert not execution_context.is_delayed_analysis
    assert execution_context.delayed_analysis_request is None
    assert execution_context.root is root_analysis


#
# integration tests
# ----------------------------------------------------------------------------


def _capture_contexts(monkeypatch) -> list:
    """Records the EngineExecutionContext each work item is orchestrated with.

    Single-threaded mode runs in this process, so the objects we get back are
    the objects the engine actually used. We deliberately do not read
    Worker.current_execution_context instead -- the worker clears it in its
    finally, and keeping it populated just to be testable would pin a whole
    RootAnalysis tree across idle periods.
    """
    captured = []
    original = AnalysisOrchestrator.orchestrate_analysis

    def spy(self, execution_context):
        captured.append(execution_context)
        return original(self, execution_context)

    monkeypatch.setattr(AnalysisOrchestrator, "orchestrate_analysis", spy)
    return captured


@pytest.mark.integration
def test_cancel_before_the_main_loop_stops_the_analysis(monkeypatch):
    """A cancel landing after the load but before the main loop stops the run.

    This is the defect end to end: before the fix the cancel landed on an object
    nothing read and every module ran anyway.
    """
    original = AnalysisOrchestrator._process_work_item

    def cancel_after_load(self, execution_context):
        result = original(self, execution_context)
        # as if _handle_lock_lost fired while root.load() was running
        execution_context.cancel_analysis()
        return result

    monkeypatch.setattr(AnalysisOrchestrator, "_process_work_item", cancel_after_load)

    root = create_root_analysis(uuid=str(uuidlib.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "test_1")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    observable = root.get_observable(observable.uuid)
    assert observable
    assert len(observable.all_analysis) == 0


@pytest.mark.integration
def test_module_cancel_lands_on_the_engine_context(monkeypatch):
    """A module cancelling analysis is visible on the worker's context.

    This asserts the merge from the inside out (module -> executor -> worker),
    complementing the unit tests which assert it from the outside in.
    """
    captured = _capture_contexts(monkeypatch)

    root = create_root_analysis(uuid=str(uuidlib.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "test_cancel")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert len(captured) == 1
    assert captured[0].cancel_analysis_flag is True


@pytest.mark.integration
def test_total_analysis_time_lands_on_the_engine_context(monkeypatch):
    """Per-module timing accumulates on the one context, not a private copy."""
    captured = _capture_contexts(monkeypatch)

    root = create_root_analysis(uuid=str(uuidlib.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "test_1")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert len(captured) == 1
    assert captured[0].total_analysis_time
    assert "basic_test" in captured[0].total_analysis_time
    assert captured[0].total_analysis_time["basic_test"] >= 0


@pytest.mark.integration
def test_delayed_request_pass_shares_one_context(monkeypatch):
    """The delayed-analysis resumption gets one context built before the load.

    A merge that kept AnalysisExecutionContext's snapshot `root` attribute would
    leave captured[1].root as None forever, since the context is constructed in
    Worker.execute and DelayedAnalysisRequest.load() runs after it.
    """
    captured = _capture_contexts(monkeypatch)

    root = create_root_analysis(uuid=str(uuidlib.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "0:00|0:01")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    assert len(captured) == 2

    assert isinstance(captured[0].work_item, RootAnalysis)
    assert not captured[0].is_delayed_analysis

    assert isinstance(captured[1].work_item, DelayedAnalysisRequest)
    assert captured[1].is_delayed_analysis
    assert captured[1].root is not None
    assert captured[1].root is captured[1].work_item.root
