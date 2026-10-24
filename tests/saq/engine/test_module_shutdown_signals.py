"""Tests for the module-facing shutdown signal (see docs/ENGINE.md §19.5).

``AnalysisModule`` exposes three things that are supposed to tell a module the
process it is running in is going away:

    @property
    def shutdown(self):
        return self.get_engine().shutdown

    @property
    def controlled_shutdown(self):
        return self.get_engine().controlled_shutdown

    def sleep(self, seconds):
        while not self.shutdown and not self._context.cancel_analysis_flag ...

``get_engine()`` returned ``self._context.engine`` and ``AnalysisModuleContext``
has no ``engine`` member, so every one of them raised ``AttributeError`` --
``sleep()`` on its very first loop iteration. The type it claimed to return,
``EngineInterface``, described an engine that no longer exists: nothing on
``Engine`` implements any of its five members.

The signal now comes from the object that actually has shutdown state. ``Worker``
owns the two multiprocessing events, ``WorkerShutdownAdapter`` presents them as
``ShutdownInterface``, and the executor hands that to every module's
``AnalysisModuleContext`` -- the same route ``DelayedAnalysisAdapter`` already
took.

Tests 1-3 and 7 failed before the fix with ``AttributeError``. Test 4 pins the
positive path, tests 5-6 pin the removals.
"""
import glob
import os
import threading
import time
import uuid
from unittest.mock import Mock

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import F_TEST
from saq.database.util.locking import acquire_lock, force_release_lock, release_lock
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.shutdown_adapter import WorkerShutdownAdapter
from saq.engine.worker import Worker
from saq.environment import get_temp_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.test import KEY_CONTROLLED_SHUTDOWN, KEY_SHUTDOWN, KEY_TEST_RESULT, BasicTestAnalysis
from saq.sandbox.runner import landlock_available
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import search_log, wait_for_condition
from tests.saq.test_util import create_test_context


class FakeShutdownInterface:
    """A ShutdownInterface whose two flags can be flipped from the test."""

    def __init__(self):
        self.immediate = False
        self.controlled = False

    @property
    def shutdown(self) -> bool:
        return self.immediate

    @property
    def controlled_shutdown(self) -> bool:
        return self.controlled


def make_module(context: AnalysisModuleContext) -> AnalysisModule:
    return AnalysisModule(
        context=context,
        config=AnalysisModuleConfig(
            name="test",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True,
        ),
    )


@pytest.mark.unit
def test_module_shutdown_defaults_false(test_context):
    """A module that is not running under a worker is not shutting down.

    Before the fix this raised AttributeError on ``self._context.engine``.
    """
    assert make_module(test_context).shutdown is False


@pytest.mark.unit
def test_module_controlled_shutdown_defaults_false(test_context):
    assert make_module(test_context).controlled_shutdown is False


@pytest.mark.unit
def test_module_sleep_returns_without_engine(test_context):
    """``sleep()`` reads ``self.shutdown`` on every iteration, so it raised
    immediately rather than sleeping."""
    make_module(test_context).sleep(1)


@pytest.mark.unit
def test_module_shutdown_follows_shutdown_interface():
    """Both flags travel from the injected interface to the module."""
    shutdown_interface = FakeShutdownInterface()
    module = make_module(create_test_context(shutdown_interface=shutdown_interface))

    assert module.shutdown is False
    assert module.controlled_shutdown is False

    shutdown_interface.immediate = True
    assert module.shutdown is True
    assert module.controlled_shutdown is False

    shutdown_interface.immediate = False
    shutdown_interface.controlled = True
    assert module.shutdown is False
    assert module.controlled_shutdown is True


@pytest.mark.unit
def test_module_should_stop_on_shutdown_or_cancel():
    """One predicate for both reasons a module gives up, so it can be handed to a blocking call."""
    shutdown_interface = FakeShutdownInterface()
    module = make_module(create_test_context(shutdown_interface=shutdown_interface))
    assert module.should_stop() is False

    # a controlled shutdown finishes the work item in hand
    shutdown_interface.controlled = True
    assert module.should_stop() is False

    shutdown_interface.immediate = True
    assert module.should_stop() is True

    shutdown_interface.immediate = False
    module.cancel_analysis()
    assert module.should_stop() is True


@pytest.mark.unit
def test_module_sees_the_engines_cancel():
    """A cancel on the engine's context reaches the module, which never cancelled anything itself."""
    engine_canceled = False
    module = make_module(create_test_context(engine_canceled=lambda: engine_canceled))
    assert module.is_canceled_analysis() is False
    assert module.should_stop() is False

    engine_canceled = True
    assert module.is_canceled_analysis() is True
    assert module.should_stop() is True
    # the module's own flag is untouched: the executor tells the two apart
    assert module._context.cancel_analysis_flag is False


@pytest.mark.unit
def test_module_without_an_engine_is_not_canceled(test_context):
    assert make_module(test_context).is_canceled_analysis() is False


@pytest.mark.unit
@pytest.mark.parametrize("stop", ["shutdown", "cancel"])
def test_module_sleep_returns_once_it_should_stop(stop):
    shutdown_interface = FakeShutdownInterface()
    module = make_module(create_test_context(shutdown_interface=shutdown_interface))
    if stop == "shutdown":
        shutdown_interface.immediate = True
    else:
        module.cancel_analysis()

    started = time.monotonic()
    module.sleep(60)
    assert time.monotonic() - started < 1


@pytest.mark.unit
def test_worker_shutdown_adapter_tracks_worker():
    """The adapter reports the worker's two shutdown events, separately.

    They are separate on purpose: an immediate shutdown must break a module out
    of ``sleep()``, a controlled one means "finish the work item you have".
    """
    worker = Worker(
        name="test_worker",
        configuration_manager=ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True)),
        node_manager=Mock(spec=NodeManagerInterface),
    )

    adapter = WorkerShutdownAdapter(worker)
    assert adapter.shutdown is False
    assert adapter.controlled_shutdown is False

    worker.controlled_shutdown()
    assert adapter.shutdown is False
    assert adapter.controlled_shutdown is True

    worker.immediate_shutdown()
    assert adapter.shutdown is True
    assert adapter.controlled_shutdown is True


@pytest.mark.unit
def test_stale_engine_interface_is_gone():
    """The protocol and adapter that described an engine that never existed."""
    with pytest.raises(ImportError):
        import saq.engine.interface  # noqa: F401

    with pytest.raises(ImportError):
        import saq.engine.adapter  # noqa: F401

    # get_engine() named something the context never had
    assert not hasattr(AnalysisModule, "get_engine")


@pytest.mark.unit
def test_dead_alerts_module_is_gone():
    """``saq/modules/alerts.py`` was the only caller of
    ``get_engine().cancel_analysis()``. It was registered in no config file: the
    disposition check lives in the executor (§19.1) and the detection -> mode
    transition in the orchestrator (§13.3)."""
    with pytest.raises(ImportError):
        import saq.modules.alerts  # noqa: F401


@pytest.mark.integration
def test_module_shutdown_signals_during_analysis(root_analysis):
    """The executor wires the signal into every module it runs.

    ``BasicTestAnalyzer.execute_test_engine_signals`` records both flags into the
    analysis details. Before the fix the module raised AttributeError, the
    executor swallowed it as a module exception, and no analysis was attached at
    all.
    """
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_engine_signals")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    # get_and_load_analysis returns False (not None) when nothing is attached
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert analysis, "the module raised instead of reading the shutdown signal"
    assert analysis.details[KEY_SHUTDOWN] is False
    assert analysis.details[KEY_CONTROLLED_SHUTDOWN] is False


def _when_the_command_starts(action) -> threading.Thread:
    """Runs action on another thread once the module's sandboxed command is running."""
    def run():
        started_glob = os.path.join(get_temp_dir(), "test_sandbox_should_stop", "*", "started")
        wait_for_condition(lambda: glob.glob(started_glob), timeout=30)
        action()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _schedule_sandbox_should_stop(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_sandbox_should_stop")
    root_analysis.save()
    root_analysis.schedule()
    return observable


def _sandbox_result(root_analysis, observable) -> str:
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert analysis
    return analysis.details[KEY_TEST_RESULT]


@pytest.mark.integration
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_engine_cancel_stops_a_modules_sandboxed_command(root_analysis, monkeypatch):
    """A cancel on the work item's context reaches a module blocked in run_sandboxed(cancel=should_stop).

    Before the fix the engine's cancel never reached the module's is_canceled_analysis(), so the
    command ran to its 60 second timeout.
    """
    captured = []
    original = AnalysisOrchestrator.orchestrate_analysis

    def spy(self, execution_context):
        captured.append(execution_context)
        return original(self, execution_context)

    monkeypatch.setattr(AnalysisOrchestrator, "orchestrate_analysis", spy)
    observable = _schedule_sandbox_should_stop(root_analysis)
    # the call Worker._handle_lock_lost makes from the keepalive thread
    canceller = _when_the_command_starts(lambda: captured[0].cancel_analysis())

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    started = time.monotonic()
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    elapsed = time.monotonic() - started
    canceller.join(timeout=5)

    assert _sandbox_result(root_analysis, observable) == "cancelled"
    assert elapsed < 30
    # the cancel came from the engine and is not reported as the module's
    assert not search_log("cancelled analysis for")


@pytest.mark.system
@pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")
def test_lost_lock_stops_a_modules_sandboxed_command(root_analysis, monkeypatch):
    """The same, end to end: a forked worker loses its lock while the command runs.

    Only a worker that is not single threaded keeps its lock alive, so this one is forked.
    """
    monkeypatch.setattr(get_config().global_settings, "lock_keepalive_frequency", 0.1)
    observable = _schedule_sandbox_should_stop(root_analysis)
    other_lock_uuid = str(uuid.uuid4())

    def steal_lock():
        # as another node does once our lock has expired: our keepalive cannot re-acquire it
        force_release_lock(root_analysis.uuid)
        assert acquire_lock(root_analysis.uuid, other_lock_uuid)

    thief = _when_the_command_starts(steal_lock)

    try:
        engine = Engine()
        engine.configuration_manager.enable_module("basic_test", "test_groups")
        engine.start(execution_mode=EngineExecutionMode.SINGLE_SHOT)
        thief.join(timeout=5)
    finally:
        release_lock(root_analysis.uuid, other_lock_uuid)

    # the controller stops at once in SINGLE_SHOT and kills a worker still running after its
    # shutdown budget, which leaves no analysis: a result at all means the command was stopped
    assert _sandbox_result(root_analysis, observable) == "cancelled"
