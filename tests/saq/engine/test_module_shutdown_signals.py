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
from unittest.mock import Mock

import pytest

from saq.analysis.root import load_root
from saq.constants import F_TEST, LockManagerType, WorkloadManagerType
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.shutdown_adapter import WorkerShutdownAdapter
from saq.engine.worker import Worker
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.modules.test import KEY_CONTROLLED_SHUTDOWN, KEY_SHUTDOWN, BasicTestAnalysis
from saq.util.uuid import get_storage_dir
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
def test_worker_shutdown_adapter_tracks_worker():
    """The adapter reports the worker's two shutdown events, separately.

    They are separate on purpose: an immediate shutdown must break a module out
    of ``sleep()``, a controlled one means "finish the work item you have".
    """
    configuration_manager = Mock(spec=ConfigurationManager)
    configuration_manager.config = Mock()
    configuration_manager.config.analysis_mode_priority = None
    configuration_manager.config.lock_manager_type = LockManagerType.LOCAL
    configuration_manager.config.workload_manager_type = WorkloadManagerType.MEMORY
    configuration_manager.config.single_threaded_mode = True

    worker = Worker(
        name="test_worker",
        configuration_manager=configuration_manager,
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
