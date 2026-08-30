"""Tests for the per-analysis-mode mid-pass save policy (ENGINE.md 19.7).

The engine used to write the entire serialized analysis tree after every single module
invocation. That is only useful for alert-facing modes, where an analyst may reload the
alert page while it is still being analyzed; for high volume detection modes nobody is
watching an individual root and the O(tree) serialize per module is pure cost.

``root_save_frequency`` is resolved per analysis mode, falling back to ``global_settings``:

    None -> never write mid-pass, only at the boundaries of the pass
    0    -> write after every module invocation (the pre-throttle behavior)
    N    -> write at most once every N seconds
"""
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor


def _make_executor() -> AnalysisExecutor:
    return AnalysisExecutor(
        configuration_manager=MagicMock(),
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_context(tmp_path, analysis_mode="test_groups"):
    root = RootAnalysis(storage_dir=str(tmp_path), analysis_mode=analysis_mode)
    root.initialize_storage()
    return EngineExecutionContext(root), root


def _config(mode_value, global_value):
    """Stand-in for get_config() covering only what _get_root_save_frequency reads."""
    config = MagicMock()
    config.get_analysis_mode_config.return_value = SimpleNamespace(root_save_frequency=mode_value)
    config.global_settings = SimpleNamespace(root_save_frequency=global_value)
    return config


@pytest.mark.unit
@pytest.mark.parametrize("mode_value, global_value, expected", [
    # the mode's own value always wins when it is set...
    (5, None, 5),
    (0, 5, 0),
    (30, 0, 30),
    # ...and falls back to global_settings when it is not
    (None, 5, 5),
    (None, 0, 0),
    (None, None, None),
])
def test_get_root_save_frequency_resolution(mode_value, global_value, expected):
    executor = _make_executor()
    with patch("saq.engine.executor.get_config", return_value=_config(mode_value, global_value)):
        assert executor._get_root_save_frequency("test_groups") == expected


@pytest.mark.unit
def test_save_root_never_when_unset(tmp_path):
    """An unset frequency means detection-mode behavior: no mid-pass writes at all."""
    executor = _make_executor()
    context, root = _make_context(tmp_path)
    root.save = MagicMock()

    with patch.object(executor, "_get_root_save_frequency", return_value=None):
        for _ in range(10):
            assert executor._save_root(context, root) is False

    root.save.assert_not_called()


@pytest.mark.unit
def test_save_root_every_invocation_when_zero(tmp_path):
    """0 preserves the pre-throttle behavior exactly."""
    executor = _make_executor()
    context, root = _make_context(tmp_path)
    root.save = MagicMock()

    with patch.object(executor, "_get_root_save_frequency", return_value=0):
        for _ in range(10):
            assert executor._save_root(context, root) is True

    assert root.save.call_count == 10


@pytest.mark.unit
def test_save_root_throttled_within_window(tmp_path):
    """Several invocations inside one window produce exactly one write."""
    executor = _make_executor()
    context, root = _make_context(tmp_path)
    root.save = MagicMock()

    # the context starts with last_root_save = now, so the window is already open
    with patch.object(executor, "_get_root_save_frequency", return_value=5):
        for _ in range(10):
            assert executor._save_root(context, root) is False

    root.save.assert_not_called()


@pytest.mark.unit
def test_save_root_writes_once_window_elapses(tmp_path):
    """Once the window closes a single write happens and the window reopens."""
    executor = _make_executor()
    context, root = _make_context(tmp_path)
    root.save = MagicMock()

    with patch.object(executor, "_get_root_save_frequency", return_value=5):
        # push the last save far enough into the past that the window has closed
        context.last_root_save = datetime.now() - timedelta(seconds=6)
        assert executor._save_root(context, root) is True
        assert root.save.call_count == 1

        # and the window is closed again immediately afterwards
        for _ in range(5):
            assert executor._save_root(context, root) is False
        assert root.save.call_count == 1

        # ...until it elapses once more
        context.last_root_save = datetime.now() - timedelta(seconds=6)
        assert executor._save_root(context, root) is True
        assert root.save.call_count == 2


@pytest.mark.unit
def test_save_root_uses_the_roots_analysis_mode(tmp_path):
    """The policy is looked up against the mode of the root actually being analyzed."""
    executor = _make_executor()
    context, root = _make_context(tmp_path, analysis_mode="correlation")
    root.save = MagicMock()

    with patch.object(executor, "_get_root_save_frequency", return_value=0) as mock_lookup:
        executor._save_root(context, root)

    mock_lookup.assert_called_once_with("correlation")


#
# integration coverage: a real engine pass under each policy
#

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import F_TEST
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.util.uuid import get_storage_dir


class _SaveRootTally:
    """Counts calls to AnalysisExecutor._save_root and the writes they produced."""

    def __init__(self):
        self.calls = 0
        self.writes = 0


def _make_save_root_spy(tally):
    """A drop-in replacement for AnalysisExecutor._save_root that records into ``tally``.

    Written as a plain function so it still binds as a method when patched onto the class.
    """
    original = AnalysisExecutor._save_root

    def _save_root(self, context, root):
        tally.calls += 1
        result = original(self, context, root)
        if result:
            tally.writes += 1
        return result

    return _save_root


def _run_one_pass(root_analysis, modules, frequency):
    """Runs a single engine pass over root_analysis, returning the _save_root tally."""
    # clear the global fallback so the mode's own value is what decides the policy -- the
    # unittest config pins global_settings.root_save_frequency to 0, which would otherwise
    # turn the "unset" case back into "write every invocation". the per-test config deep
    # copy in tests/conftest.py::global_function_setup undoes both of these afterwards.
    get_config().global_settings.root_save_frequency = None
    get_config().get_analysis_mode_config(root_analysis.analysis_mode).root_save_frequency = frequency

    tally = _SaveRootTally()
    engine = Engine()
    for module in modules:
        engine.configuration_manager.enable_module(module, root_analysis.analysis_mode)

    with patch.object(AnalysisExecutor, "_save_root", _make_save_root_spy(tally)):
        engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    return tally


@pytest.mark.integration
def test_no_mid_pass_writes_when_unset(root_analysis):
    """A detection-style mode writes nothing mid-pass, yet the pass still persists
    every module's analysis through the unconditional save at the pass boundary."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()
    root_analysis.schedule()

    tally = _run_one_pass(root_analysis, ["basic_test", "low_priority", "high_priority"], None)

    # the modules ran and asked to be saved...
    assert tally.calls > 1
    # ...and not one of those requests produced a write
    assert tally.writes == 0

    # the analysis is still on disk, because _execute_analysis saves at the boundary
    from saq.modules.test import BasicTestAnalysis
    reloaded = load_root(get_storage_dir(root_analysis.uuid))
    analysis = reloaded.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert analysis is not None
    assert analysis.test_result


@pytest.mark.integration
def test_writes_every_invocation_when_zero(root_analysis):
    """0 reproduces the pre-throttle behavior: every request produces a write."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()
    root_analysis.schedule()

    tally = _run_one_pass(root_analysis, ["basic_test", "low_priority", "high_priority"], 0)

    assert tally.calls > 1
    assert tally.writes == tally.calls

    from saq.modules.test import BasicTestAnalysis
    reloaded = load_root(get_storage_dir(root_analysis.uuid))
    analysis = reloaded.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert analysis is not None


@pytest.mark.integration
def test_throttle_collapses_a_burst_of_invocations(root_analysis):
    """With a window far longer than the pass, the whole burst collapses to no writes --
    every module invocation lands inside the window opened when the pass started."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()
    root_analysis.schedule()

    tally = _run_one_pass(root_analysis, ["basic_test", "low_priority", "high_priority"], 3600)

    assert tally.calls > 1
    assert tally.writes == 0

    from saq.modules.test import BasicTestAnalysis
    reloaded = load_root(get_storage_dir(root_analysis.uuid))
    analysis = reloaded.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    assert analysis is not None


@pytest.mark.integration
@pytest.mark.parametrize("frequency", [None, 0, 3600])
def test_delayed_analysis_suspension_is_on_disk(root_analysis, frequency):
    """A module that requests delayed analysis suspends the pass. Whatever the policy, the
    in-flight analysis must be on disk before the DelayedAnalysisRequest can be resumed --
    the pass boundary save is what guarantees that."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    root_analysis.save()
    root_analysis.schedule()

    _run_one_pass(root_analysis, ["test_delayed_analysis"], frequency)

    from saq.modules.test import DelayedAnalysisTestAnalysis
    reloaded = load_root(get_storage_dir(root_analysis.uuid))
    analysis = reloaded.get_observable(observable.uuid).get_and_load_analysis(DelayedAnalysisTestAnalysis)
    assert analysis is not None, "the in-flight delayed analysis was not persisted"
    assert analysis.initial_request


#
# system coverage: what a mode with no mid-pass saving gives up, and what it must keep
#

import os
import signal
import uuid

from saq.engine.engine_configuration import EngineConfiguration
from tests.saq.helpers import (
    create_root_analysis,
    log_count,
    wait_for_log_count,
    wait_for_process,
)


@pytest.mark.system
def test_detection_mode_restarts_from_scratch_without_looping():
    """The detection-mode counterpart to test_timeout_root_flushed.

    That test asserts work completed before a crash *survives* the crash, which is what
    root_save_frequency=0 buys. With the frequency unset there is no mid-pass write, so
    the same work is lost and re-run -- the tradeoff we accepted. What must NOT change is
    that the module which killed the worker is recorded as failed and skipped on the
    retry, otherwise the root would crash the worker forever.
    """
    get_config().global_settings.root_save_frequency = None
    get_config().get_analysis_mode_config("test_groups").root_save_frequency = None
    get_config().get_analysis_module_config("generate_file").priority = 0
    get_config().get_analysis_module_config("basic_test").priority = 10
    get_config().get_analysis_module_config("basic_test").maximum_analysis_time = 0

    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=get_storage_dir(root_uuid))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "test_generate_file")
    root.save()
    root.schedule()

    engine = Engine(config=EngineConfiguration(pool_size_limit=1))
    engine.configuration_manager.enable_module("generate_file")
    engine.configuration_manager.enable_module("basic_test")
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    # the worker dies on basic_test and is replaced
    wait_for_log_count("detected death of", 1, 5)
    wait_for_log_count("started worker", 2, 5)
    os.kill(engine_process.pid, signal.SIGINT)
    wait_for_process(engine_process)

    root = RootAnalysis(storage_dir=get_storage_dir(root_uuid))
    root.load()
    observable = root.get_observable(observable.uuid)
    assert observable

    # the module that killed the worker is recorded, so the retry skips it. this is the
    # part that must hold no matter what the save policy is -- without it the replacement
    # worker re-runs the same module and dies again, forever
    from saq.modules.test import BasicTestAnalysis
    assert root.is_analysis_failed(BasicTestAnalysis, observable)

    # and generate_file ran a second time, because nothing was written mid-pass. this is
    # the cost of the policy, asserted so a future change to it is visible here
    assert log_count("analysis GenerateFileAnalysis is completed") == 2
