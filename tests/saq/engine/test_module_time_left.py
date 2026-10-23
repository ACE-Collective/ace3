# tests for AnalysisModule.time_left(): how long the engine's current call to a module has before
# the monitor kills the worker (the module's maximum_analysis_time) or the pass is abandoned (the
# mode's cumulative fail time)

from types import SimpleNamespace
import time
import uuid

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config, get_engine_config
from saq.constants import F_TEST
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.engine.executor import AnalysisExecutor
from saq.engine.tracking import NullTrackingWriter
from saq.modules import AnalysisModule
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.config import AnalysisModuleConfig
from saq.modules.test import TimeLeftTestAnalysis
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis


def _module(test_context, maximum_analysis_time: int = 300) -> AnalysisModule:
    return AnalysisModule(
        context=test_context,
        config=AnalysisModuleConfig(
            name="test",
            python_module="saq.modules.base_module",
            python_class="AnalysisModule",
            enabled=True,
            maximum_analysis_time=maximum_analysis_time,
        ),
    )


def _executor() -> AnalysisExecutor:
    return AnalysisExecutor(
        configuration_manager=ConfigurationManager(EngineConfiguration()),
        delayed_analysis_interface=None,
        tracking_message_manager=NullTrackingWriter("test"),
    )


def _seconds_left(deadline: float) -> float:
    return deadline - time.monotonic()


@pytest.mark.unit
def test_time_left_outside_an_engine_call_is_the_module_limit(test_context):
    assert _module(test_context, maximum_analysis_time=42).time_left() == 42


@pytest.mark.unit
def test_time_left_counts_down_to_the_deadline(test_context):
    module = _module(test_context)
    module.set_analysis_deadline(time.monotonic() + 10)
    assert 9 < module.time_left() <= 10

    module.set_analysis_deadline(time.monotonic() - 5)
    assert module.time_left() < 0

    module.set_analysis_deadline(None)
    assert module.time_left() == 300


@pytest.mark.unit
def test_adapter_passes_the_deadline_to_the_module(test_context):
    # the engine only ever holds the adapter, which inherits a do-nothing stub from the protocol
    module = _module(test_context)
    AnalysisModuleAdapter(module).set_analysis_deadline(time.monotonic() + 10)
    assert 9 < module.time_left() <= 10


@pytest.mark.unit
def test_deadline_is_the_module_limit_when_it_is_tighter():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900
    module = SimpleNamespace(maximum_analysis_time=60)

    deadline = _executor()._get_analysis_deadline(module, "test_groups", current_total_time=100)

    assert 59 < _seconds_left(deadline) <= 60


@pytest.mark.unit
def test_deadline_is_the_cumulative_limit_when_it_is_tighter():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900
    module = SimpleNamespace(maximum_analysis_time=300)

    deadline = _executor()._get_analysis_deadline(module, "test_groups", current_total_time=880)

    assert 19 < _seconds_left(deadline) <= 20


@pytest.mark.unit
def test_deadline_uses_the_analysis_mode_cumulative_limit():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900
    get_config().get_analysis_mode_config("test_groups").maximum_cumulative_analysis_fail_time = 30
    module = SimpleNamespace(maximum_analysis_time=300)

    deadline = _executor()._get_analysis_deadline(module, "test_groups", current_total_time=10)

    assert 19 < _seconds_left(deadline) <= 20


@pytest.mark.unit
def test_deadline_is_past_once_the_cumulative_limit_is_spent():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900
    module = SimpleNamespace(maximum_analysis_time=300)

    deadline = _executor()._get_analysis_deadline(module, "test_groups", current_total_time=950)

    assert _seconds_left(deadline) < -49


@pytest.mark.unit
def test_deadline_ignores_the_cumulative_limit_in_ignored_modes():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900
    get_engine_config().analysis_modes_ignore_cumulative_timeout = ["test_groups"]
    module = SimpleNamespace(maximum_analysis_time=300)

    deadline = _executor()._get_analysis_deadline(module, "test_groups", current_total_time=880)

    assert 299 < _seconds_left(deadline) <= 300


def _run_time_left_module() -> float:
    """Runs TimeLeftTestModule through the engine and returns what time_left() said."""
    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "test_1")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("test_time_left", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root.uuid))
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(TimeLeftTestAnalysis)
    assert analysis is not None
    return analysis.details["time_left"]


@pytest.mark.integration
def test_engine_gives_the_module_its_own_limit():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 900

    # the module's maximum_analysis_time defaults to 300, which is what time_left() returns when
    # no deadline was set, so the bound is strict
    assert 290 < _run_time_left_module() < 300


@pytest.mark.integration
def test_engine_gives_the_module_what_is_left_of_the_cumulative_limit():
    get_config().global_settings.maximum_cumulative_analysis_fail_time = 30

    assert 20 < _run_time_left_module() <= 30
