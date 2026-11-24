import pytest

from saq.analysis.root import load_root
from saq.constants import F_TEST
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.util.uuid import get_storage_dir

from example.modules import ExampleAnalysis


# the standard analysis-module test (AGENTS.md): enable the one module in a test analysis mode, run
# the engine for one work item, then read the result from what the engine saved, not from the root
# built here
@pytest.mark.integration
def test_example_analyzer(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "example value")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    # the name in the analysis_module_example: block of etc/saq.integration.yaml
    engine.configuration_manager.enable_module("example", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(ExampleAnalysis)
    assert isinstance(analysis, ExampleAnalysis)
    assert analysis.result == "Example Analysis Result"
    assert analysis.summary == "Example Analysis: Example Analysis Result"
