import logging
from unittest.mock import MagicMock

import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.engine.executor import AnalysisExecutor
from saq.configuration.config import get_analysis_module_config
from saq.modules.test import BasicTestAnalysis, BasicTestAnalyzer


def _executor() -> AnalysisExecutor:
    return AnalysisExecutor(
        configuration_manager=MagicMock(),
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _module() -> BasicTestAnalyzer:
    return BasicTestAnalyzer(get_analysis_module_config("basic_test"))


@pytest.mark.unit
def test_module_exception_marks_the_analysis_it_had_created():
    root = RootAnalysis()
    observable = root.add_observable_by_spec(F_TEST, "test")
    analysis = observable.add_analysis(BasicTestAnalysis())

    _executor()._record_module_exception(root, observable, _module(), RuntimeError("boom"), "crash-1")

    assert analysis.error == "RuntimeError: boom (crash_id crash-1)"
    assert analysis.completed
    # recorded on the analysis, so not also as a failure without one
    assert not root.is_analysis_failed(BasicTestAnalysis, observable)


@pytest.mark.unit
def test_failing_to_record_a_module_exception_is_logged_and_does_not_raise(monkeypatch, caplog):
    root = RootAnalysis()
    observable = root.add_observable_by_spec(F_TEST, "test")

    def _fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("saq.engine.executor.mark_analysis_failed", _fail)
    with caplog.at_level(logging.ERROR):
        _executor()._record_module_exception(root, observable, _module(), RuntimeError("boom"), "crash-1")

    record = next(r for r in caplog.records if r.message == "unable to mark analysis failed")
    assert record.levelno == logging.ERROR
    assert record.exc_info
    assert record.crash_id == "crash-1"


@pytest.mark.unit
def test_module_exception_without_an_observable_records_nothing():
    root = RootAnalysis()

    _executor()._record_module_exception(root, None, _module(), RuntimeError("boom"), "crash-1")

    assert root.analysis_failures == {}
