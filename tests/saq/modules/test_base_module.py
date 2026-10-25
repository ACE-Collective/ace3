"""Tests for the parts of AnalysisModule (saq/modules/base_module.py) the engine tests do not reach:
the accepts() gates, the analysis lifecycle helpers and the environment checks modules call from
verify_environment()."""
import logging
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from saq.analysis import Analysis, RootAnalysis
from saq.constants import (
    DIRECTIVE_EXCLUDE_ALL,
    DIRECTIVE_IGNORE_AUTOMATION_LIMITS,
    F_TEST,
    AnalysisExecutionResult,
)
from saq.engine.errors import WaitForAnalysisException
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from tests.saq.test_util import create_test_context


class _TestAnalysis(Analysis):
    pass


class _OtherAnalysis(Analysis):
    pass


class _FailableAnalysis(Analysis):
    """An analysis that records whether it failed, for the allow_reanalysis_on_failure path."""

    @property
    def error(self):
        return self.details.get("error") if self.details else None


class _TestModule(AnalysisModule):
    def __init__(self, *args, result=AnalysisExecutionResult.COMPLETED, **kwargs):
        super().__init__(*args, **kwargs)
        self.result = result
        self.calls = []

    @property
    def generated_analysis_type(self):
        return _TestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, observable):
        self.calls.append(("execute_analysis", observable))
        return self.result

    def continue_analysis(self, observable, analysis):
        self.calls.append(("continue_analysis", observable))
        return self.result


class _RetryingModule(_TestModule):
    @property
    def generated_analysis_type(self):
        return _FailableAnalysis

    @property
    def allow_reanalysis_on_failure(self):
        return True


def _config(**kwargs) -> AnalysisModuleConfig:
    return AnalysisModuleConfig(
        name="test",
        python_module="saq.modules.base_module",
        python_class="AnalysisModule",
        enabled=True,
        **kwargs,
    )


def _module(root: RootAnalysis, cls=_TestModule, delayed_analysis_interface=None, **kwargs):
    return cls(
        context=create_test_context(root=root, delayed_analysis_interface=delayed_analysis_interface),
        config=_config(**kwargs),
    )


@pytest.fixture
def root():
    return RootAnalysis(queue="default", alert_type="test")


#
# accepts()
#

@pytest.mark.unit
def test_accepts_valid_queues(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    assert _module(root, valid_queues=["default"]).accepts(observable)
    assert not _module(root, valid_queues=["other"]).accepts(observable)


@pytest.mark.unit
def test_accepts_invalid_queues(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    assert _module(root, invalid_queues=["other"]).accepts(observable)
    assert not _module(root, invalid_queues=["default"]).accepts(observable)


@pytest.mark.unit
def test_accepts_exclude_all_directive(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)
    assert module.accepts(observable)

    observable.add_directive(DIRECTIVE_EXCLUDE_ALL)
    assert not module.accepts(observable)


@pytest.mark.unit
def test_accepts_module_observable_exclusions(root):
    excluded = root.add_observable_by_spec(F_TEST, "excluded")
    other = root.add_observable_by_spec(F_TEST, "other")
    module = _module(root, observable_exclusions={F_TEST: ["excluded"], "ipv4": ["10.0.0.1"]})

    assert module.is_excluded(excluded)
    assert not module.accepts(excluded)
    assert module.accepts(other)


@pytest.mark.unit
def test_accepts_required_directives_and_tags(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root, required_directives=["sandbox"], required_tags=["phish"])
    assert not module.accepts(observable)

    observable.add_directive("sandbox")
    assert not module.accepts(observable)

    observable.add_tag("phish")
    assert module.accepts(observable)


@pytest.mark.unit
def test_accepts_invalid_valid_observable_types(root, caplog):
    class _BrokenModule(_TestModule):
        @property
        def valid_observable_types(self):
            return 42

    observable = root.add_observable_by_spec(F_TEST, "test")
    with caplog.at_level(logging.ERROR):
        assert not _module(root, cls=_BrokenModule).accepts(observable)

    records = [r for r in caplog.records if "valid_observable_types returned invalid data type" in r.getMessage()]
    assert len(records) == 1
    assert records[0].exc_info is not None


@pytest.mark.unit
def test_accepts_completed_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)

    analysis = module.create_analysis(observable)
    analysis.completed = False
    # a delayed analysis is still accepted so the engine can continue it
    assert module.accepts(observable)

    analysis.completed = True
    assert not module.accepts(observable)


@pytest.mark.unit
def test_accepts_retries_failed_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root, cls=_RetryingModule)

    analysis = module.create_analysis(observable)
    analysis.details = {"error": "upstream timed out"}
    analysis.completed = True

    assert module.accepts(observable)
    # the failed analysis is gone, so the retry creates a new one
    assert observable.get_analysis(_FailableAnalysis) is None
    assert module.create_analysis(observable) is not analysis


@pytest.mark.unit
def test_accepts_does_not_retry_successful_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root, cls=_RetryingModule)

    analysis = module.create_analysis(observable)
    analysis.details = {"error": None}
    analysis.completed = True

    assert not module.accepts(observable)
    assert observable.get_analysis(_FailableAnalysis) is analysis


@pytest.mark.unit
def test_accepts_file_size_limit(root_analysis):
    small_path = root_analysis.create_file_path("small.bin")
    with open(small_path, "wb") as fp:
        fp.write(b"x" * 10)
    large_path = root_analysis.create_file_path("large.bin")
    with open(large_path, "wb") as fp:
        fp.write(b"x" * 100)

    small = root_analysis.add_file_observable(small_path)
    large = root_analysis.add_file_observable(large_path)

    class _FileModule(_TestModule):
        @property
        def valid_observable_types(self):
            return None

    module = _module(root_analysis, cls=_FileModule, file_size_limit=50)
    assert module.accepts(small)
    assert not module.accepts(large)

    # a file that is gone is not held back by the limit
    os.remove(large_path)
    assert module.accepts(large)


@pytest.mark.unit
def test_accepts_file_size_failure_is_logged(root_analysis, monkeypatch, caplog):
    file_path = root_analysis.create_file_path("test.bin")
    with open(file_path, "wb") as fp:
        fp.write(b"x" * 100)

    observable = root_analysis.add_file_observable(file_path)

    class _FileModule(_TestModule):
        @property
        def valid_observable_types(self):
            return None

    module = _module(root_analysis, cls=_FileModule, file_size_limit=50)
    monkeypatch.setattr(type(observable), "full_path", property(Mock(side_effect=RuntimeError("file_manager is not set"))))

    # the module still gets the file: the limit cannot be checked
    with caplog.at_level(logging.WARNING):
        assert module.accepts(observable)

    assert any(
        "unable to get size of file test.bin" in r.getMessage() and "file_manager is not set" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.unit
def test_accepts_clears_expired_cooldown(root, caplog):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root, cooldown_period=60)

    with caplog.at_level(logging.WARNING):
        module.enter_cooldown()
    assert any("entered cooldown period" in r.getMessage() for r in caplog.records)
    cooldown_timeout = module._context.cooldown_timeout
    assert cooldown_timeout > datetime.now()

    # still in cooldown: the module is called anyway, it decides what to do while cooling down
    assert module.accepts(observable)
    assert module._context.cooldown_timeout == cooldown_timeout

    module._context.cooldown_timeout = datetime.now() - timedelta(seconds=1)
    with caplog.at_level(logging.INFO):
        assert module.accepts(observable)
    assert module._context.cooldown_timeout is None
    assert any("exited cooldown mode" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_accepts_automation_limit(root):
    first = root.add_observable_by_spec(F_TEST, "first")
    second = root.add_observable_by_spec(F_TEST, "second")
    module = _module(root, automation_limit=1)

    assert module.accepts(second)
    module.create_analysis(first)
    assert not module.accepts(second)

    # an analyst forcing the analysis is not held to the limit
    second.add_directive(DIRECTIVE_IGNORE_AUTOMATION_LIMITS)
    assert module.accepts(second)


#
# analysis lifecycle
#

@pytest.mark.unit
def test_create_analysis_without_generated_type(root):
    class _NoAnalysisModule(AnalysisModule):
        pass

    observable = root.add_observable_by_spec(F_TEST, "test")
    with pytest.raises(RuntimeError, match="does not actually create Analysis"):
        _module(root, cls=_NoAnalysisModule).create_analysis(observable)


@pytest.mark.unit
def test_create_analysis_returns_existing(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)
    analysis = module.create_analysis(observable)

    assert module.create_analysis(observable) is analysis
    assert module.get_analysis(observable) is analysis


@pytest.mark.unit
def test_get_analysis_ignores_other_types(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    observable.add_analysis(_OtherAnalysis())

    assert _module(root).get_analysis(observable) is None


@pytest.mark.unit
def test_analyze_delayed_without_existing_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)

    # nothing to continue: the analysis starts over
    assert module.analyze(observable, delayed_analysis=True) == AnalysisExecutionResult.COMPLETED
    assert module.calls == [("execute_analysis", observable)]


@pytest.mark.unit
def test_analyze_delayed_continues_existing_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)
    module.create_analysis(observable)

    assert module.analyze(observable, delayed_analysis=True) == AnalysisExecutionResult.COMPLETED
    assert module.calls == [("continue_analysis", observable)]


@pytest.mark.unit
def test_analyze_invalid_result_is_logged(root, caplog):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)
    module.result = True

    with caplog.at_level(logging.ERROR):
        assert module.analyze(observable) is True

    assert any("should return an AnalysisExecutionResult" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_analyze_marks_grouping_target(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root, observation_grouping_time_range=timedelta(minutes=10))

    module.analyze(observable)
    assert observable.grouping_target


@pytest.mark.unit
def test_base_execute_and_continue_are_abstract(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = AnalysisModule(context=create_test_context(root=root), config=_config())

    with pytest.raises(NotImplementedError):
        module.execute_analysis(observable)

    with pytest.raises(NotImplementedError):
        module.continue_analysis(observable, _TestAnalysis())


@pytest.mark.unit
@pytest.mark.parametrize("kwargs,expected", [
    ({}, (0, 0, 10)),
    ({"minutes": 5}, (0, 5, 0)),
    ({"hours": 1, "seconds": 30}, (1, 0, 30)),
])
def test_delay_analysis(root, kwargs, expected):
    observable = root.add_observable_by_spec(F_TEST, "test")
    delayed_analysis_interface = Mock()
    delayed_analysis_interface.delay_analysis.return_value = True
    module = _module(root, delayed_analysis_interface=delayed_analysis_interface)
    analysis = module.create_analysis(observable)

    assert module.delay_analysis(observable, analysis, **kwargs) == AnalysisExecutionResult.INCOMPLETE
    assert analysis.delayed
    assert not analysis.completed

    call = delayed_analysis_interface.delay_analysis.call_args
    assert call.args[0] is root
    assert (call.kwargs["hours"], call.kwargs["minutes"], call.kwargs["seconds"]) == expected


@pytest.mark.unit
def test_delay_analysis_refused(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    delayed_analysis_interface = Mock()
    delayed_analysis_interface.delay_analysis.return_value = False
    module = _module(root, delayed_analysis_interface=delayed_analysis_interface)
    analysis = module.create_analysis(observable)

    assert module.delay_analysis(observable, analysis, seconds=5) == AnalysisExecutionResult.COMPLETED
    assert analysis.completed
    assert not analysis.delayed
    assert analysis.delay_analysis_timed_out


@pytest.mark.unit
def test_wait_for_analysis(root):
    observable = root.add_observable_by_spec(F_TEST, "test")
    module = _module(root)

    with pytest.raises(WaitForAnalysisException):
        module.wait_for_analysis(observable, _OtherAnalysis)

    analysis = _OtherAnalysis()
    analysis.completed = False
    observable.add_analysis(analysis)
    with pytest.raises(WaitForAnalysisException):
        module.wait_for_analysis(observable, _OtherAnalysis)

    analysis.completed = True
    assert module.wait_for_analysis(observable, _OtherAnalysis) is analysis


#
# grouping by time
#

def _timed(root, value, minutes):
    return root.add_observable_by_spec(
        F_TEST, value, o_time=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes))


@pytest.mark.unit
def test_grouping_requires_time_range():
    with pytest.raises(ValidationError, match="is_grouped_by_time requires observation_grouping_time_range"):
        _config(is_grouped_by_time=True)


@pytest.mark.unit
def test_analysis_covered_by_analyzed_observable_in_range(root):
    module = _module(root, observation_grouping_time_range=timedelta(minutes=10))
    first = _timed(root, "test", 0)
    second = _timed(root, "test", 5)
    out_of_range = _timed(root, "test", 30)
    other_value = _timed(root, "other", 5)

    module.create_analysis(first)
    assert module.analysis_covered(second)
    assert not module.analysis_covered(out_of_range)
    assert not module.analysis_covered(other_value)

    # covered observables are reported as done without being analyzed
    assert module.analyze(second) == AnalysisExecutionResult.COMPLETED
    assert module.calls == []


@pytest.mark.unit
def test_analysis_covered_by_grouping_target(root):
    module = _module(root, observation_grouping_time_range=timedelta(minutes=10))
    first = _timed(root, "test", 0)
    second = _timed(root, "test", 5)

    first.grouping_target = True
    # the grouping target gets the analysis, the rest of the group is covered by it
    assert not module.analysis_covered(first)
    assert module.analysis_covered(second)


@pytest.mark.unit
def test_analysis_covered_needs_timezones(root):
    module = _module(root, observation_grouping_time_range=timedelta(minutes=10))
    naive = root.add_observable_by_spec(F_TEST, "test", o_time=datetime(2026, 1, 1, 12, 0))
    untimed = root.add_observable_by_spec(F_TEST, "test")
    aware = _timed(root, "test", 0)

    # neither observable without a timezoned time can cover the other
    module.create_analysis(naive)
    module.create_analysis(untimed)
    assert not module.analysis_covered(naive)
    assert not module.analysis_covered(untimed)
    assert not module.analysis_covered(aware)


@pytest.mark.unit
def test_analysis_covered_without_grouping(root):
    module = _module(root)
    first = _timed(root, "test", 0)
    second = _timed(root, "test", 5)

    module.create_analysis(first)
    assert not module.analysis_covered(second)


#
# environment checks and utilities
#

@pytest.mark.unit
def test_verify_path_exists(root, tmpdir):
    module = _module(root)
    module.verify_path_exists(str(tmpdir))
    # relative paths are relative to SAQ_HOME
    module.verify_path_exists("etc/saq.default.yaml")

    with pytest.raises(RuntimeError, match="missing"):
        module.verify_path_exists("etc/does-not-exist.yaml")


@pytest.mark.unit
def test_verify_program_exists(root):
    module = _module(root)
    module.verify_program_exists("ls")
    module.verify_program_exists("/bin/sh")

    with pytest.raises(RuntimeError, match="missing /does/not/exist"):
        module.verify_program_exists("/does/not/exist")

    with pytest.raises(RuntimeError, match="cannot find does-not-exist-program"):
        module.verify_program_exists("does-not-exist-program")


@pytest.mark.unit
def test_create_required_directory(root, tmpdir):
    module = _module(root)
    target = os.path.join(str(tmpdir), "a", "b")
    module.create_required_directory(target)
    assert os.path.isdir(target)
    # already there
    module.create_required_directory(target)


@pytest.mark.unit
def test_create_required_directory_failure(root, tmpdir, caplog):
    module = _module(root)
    blocker = os.path.join(str(tmpdir), "file")
    with open(blocker, "w") as fp:
        fp.write("not a directory")

    with caplog.at_level(logging.ERROR), pytest.raises(OSError):
        module.create_required_directory(os.path.join(blocker, "sub"))

    assert any("unable to create required directory" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_create_required_directory_lost_race(root, tmpdir, monkeypatch):
    module = _module(root)
    target = os.path.join(str(tmpdir), "raced")

    def _makedirs(path):
        # another process created it between the isdir check and makedirs
        os.mkdir(path)
        raise FileExistsError(path)

    monkeypatch.setattr("saq.modules.base_module.os.makedirs", _makedirs)
    module.create_required_directory(target)
    assert os.path.isdir(target)


@pytest.mark.unit
def test_is_expected_observable(root):
    module = _module(root, expected_observables={F_TEST: {"expected"}})
    assert module.is_expected_observable(F_TEST, "expected")
    assert not module.is_expected_observable(F_TEST, "other")
    assert not module.is_expected_observable("ipv4", "10.0.0.1")


@pytest.mark.unit
@pytest.mark.parametrize("seconds,expected_sleeps", [
    (0.25, [0.25]),
    (2.5, [1, 1, 0.5]),
    (2, [1, 1]),
    (0, []),
])
def test_sleep(root, monkeypatch, seconds, expected_sleeps):
    sleeps = []
    monkeypatch.setattr("saq.modules.base_module.time.sleep", sleeps.append)

    _module(root).sleep(seconds)
    assert sleeps == pytest.approx(expected_sleeps)


@pytest.mark.unit
def test_sleep_stops_on_cancel(root, monkeypatch):
    module = _module(root)
    sleeps = []

    def _sleep(seconds):
        sleeps.append(seconds)
        module.cancel_analysis()

    monkeypatch.setattr("saq.modules.base_module.time.sleep", _sleep)
    module.sleep(10)
    assert sleeps == [1]


@pytest.mark.unit
def test_str_includes_instance(root):
    assert str(_module(root)) == "_TestModule"
    assert str(_module(root, instance="alpha")) == "_TestModule:alpha"
