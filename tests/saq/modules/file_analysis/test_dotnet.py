import logging
import os
import pytest
from unittest.mock import Mock

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_DE4DOT, ANALYSIS_MODULE_ILSPY, F_FILE, AnalysisExecutionResult, R_EXTRACTED_FROM
from saq.modules.file_analysis import dotnet
from saq.modules.file_analysis.dotnet import (
    De4dotAnalysis,
    De4dotAnalyzer,
    IlspyAnalysis,
    IlspyAnalyzer,
    KEY_STDERR,
    KEY_DEOBFUSCATED,
)
from saq.observables.file import FileObservable
from tests.saq.test_util import create_test_context

DOTNET_SAMPLE_HEX = os.path.join(os.path.dirname(__file__), "..", "test_file_analysis", "6346eea9dff4eac53113fc2ba3b8a497.hex")


def _write_dotnet_sample(path, truncate: int = 0) -> str:
    """Writes the Obfuscar-protected .NET sample to path. A truncated copy still identifies as a .NET assembly
    but neither de4dot nor ilspy can load it."""
    data = b""
    with open(DOTNET_SAMPLE_HEX, "r") as fp:
        for line in fp:
            data += bytes.fromhex(line.strip())

    with open(str(path), "wb") as fp:
        fp.write(data[:truncate] if truncate else data)

    return str(path)


def _stopped_on_call(cls, call_number: int):
    """Runs the real run_sandboxed_tool except for the given (1-based) call, which returns None, as it does
    for a tool that was stopped (a timeout, too much output) or could not be run."""
    calls = []
    real = cls.run_sandboxed_tool

    def _run(self, args, target, **kwargs):
        calls.append(args)
        if len(calls) == call_number:
            return None
        return real(self, args, target, **kwargs)

    return _run


@pytest.mark.unit
class TestDe4dotAnalysis:

    def test_init(self):
        analysis = De4dotAnalysis()
        assert analysis.stdout is None
        assert analysis.stderr is None
        assert analysis.error is None
        assert analysis.deobfuscated is False

    def test_stderr_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.stderr is None

        # test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr

    def test_generate_summary_with_error(self):
        analysis = De4dotAnalysis()
        analysis.error = "Deobfuscation failed"

        summary = analysis.generate_summary()
        assert summary == "De4dot Analysis error: Deobfuscation failed"

    def test_generate_summary_success(self):
        analysis = De4dotAnalysis()
        analysis.error = None

        summary = analysis.generate_summary()
        assert summary == "De4dot Analysis: deobfuscated"


@pytest.mark.unit
class TestDe4dotAnalyzer:

    def test_valid_observable_types(self):
        analyzer = De4dotAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))
        assert analyzer.valid_observable_types == F_FILE

    def test_execute_analysis_not_dotnet_file(self, root_analysis, tmpdir, monkeypatch):
        # de4dot -d detects nothing in a text file either, so only the tool not running shows the check
        run = Mock(return_value=None)
        monkeypatch.setattr(De4dotAnalyzer, "run_sandboxed_tool", run)
        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        # create a non-dotnet file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not a dotnet file")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None
        run.assert_not_called()

    def test_execute_analysis_no_obfuscation_detected(self, root_analysis, tmpdir):
        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        # de4dot cannot load a truncated assembly, so it detects nothing
        test_file = _write_dotnet_sample(tmpdir / "test.exe", truncate=4096)
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None
        assert not os.path.exists(f"{file_observable.full_path}.deobfuscated")

    def test_execute_analysis_detection_stopped(self, root_analysis, tmpdir, monkeypatch):
        # the -d detection check does not finish: nothing is known about the file, so nothing is recorded
        monkeypatch.setattr(De4dotAnalyzer, "run_sandboxed_tool", _stopped_on_call(De4dotAnalyzer, 1))

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        assert file_observable.get_analysis(De4dotAnalysis) is None

    def test_execute_analysis_successful_deobfuscation(self, root_analysis, tmpdir):
        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert isinstance(analysis, De4dotAnalysis)

        # check analysis properties
        assert "Renaming all obfuscated symbols" in analysis.stdout
        assert analysis.error is None
        assert analysis.deobfuscated is True

        # check that deobfuscated file was added as observable
        deobfuscated_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".deobfuscated"):
                deobfuscated_observable = obs
                break

        assert deobfuscated_observable is not None
        assert os.path.getsize(deobfuscated_observable.full_path) > 0
        assert deobfuscated_observable.has_relationship(R_EXTRACTED_FROM)
        assert deobfuscated_observable.redirection == file_observable

    def test_execute_analysis_deobfuscation_stopped(self, root_analysis, tmpdir, monkeypatch):
        # the real -d detection check runs, the deobfuscation does not finish
        monkeypatch.setattr(De4dotAnalyzer, "run_sandboxed_tool", _stopped_on_call(De4dotAnalyzer, 2))

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert analysis.error == "de4dot did not finish"
        assert analysis.deobfuscated is True
        # a stopped tool's output is never kept
        assert not os.path.exists(f"{file_observable.full_path}.deobfuscated")
        assert not analysis.observables

    @pytest.mark.skipif(not os.path.exists("/opt/de4dotEx/de4dot"), reason="de4dot is not installed")
    def test_a_runtime_the_sandbox_keeps_from_starting_is_reported(self, root_analysis, tmpdir, monkeypatch, caplog):
        # CoreCLR does not start without its own /proc/<pid>
        monkeypatch.setattr(dotnet, "DOTNET_READ_DIRS", [])
        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))
        file_observable = root_analysis.add_file_observable(_write_dotnet_sample(tmpdir / "test.exe"))

        assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED

        assert file_observable.get_analysis(De4dotAnalysis) is None
        [record] = [r for r in caplog.records if "in the sandbox" in r.getMessage()]
        assert record.levelno == logging.ERROR
        assert "Failed to create CoreCLR" in record.getMessage()

    def test_de4dot_runs_the_binary_not_the_wrapper(self):
        # the wrapper script execs the binary in /opt/de4dotEx, which the sandbox would not let it read
        assert get_analysis_module_config(ANALYSIS_MODULE_DE4DOT).binary_path == "/opt/de4dotEx/de4dot"


@pytest.mark.unit
class TestIlspyAnalysis:

    def test_init(self):
        analysis = IlspyAnalysis()
        assert analysis.stderr is None
        assert analysis.exit_code is None

    def test_generate_summary_basic(self):
        analysis = IlspyAnalysis()

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis"

    def test_generate_summary_with_exit_code(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 0

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 0"

    def test_generate_summary_with_both(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 1
        analysis.stderr = "error occurred"

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 1: stderr: error occurred"


@pytest.mark.unit
class TestIlspyAnalyzer:

    def test_valid_observable_types(self):
        analyzer = IlspyAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))
        assert analyzer.valid_observable_types == F_FILE

    def test_execute_analysis_not_dotnet_file(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        # create a non-dotnet file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not a dotnet file")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is None

    def test_execute_analysis_successful(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert isinstance(analysis, IlspyAnalysis)

        # check analysis properties
        assert analysis.exit_code == 0

        # check that il file was added as observable
        il_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".il"):
                il_observable = obs
                break

        assert il_observable is not None
        assert il_observable.file_name == "test.exe_ilspy.il"
        with open(il_observable.full_path, "r") as fp:
            assert fp.readline().startswith("// IL code")
        assert il_observable.has_relationship(R_EXTRACTED_FROM)
        assert il_observable.redirection == file_observable

    def test_execute_analysis_with_stderr(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        # ilspy fails on a truncated assembly
        test_file = _write_dotnet_sample(tmpdir / "test.exe", truncate=4096)
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert analysis.exit_code != 0
        assert "BadImageFormatException" in analysis.stderr

    def test_ilspy_writes_its_own_file_and_skips_the_update_check(self, root_analysis, tmpdir, monkeypatch):
        # writing stdout to the .il file was a few bytes per write(), minutes on a slow filesystem, and -o
        # turns on a network update check unless it is disabled
        run = Mock(return_value=None)
        monkeypatch.setattr(IlspyAnalyzer, "run_sandboxed_tool", run)

        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        analyzer.execute_analysis(root_analysis.add_file_observable(test_file))

        argv = run.call_args.args[0]
        assert "--disable-updatecheck" in argv
        assert "-o" in argv

    def test_execute_analysis_stopped(self, root_analysis, tmpdir, monkeypatch, caplog):
        # ilspy does not finish, so it never wrote its file
        monkeypatch.setattr(IlspyAnalyzer, "run_sandboxed_tool", _stopped_on_call(IlspyAnalyzer, 1))

        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert analysis.stderr == "ilspy did not finish"
        # with no .il written there is nothing to add, and no warning about a missing file
        assert not [obs for obs in analysis.observables if obs.file_name.endswith(".il")]
        assert "non-existant file" not in caplog.text

    def test_execute_analysis_duplicate_filename(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        # create the target file that would normally be created by ilspy
        # this simulates a duplicate filename scenario
        target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy.il")
        with open(target_path, "w") as f:
            f.write("existing content")

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None

        # check that a new il file with index was created
        il_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".il"):
                il_observable = obs
                break

        assert il_observable is not None
        # should have _0 in the name due to duplicate
        assert "_ilspy_0.il" in il_observable.file_name
        with open(target_path, "r") as f:
            assert f.read() == "existing content"
        with open(il_observable.full_path, "r") as fp:
            assert fp.readline().startswith("// IL code")

    def test_execute_analysis_max_duplicates(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        # create target file and all duplicates up to the limit
        target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy.il")
        with open(target_path, "w") as f:
            f.write("existing content")

        # create all duplicate files
        for i in range(1024):
            target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy_{i}.il")
            with open(target_path, "w") as f:
                f.write("existing content")

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created analysis because no valid path was available
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is None
