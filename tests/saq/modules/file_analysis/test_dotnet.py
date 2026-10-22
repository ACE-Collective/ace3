import os
import pytest
from unittest.mock import Mock, patch
from subprocess import Popen, TimeoutExpired

from saq.configuration.config import get_config, get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_DE4DOT, ANALYSIS_MODULE_ILSPY, F_FILE, AnalysisExecutionResult, R_EXTRACTED_FROM
from saq.modules.file_analysis.dotnet import (
    De4dotAnalysis,
    De4dotAnalyzer,
    IlspyAnalysis,
    IlspyAnalyzer,
    KEY_STDOUT,
    KEY_STDERR,
    KEY_ERROR,
    KEY_DEOBFUSCATED,
    KEY_EXIT_CODE,
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


def _popen_failing_on_call(call_number: int, failure):
    """Runs the real Popen except for the given (1-based) call, which gets the failure instead."""
    calls = []

    def _popen(*args, **kwargs):
        calls.append(args)
        if len(calls) == call_number:
            if isinstance(failure, Exception):
                raise failure
            return failure
        return Popen(*args, **kwargs)

    return _popen


@pytest.mark.unit
class TestDe4dotAnalysis:

    def test_init(self):
        analysis = De4dotAnalysis()
        assert analysis.stdout is None
        assert analysis.stderr is None
        assert analysis.error is None
        assert analysis.deobfuscated is False

    def test_display_name(self):
        analysis = De4dotAnalysis()
        assert analysis.display_name == "De4dot Analysis"

    def test_stdout_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.stdout is None

        # test setter and getter
        test_stdout = "test stdout output"
        analysis.stdout = test_stdout
        assert analysis.stdout == test_stdout
        assert analysis.details[KEY_STDOUT] == test_stdout

    def test_stderr_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.stderr is None

        # test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr

    def test_error_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.error is None

        # test setter and getter
        test_error = "test error message"
        analysis.error = test_error
        assert analysis.error == test_error
        assert analysis.details[KEY_ERROR] == test_error

    def test_deobfuscated_property(self):
        analysis = De4dotAnalysis()

        # test getter with False
        assert analysis.deobfuscated is False

        # test setter and getter
        analysis.deobfuscated = True
        assert analysis.deobfuscated is True
        assert analysis.details[KEY_DEOBFUSCATED] is True

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

    def test_generated_analysis_type(self):
        analyzer = De4dotAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))
        assert analyzer.generated_analysis_type == De4dotAnalysis

    def test_valid_observable_types(self):
        analyzer = De4dotAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))
        assert analyzer.valid_observable_types == F_FILE

    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir):
        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

    def test_execute_analysis_not_dotnet_file(self, root_analysis, tmpdir):
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

    @patch("saq.modules.file_analysis.dotnet.Popen")
    def test_execute_analysis_detection_timeout(self, mock_popen, root_analysis, tmpdir):
        # mock the -d detection check to timeout
        mock_process = Mock()
        mock_process.communicate.side_effect = [TimeoutExpired(cmd="de4dot", timeout=10), (b"", b"")]
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_process.kill.assert_called_once()
        assert file_observable.get_analysis(De4dotAnalysis) is None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    def test_execute_analysis_detection_exception(self, mock_popen, root_analysis, tmpdir):
        # mock the -d detection check to raise an exception
        mock_popen.side_effect = Exception("Test exception")

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None

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

    def test_execute_analysis_deobfuscation_timeout(self, root_analysis, tmpdir, monkeypatch):
        # the real -d detection check runs, the deobfuscation process times out
        mock_deobfuscate_process = Mock()
        mock_deobfuscate_process.communicate.side_effect = [TimeoutExpired(cmd="de4dot", timeout=10), (b"", b"")]
        mock_deobfuscate_process.kill = Mock()
        monkeypatch.setattr("saq.modules.file_analysis.dotnet.Popen", _popen_failing_on_call(2, mock_deobfuscate_process))

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_deobfuscate_process.kill.assert_called_once()

        # should have created analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert analysis.deobfuscated is True

    def test_execute_analysis_deobfuscation_exception(self, root_analysis, tmpdir, monkeypatch):
        # the real -d detection check runs, the deobfuscation process raises
        monkeypatch.setattr("saq.modules.file_analysis.dotnet.Popen", _popen_failing_on_call(2, Exception("Test exception")))

        analyzer = De4dotAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_DE4DOT))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis with error
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert analysis.error == "Test exception"
        assert analysis.deobfuscated is True


@pytest.mark.unit
class TestIlspyAnalysis:

    def test_init(self):
        analysis = IlspyAnalysis()
        assert analysis.stderr is None
        assert analysis.exit_code is None

    def test_exit_code_property(self):
        analysis = IlspyAnalysis()

        # test getter with None
        assert analysis.exit_code is None

        # test setter and getter
        analysis.exit_code = 0
        assert analysis.exit_code == 0
        assert analysis.details[KEY_EXIT_CODE] == 0

    def test_stderr_property(self):
        analysis = IlspyAnalysis()

        # test getter with None
        assert analysis.stderr is None

        # test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr

    def test_generate_summary_basic(self):
        analysis = IlspyAnalysis()

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis"

    def test_generate_summary_with_exit_code(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 0

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 0"

    def test_generate_summary_with_stderr(self):
        analysis = IlspyAnalysis()
        analysis.stderr = "some error message"

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: stderr: some error message"

    def test_generate_summary_with_both(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 1
        analysis.stderr = "error occurred"

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 1: stderr: error occurred"


@pytest.mark.unit
class TestIlspyAnalyzer:

    def test_generated_analysis_type(self):
        analyzer = IlspyAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))
        assert analyzer.generated_analysis_type == IlspyAnalysis

    def test_valid_observable_types(self):
        analyzer = IlspyAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))
        assert analyzer.valid_observable_types == F_FILE

    def test_binary_path_property(self):
        analyzer = IlspyAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))
        # just verify the property returns something (it reads from config)
        assert analyzer.binary_path is not None
        assert isinstance(analyzer.binary_path, str)

    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

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

    @patch("saq.modules.file_analysis.dotnet.Popen")
    def test_execute_analysis_timeout(self, mock_popen, root_analysis, tmpdir):
        # mock the ilspy process to timeout on first communicate, then return on second
        mock_process = Mock()
        mock_process.communicate.side_effect = [
            TimeoutExpired(cmd="ilspy", timeout=10),
            (None, b"")
        ]
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process

        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_process.kill.assert_called_once()

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    def test_execute_analysis_exception(self, mock_popen, root_analysis, tmpdir):
        # mock the ilspy process to raise an exception
        mock_popen.side_effect = Exception("Test exception")

        analyzer = IlspyAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ILSPY))

        test_file = _write_dotnet_sample(tmpdir / "test.exe")
        file_observable = root_analysis.add_file_observable(test_file)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis with error in stderr
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert analysis.stderr == "Test exception"

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
