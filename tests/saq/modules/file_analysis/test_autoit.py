import os
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_AUTOIT, F_FILE, AnalysisExecutionResult
from saq.modules.file_analysis.autoit import AutoItAnalysis, AutoItAnalyzer, KEY_STDERR
from tests.saq.test_util import create_test_context


@pytest.mark.unit
class TestAutoItAnalysis:
    
    def test_init(self):
        analysis = AutoItAnalysis()
        assert analysis.stdout is None
        assert analysis.stderr is None
        assert analysis.error is None
        assert analysis.scripts == []
        assert analysis.output_dir is None

    def test_stderr_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with None
        assert analysis.stderr is None
        
        # Test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr
    
    def test_generate_summary_with_error(self):
        analysis = AutoItAnalysis()
        analysis.error = "Decompilation failed"
        
        summary = analysis.generate_summary()
        assert summary == "AutoIt Analysis: Decompilation failed"
    
    def test_generate_summary_no_scripts(self):
        analysis = AutoItAnalysis()
        analysis.error = None
        analysis.scripts = []
        
        summary = analysis.generate_summary()
        assert summary is None
    
    def test_generate_summary_multiple_scripts(self):
        analysis = AutoItAnalysis()
        analysis.error = None
        analysis.scripts = ["script1.au3", "script2.au3", "script3.au3"]
        
        summary = analysis.generate_summary()
        assert summary == "AutoIt Analysis: decompiled script1.au3, script2.au3, script3.au3"


@pytest.mark.integration
class TestAutoItAnalyzer:
    
    def test_valid_observable_types(self):
        analyzer = AutoItAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))
        assert analyzer.valid_observable_types == F_FILE
    
    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir, caplog):
        analyzer = AutoItAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))
        
        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # the observable is a copy in the root's storage: remove that one
        os.remove(file_observable.full_path)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        assert file_observable.get_analysis(AutoItAnalysis) is None
        assert not file_observable.has_tag("autoit")
        assert f"cannot find local file path {file_observable.full_path}" in caplog.text
    
    def test_custom_requirement_not_autoit_file(self, root_analysis, tmpdir):
        analyzer = AutoItAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))

        # create a non-autoit file -- the gating now lives in custom_requirement
        test_file = tmpdir / "test.txt"
        test_file.write("this is not an autoit file")

        file_observable = root_analysis.add_file_observable(str(test_file))

        assert analyzer.custom_requirement(file_observable) is False

    def test_custom_requirement_autoit_file(self, root_analysis, datadir):
        analyzer = AutoItAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))

        file_observable = root_analysis.add_file_observable(str(datadir / "UGtZgHHT.au3"))

        assert analyzer.custom_requirement(file_observable) is True

    def test_custom_requirement_missing_file(self, root_analysis, tmpdir):
        analyzer = AutoItAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))

        test_file = tmpdir / "gone.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # the observable is a copy in the root's storage: remove that one
        os.remove(file_observable.full_path)

        assert analyzer.custom_requirement(file_observable) is False

    def test_execute_analysis_autoit_file(self, root_analysis, datadir, tmpdir, monkeypatch):
        analyzer = AutoItAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOIT))
        
        # copy the sample autoit file to a test location within root analysis storage
        file_observable = root_analysis.add_file_observable(str(datadir / "UGtZgHHT.au3"))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should have added autoit tag
        assert file_observable.has_tag("autoit")
        
        # should have created analysis
        analysis = file_observable.get_analysis(AutoItAnalysis)
        assert analysis is not None
        assert isinstance(analysis, AutoItAnalysis)
        
        # check analysis properties
        assert analysis.stdout
        assert not analysis.stderr
        assert not analysis.error
        assert len(analysis.scripts) == 1
        assert "script_1.au3" in analysis.scripts
        assert analysis.output_dir == file_observable.full_path + ".autoit"
        