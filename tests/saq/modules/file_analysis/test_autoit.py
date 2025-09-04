import os
import shutil
import pytest

from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules.file_analysis.autoit import AutoItAnalysis, AutoItAnalyzer, KEY_STDOUT, KEY_STDERR, KEY_ERROR, KEY_SCRIPTS, KEY_OUTPUT_DIR
from saq.observables.file import FileObservable
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

    def test_display_name(self):
        analysis = AutoItAnalysis()
        assert analysis.display_name == "AutoIt Analysis"
    
    def test_stdout_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with None
        assert analysis.stdout is None
        
        # Test setter and getter
        test_stdout = "test stdout output"
        analysis.stdout = test_stdout
        assert analysis.stdout == test_stdout
        assert analysis.details[KEY_STDOUT] == test_stdout
    
    def test_stderr_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with None
        assert analysis.stderr is None
        
        # Test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr
    
    def test_error_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with None
        assert analysis.error is None
        
        # Test setter and getter
        test_error = "test error message"
        analysis.error = test_error
        assert analysis.error == test_error
        assert analysis.details[KEY_ERROR] == test_error
    
    def test_scripts_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with empty list
        assert analysis.scripts == []
        
        # Test setter and getter
        test_scripts = ["script1.au3", "script2.au3"]
        analysis.scripts = test_scripts
        assert analysis.scripts == test_scripts
        assert analysis.details[KEY_SCRIPTS] == test_scripts
    
    def test_output_dir_property(self):
        analysis = AutoItAnalysis()
        
        # Test getter with None
        assert analysis.output_dir is None
        
        # Test setter and getter
        test_output_dir = "/path/to/output"
        analysis.output_dir = test_output_dir
        assert analysis.output_dir == test_output_dir
        assert analysis.details[KEY_OUTPUT_DIR] == test_output_dir
    
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
    
    def test_generate_summary_single_script(self):
        analysis = AutoItAnalysis()
        analysis.error = None
        analysis.scripts = ["script.au3"]
        
        summary = analysis.generate_summary()
        assert summary == "AutoIt Analysis: decompiled script.au3"
    
    def test_generate_summary_multiple_scripts(self):
        analysis = AutoItAnalysis()
        analysis.error = None
        analysis.scripts = ["script1.au3", "script2.au3", "script3.au3"]
        
        summary = analysis.generate_summary()
        assert summary == "AutoIt Analysis: decompiled script1.au3, script2.au3, script3.au3"


@pytest.mark.integration
class TestAutoItAnalyzer:
    
    def test_generated_analysis_type(self):
        analyzer = AutoItAnalyzer(context=create_test_context())
        assert analyzer.generated_analysis_type == AutoItAnalysis
    
    def test_valid_observable_types(self):
        analyzer = AutoItAnalyzer(context=create_test_context())
        assert analyzer.valid_observable_types == F_FILE
    
    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir):
        analyzer = AutoItAnalyzer(context=create_test_context(root=root_analysis))
        
        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
    
    def test_execute_analysis_not_autoit_file(self, root_analysis, tmpdir):
        analyzer = AutoItAnalyzer(context=create_test_context(root=root_analysis))
        
        # create a non-autoit file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not an autoit file")
        
        file_observable = root_analysis.add_file_observable(str(test_file))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should not have created any analysis
        analysis = file_observable.get_analysis(AutoItAnalysis)
        assert analysis is None
        
        # should not have added autoit tag
        assert not file_observable.has_tag("autoit")
    
    def test_execute_analysis_autoit_file(self, root_analysis, datadir, tmpdir, monkeypatch):
        analyzer = AutoItAnalyzer(context=create_test_context(root=root_analysis))
        
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
        