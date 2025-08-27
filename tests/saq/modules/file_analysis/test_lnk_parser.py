import os
import pytest

from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules.file_analysis.lnk_parser import LnkParseAnalysis, LnkParseAnalyzer, KEY_ERROR, KEY_INFO
from saq.observables.file import FileObservable
from tests.saq.test_util import create_test_context


@pytest.mark.unit
class TestLnkParseAnalysis:
    
    def test_init(self):
        analysis = LnkParseAnalysis()
        assert analysis.error is None
        assert analysis.info == {}

    def test_display_name(self):
        analysis = LnkParseAnalysis()
        assert analysis.display_name == "LnkParse Analysis"
    
    def test_error_property(self):
        analysis = LnkParseAnalysis()
        
        # Test getter with None
        assert analysis.error is None
        
        # Test setter and getter
        test_error = "test error message"
        analysis.error = test_error
        assert analysis.error == test_error
        assert analysis.details[KEY_ERROR] == test_error
    
    def test_info_property(self):
        analysis = LnkParseAnalysis()
        
        # Test getter with empty dict
        assert analysis.info == {}
        
        # Test setter and getter
        test_info = {"data": {"command_line_arguments": "test args"}}
        analysis.info = test_info
        assert analysis.info == test_info
        assert analysis.details[KEY_INFO] == test_info
    
    def test_command_line_arguments_property(self):
        analysis = LnkParseAnalysis()
        
        # Test getter with no info
        assert analysis.command_line_arguments is None
        
        # Test with info but no data
        analysis.info = {}
        assert analysis.command_line_arguments is None
        
        # Test with data but no command_line_arguments
        analysis.info = {"data": {}}
        assert analysis.command_line_arguments is None
        
        # Test with command_line_arguments
        test_cmd_args = "test command line arguments"
        analysis.info = {"data": {"command_line_arguments": test_cmd_args}}
        assert analysis.command_line_arguments == test_cmd_args
    
    def test_icon_location_property(self):
        analysis = LnkParseAnalysis()
        
        # Test getter with no info
        assert analysis.icon_location is None
        
        # Test with info but no data
        analysis.info = {}
        assert analysis.icon_location is None
        
        # Test with data but no icon_location
        analysis.info = {"data": {}}
        assert analysis.icon_location is None
        
        # Test with icon_location
        test_icon_location = "test icon location"
        analysis.info = {"data": {"icon_location": test_icon_location}}
        assert analysis.icon_location == test_icon_location
    
    def test_working_directory_property(self):
        analysis = LnkParseAnalysis()
        
        # Test getter with no info
        assert analysis.working_directory is None
        
        # Test with info but no data
        analysis.info = {}
        assert analysis.working_directory is None
        
        # Test with data but no working_directory
        analysis.info = {"data": {}}
        assert analysis.working_directory is None
        
        # Test with working_directory
        test_working_directory = "test working directory"
        analysis.info = {"data": {"working_directory": test_working_directory}}
        assert analysis.working_directory == test_working_directory
    
    def test_generate_summary_with_error(self):
        analysis = LnkParseAnalysis()
        analysis.error = "Parse failed"
        
        summary = analysis.generate_summary()
        assert summary == "LnkParse Analysis: Parse failed"
    
    def test_generate_summary_no_info(self):
        analysis = LnkParseAnalysis()
        analysis.error = None
        analysis.info = {}
        
        summary = analysis.generate_summary()
        assert summary is None
    
    def test_generate_summary_single_field(self):
        analysis = LnkParseAnalysis()
        analysis.error = None
        analysis.info = {"data": {"command_line_arguments": "test cmd"}}
        
        summary = analysis.generate_summary()
        assert summary == "LnkParse Analysis: command line arguments: (test cmd)"
    
    def test_generate_summary_multiple_fields(self):
        analysis = LnkParseAnalysis()
        analysis.error = None
        analysis.info = {
            "data": {
                "command_line_arguments": "test cmd",
                "icon_location": "test icon",
                "working_directory": "test dir"
            }
        }
        
        summary = analysis.generate_summary()
        expected = "LnkParse Analysis: command line arguments: (test cmd), icon location: (test icon), working directory: (test dir)"
        assert summary == expected
    
    def test_generate_summary_partial_fields(self):
        analysis = LnkParseAnalysis()
        analysis.error = None
        analysis.info = {
            "data": {
                "command_line_arguments": "test cmd",
                "working_directory": "test dir"
            }
        }
        
        summary = analysis.generate_summary()
        expected = "LnkParse Analysis: command line arguments: (test cmd), working directory: (test dir)"
        assert summary == expected


@pytest.mark.integration
class TestLnkParseAnalyzer:
    
    def test_generated_analysis_type(self):
        analyzer = LnkParseAnalyzer(context=create_test_context())
        assert analyzer.generated_analysis_type == LnkParseAnalysis
    
    def test_valid_observable_types(self):
        analyzer = LnkParseAnalyzer(context=create_test_context())
        assert analyzer.valid_observable_types == F_FILE
    
    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir):
        analyzer = LnkParseAnalyzer(context=create_test_context(root=root_analysis))
        
        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.lnk"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
    
    def test_execute_analysis_not_lnk_file(self, root_analysis, tmpdir):
        analyzer = LnkParseAnalyzer(context=create_test_context(root=root_analysis))
        
        # create a non-lnk file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not a lnk file")
        
        file_observable = root_analysis.add_file_observable(str(test_file))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should not have created any analysis
        analysis = file_observable.get_analysis(LnkParseAnalysis)
        assert analysis is None
        
        # should not have added lnk tag
        assert not file_observable.has_tag("lnk")
    
    def test_execute_analysis_lnk_file(self, root_analysis, datadir):
        analyzer = LnkParseAnalyzer(context=create_test_context(root=root_analysis))
        
        # use the sample lnk file
        file_observable = root_analysis.add_file_observable(str(datadir / "INVOICE#BUSAPOMKDS03.lnk"))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should have added lnk tag
        assert file_observable.has_tag("lnk")
        
        # should have created analysis
        analysis = file_observable.get_analysis(LnkParseAnalysis)
        assert analysis is not None
        assert isinstance(analysis, LnkParseAnalysis)
        
        # check that analysis has parsed info
        assert analysis.info
        assert isinstance(analysis.info, dict)
        assert "data" in analysis.info
        assert not analysis.error
        
        # check that a JSON file was created
        json_file_path = file_observable.full_path + ".lnkparser.json"
        assert os.path.exists(json_file_path)
        
        # verify the JSON file was added as an observable to the analysis
        json_observables = [obs for obs in analysis.observables if obs.file_name.endswith(".lnkparser.json")]
        assert len(json_observables) == 1
    
    def test_execute_analysis_lnk_file_parsing_error(self, root_analysis, tmpdir):
        analyzer = LnkParseAnalyzer(context=create_test_context(root=root_analysis))
        
        # create a fake lnk file that will cause parsing error
        test_file = tmpdir / "fake.lnk"
        # write lnk file header but with very short/incomplete content to trigger parsing error
        with open(str(test_file), "wb") as f:
            f.write(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00F")  # too short for valid lnk
        
        file_observable = root_analysis.add_file_observable(str(test_file))
        
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should have added lnk tag
        assert file_observable.has_tag("lnk")
        
        # should have created analysis with error
        analysis = file_observable.get_analysis(LnkParseAnalysis)
        assert analysis is not None
        assert isinstance(analysis, LnkParseAnalysis)
        assert analysis.error is not None
        assert isinstance(analysis.error, str)