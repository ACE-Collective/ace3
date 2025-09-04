import os
from unittest.mock import Mock

import pytest

from saq.constants import AnalysisExecutionResult, F_FILE
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.cve import CVE_2021_30657_Analysis, CVE_2021_30657_Analyzer
from saq.modules.file_analysis.dmg import DMGAnalysis
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context


class TestCVE_2021_30657_Analysis:
    @pytest.mark.unit
    def test_init(self):
        analysis = CVE_2021_30657_Analysis()
        assert analysis.details["suspect_files"] == {}

    @pytest.mark.unit
    def test_display_name(self):
        analysis = CVE_2021_30657_Analysis()
        assert analysis.display_name == "CVE-2021-30657 Analysis"

    @pytest.mark.unit
    def test_suspect_files_property(self):
        analysis = CVE_2021_30657_Analysis()
        test_files = {"test_file.sh": "text/x-shellscript"}
        
        analysis.suspect_files = test_files
        assert analysis.suspect_files == test_files

    @pytest.mark.unit
    def test_generate_summary_empty(self):
        analysis = CVE_2021_30657_Analysis()
        assert analysis.generate_summary() is None

    @pytest.mark.unit
    def test_generate_summary_with_files(self):
        analysis = CVE_2021_30657_Analysis()
        analysis.suspect_files = {
            "malicious.sh": "text/x-shellscript",
            "evil.py": "text/x-python"
        }
        summary = analysis.generate_summary()
        assert "CVE-2021-30657 Analysis:" in summary
        assert "malicious.sh" in summary or "evil.py" in summary


class TestCVE_2021_30657_Analyzer:
    @pytest.mark.unit
    def test_generated_analysis_type(self, test_context):
        analyzer = CVE_2021_30657_Analyzer(context=test_context)
        assert analyzer.generated_analysis_type == CVE_2021_30657_Analysis

    @pytest.mark.unit
    def test_valid_observable_types(self, test_context):
        analyzer = CVE_2021_30657_Analyzer(context=test_context)
        assert analyzer.valid_observable_types == F_FILE

    @pytest.mark.unit
    def test_execute_analysis_missing_file(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file that we'll delete to simulate missing file
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        
        # now remove the file to simulate it being missing
        test_file.remove()
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED

    @pytest.mark.unit
    def test_execute_analysis_wrong_extension(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file without .img extension
        test_file = tmpdir.join("test.txt")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED

    @pytest.mark.unit
    def test_execute_analysis_missing_tags(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file with .img extension but no tags
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED

    @pytest.mark.unit
    def test_execute_analysis_no_dmg_analysis(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file with .img extension and proper tags
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        # create a redirection observable but with no DMG analysis
        redirection_file = tmpdir.join("original.dmg")
        redirection_file.write("dmg content")
        redirection_observable = root.add_file_observable(str(redirection_file))
        
        # mock the redirection to point to our redirection observable
        observable.redirection = redirection_observable
        
        # mock the get_and_load_analysis method to return None (no DMG analysis)
        redirection_observable.get_and_load_analysis = Mock(return_value=None)
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED

    @pytest.mark.unit
    def test_execute_analysis_with_script_files(self, tmpdir, monkeypatch, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file with .img extension and proper tags
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        # mock DMG analysis with file list containing MacOS files
        mock_dmg_analysis = Mock(spec=DMGAnalysis)
        mock_dmg_analysis.details = {
            "file_list": [
                "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302",
                "2021-04-06 23:33:06 .....        12345        12345  some/other/file.txt"
            ]
        }
        
        # create a redirection observable that will have the DMG analysis
        redirection_file = tmpdir.join("original.dmg")
        redirection_file.write("dmg content")
        redirection_observable = root.add_file_observable(str(redirection_file))
        
        # mock the redirection to point to our redirection observable
        observable.redirection = redirection_observable
        
        # mock the get_and_load_analysis method on the redirection observable
        redirection_observable.get_and_load_analysis = Mock(return_value=mock_dmg_analysis)
        
        # create a temporary script file that will be "extracted"
        script_content = "#!/bin/bash\necho 'malicious script'"
        script_file = tmpdir.join("extracted_script")
        script_file.write(script_content)
        
        # mock 7z extraction - simulate successful extraction
        def mock_popen_7z(args, **kwargs):
            if "7z" in args and "x" in args:
                # simulate extracting the file
                extracted_path = os.path.join(args[2][2:], args[4])  # -oTEMP_DIR, file_path
                os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                with open(extracted_path, 'w') as f:
                    f.write(script_content)
                mock_process = Mock()
                mock_process.communicate.return_value = (b"", b"")
                return mock_process
            return Mock()
        
        # mock file command to return script mime type
        def mock_popen_file(args, **kwargs):
            if "file" in args and "--mime-type" in args:
                mock_process = Mock()
                mock_process.communicate.return_value = ("text/x-shellscript", "")
                return mock_process
            return Mock()
        
        # apply patches for both 7z and file commands
        def mock_popen(args, **kwargs):
            if "7z" in args:
                return mock_popen_7z(args, **kwargs)
            elif "file" in args:
                return mock_popen_file(args, **kwargs)
            return Mock()
        
        monkeypatch.setattr("saq.modules.file_analysis.cve.Popen", mock_popen)
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # get the analysis and verify it found the script file
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert len(analysis.suspect_files) == 1
        
        # verify the script file was tagged and has detection point
        script_observables = [obs for obs in analysis.observables if obs.type == F_FILE]
        assert len(script_observables) == 1
        script_observable = script_observables[0]
        assert script_observable.has_tag("CVE-2021-30657")
        assert script_observable.has_detection_points()
        # the detection point message is embedded in the implementation, so we can just check it exists

    @pytest.mark.unit
    def test_execute_analysis_extraction_failure(self, tmpdir, monkeypatch, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file with .img extension and proper tags
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        # mock DMG analysis with file list containing MacOS files
        mock_dmg_analysis = Mock(spec=DMGAnalysis)
        mock_dmg_analysis.details = {
            "file_list": [
                "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302"
            ]
        }
        
        # create a redirection observable that will have the DMG analysis
        redirection_file = tmpdir.join("original.dmg")
        redirection_file.write("dmg content")
        redirection_observable = root.add_file_observable(str(redirection_file))
        
        # mock the redirection to point to our redirection observable
        observable.redirection = redirection_observable
        
        # mock the get_and_load_analysis method on the redirection observable
        redirection_observable.get_and_load_analysis = Mock(return_value=mock_dmg_analysis)
        
        # mock 7z extraction to fail
        def mock_popen(args, **kwargs):
            if "7z" in args and "x" in args:
                mock_process = Mock()
                mock_process.communicate.return_value = (b"extraction failed", b"error")
                return mock_process
            return Mock()
        
        monkeypatch.setattr("saq.modules.file_analysis.cve.Popen", mock_popen)
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should complete but find no suspect files due to extraction failure
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert len(analysis.suspect_files) == 0

    @pytest.mark.unit
    def test_execute_analysis_non_script_file(self, tmpdir, monkeypatch, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        # create a test file with .img extension and proper tags
        test_file = tmpdir.join("test.img")
        test_file.write("test content")
        
        observable = root.add_file_observable(str(test_file))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        # mock DMG analysis
        mock_dmg_analysis = Mock(spec=DMGAnalysis)
        mock_dmg_analysis.details = {
            "file_list": [
                "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/1302"
            ]
        }
        
        # create a redirection observable that will have the DMG analysis
        redirection_file = tmpdir.join("original.dmg")
        redirection_file.write("dmg content")
        redirection_observable = root.add_file_observable(str(redirection_file))
        
        # mock the redirection to point to our redirection observable
        observable.redirection = redirection_observable
        
        # mock the get_and_load_analysis method on the redirection observable
        redirection_observable.get_and_load_analysis = Mock(return_value=mock_dmg_analysis)
        
        # create a temporary binary file that will be "extracted"
        binary_content = b"\\x7fELF binary content"
        binary_file = tmpdir.join("extracted_binary")
        binary_file.write_binary(binary_content)
        
        # mock 7z extraction
        def mock_popen_7z(args, **kwargs):
            if "7z" in args and "x" in args:
                extracted_path = os.path.join(args[2][2:], args[4])
                os.makedirs(os.path.dirname(extracted_path), exist_ok=True)
                with open(extracted_path, 'wb') as f:
                    f.write(binary_content)
                mock_process = Mock()
                mock_process.communicate.return_value = (b"", b"")
                return mock_process
            return Mock()
        
        # mock file command to return binary mime type (not script)
        def mock_popen_file(args, **kwargs):
            if "file" in args and "--mime-type" in args:
                mock_process = Mock()
                mock_process.communicate.return_value = ("application/x-executable", "")
                return mock_process
            return Mock()
        
        def mock_popen(args, **kwargs):
            if "7z" in args:
                return mock_popen_7z(args, **kwargs)
            elif "file" in args:
                return mock_popen_file(args, **kwargs)
            return Mock()
        
        monkeypatch.setattr("saq.modules.file_analysis.cve.Popen", mock_popen)
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(context=create_test_context(root=root)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should complete but find no suspect files since the file is not a script
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert len(analysis.suspect_files) == 0