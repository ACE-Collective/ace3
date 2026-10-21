import subprocess
import uuid

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, AnalysisExecutionResult, F_FILE
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.cve import CVE_2021_30657_Analysis, CVE_2021_30657_Analyzer
from saq.modules.file_analysis.dmg import DMGAnalysis
from tests.saq.helpers import create_root_analysis
from tests.saq.test_util import create_test_context

MACOS_MEMBER = "Installer/yWnBJLaF/1302.app/Contents/MacOS/1302"


def _create_img(tmpdir, member_content: bytes) -> str:
    """Builds a 7z archive named like the .img the DMG analyzer extracts, holding MACOS_MEMBER."""
    build_dir = tmpdir.mkdir("img_build")
    member = build_dir.join(MACOS_MEMBER)
    member.dirpath().ensure(dir=True)
    member.write_binary(member_content)
    # the root's storage dir is shared by the tests on this worker, so the name must be unique
    img_path = str(tmpdir.join(f"{uuid.uuid4()}.img"))
    subprocess.run(["7z", "a", "-t7z", img_path, "Installer"], cwd=str(build_dir), check=True, capture_output=True)
    return img_path


def _add_dmg_analysis(root, tmpdir, observable, file_list: list[str]):
    redirection_file = tmpdir.join("original.dmg")
    redirection_file.write("dmg content")
    redirection_observable = root.add_file_observable(str(redirection_file))
    dmg_analysis = DMGAnalysis()
    dmg_analysis.details["file_list"] = file_list
    redirection_observable.add_analysis(dmg_analysis)
    observable.redirection = redirection_observable
    root.save()


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
        analyzer = CVE_2021_30657_Analyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER))
        assert analyzer.generated_analysis_type == CVE_2021_30657_Analysis

    @pytest.mark.unit
    def test_valid_observable_types(self, test_context):
        analyzer = CVE_2021_30657_Analyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER))
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
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
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
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
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
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
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
        
        observable.redirection = redirection_observable
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        assert observable.get_and_load_analysis(CVE_2021_30657_Analysis) is None

    @pytest.mark.unit
    def test_execute_analysis_with_script_files(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        observable = root.add_file_observable(_create_img(tmpdir, b"#!/bin/bash\necho 'malicious script'\n"))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        _add_dmg_analysis(root, tmpdir, observable, [
            f"2021-04-06 23:33:06 .....        59039        61440  {MACOS_MEMBER}",
            "2021-04-06 23:33:06 .....        12345        12345  some/other/file.txt"
        ])
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # get the analysis and verify it found the script file
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert list(analysis.suspect_files.values()) == ["text/x-shellscript"]
        
        # verify the script file was tagged and has detection point
        script_observables = [obs for obs in analysis.observables if obs.type == F_FILE]
        assert len(script_observables) == 1
        script_observable = script_observables[0]
        assert script_observable.file_name == "1302"
        assert script_observable.has_tag("CVE-2021-30657")
        assert script_observable.has_detection_points()
        # the detection point message is embedded in the implementation, so we can just check it exists

    @pytest.mark.unit
    def test_execute_analysis_extraction_failure(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        observable = root.add_file_observable(_create_img(tmpdir, b"#!/bin/bash\necho 'malicious script'\n"))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        # the listed file is not in the archive, so 7z extracts nothing
        _add_dmg_analysis(root, tmpdir, observable, [
            "2021-04-06 23:33:06 .....        59039        61440  Installer/yWnBJLaF/1302.app/Contents/MacOS/missing"
        ])
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should complete but find no suspect files due to extraction failure
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert len(analysis.suspect_files) == 0

    @pytest.mark.unit
    def test_execute_analysis_non_script_file(self, tmpdir, test_context):
        root = create_root_analysis(analysis_mode='test_single')
        root.initialize_storage()
        
        observable = root.add_file_observable(_create_img(tmpdir, b"\x7fELF\x02\x01\x01" + b"\x00" * 64))
        observable.add_tag("macos")
        observable.add_tag("dmg")
        
        _add_dmg_analysis(root, tmpdir, observable, [
            f"2021-04-06 23:33:06 .....        59039        61440  {MACOS_MEMBER}"
        ])
        
        analyzer = AnalysisModuleAdapter(CVE_2021_30657_Analyzer(
            context=create_test_context(root=root),
            config=get_analysis_module_config(ANALYSIS_MODULE_CVE_2021_30657_ANALYZER)))
        result = analyzer.execute_analysis(observable)
        
        assert result == AnalysisExecutionResult.COMPLETED
        
        # should complete but find no suspect files since the file is not a script
        analysis = observable.get_and_load_analysis(CVE_2021_30657_Analysis)
        assert analysis is not None
        assert len(analysis.suspect_files) == 0
        assert not analysis.observables
