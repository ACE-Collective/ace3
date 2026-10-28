import hashlib
import logging
import os
import shutil
import signal
import stat
import uuid
import zipfile
from glob import glob

import psutil
import pytest

from saq.analysis.root import load_root
from saq.constants import ANALYSIS_MODULE_ARCHIVE, ANALYSIS_MODULE_FILE_TYPE, F_FILE, AnalysisExecutionResult
from saq.configuration.config import get_analysis_module_config
from saq.crash_report import get_crash_report_root_dir
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_data_dir
from saq.modules.file_analysis.archive import ArchiveAnalysis, ArchiveAnalyzer, order_archive_file_list
from saq.modules.file_analysis.file_type import FileTypeAnalysis
from saq.util.uuid import get_storage_dir
from tests.saq.test_util import create_test_context


class TestOrderArchiveFileList:
    
    @pytest.mark.unit
    @pytest.mark.parametrize("file_list,expected", [
        # edge cases
        ([], []),
        (["file1.txt"], ["file1.txt"]),
        (["file1.txt", "file2.txt"], ["file1.txt", "file2.txt"]),
        
        # sorting by priority
        (["file1.exe", "file2.txt", "file3.pdf"], ["file1.exe", "file3.pdf", "file2.txt"]),
        
        # attack extensions (priority 0) - highest priority
        (["file1.txt", "file2.lnk", "file3.exe", "file4.one", "file5.pdf"], 
         ["file2.lnk", "file4.one", "file3.exe", "file5.pdf", "file1.txt"]),
        (["file1.jnlp", "file2.iso", "file3.img", "file4.vhd", "file5.txt"],
         ["file1.jnlp", "file2.iso", "file3.img", "file4.vhd", "file5.txt"]),
        (["file1.vhdx", "file2.vmdk", "file3.msi", "file4.hta", "file5.txt"],
         ["file1.vhdx", "file2.vmdk", "file3.msi", "file4.hta", "file5.txt"]),
        (["file1.chm", "file2.cpl", "file3.scr", "file4.txt"],
         ["file1.chm", "file2.cpl", "file3.scr", "file4.txt"]),
        
        # executable extensions (priority 1)
        (["file1.txt", "file2.exe", "file3.dll", "file4.com", "file5.pdf"],
         ["file2.exe", "file3.dll", "file4.com", "file5.pdf", "file1.txt"]),
        (["file1.bat", "file2.cmd", "file3.jar", "file4.ps1", "file5.txt"],
         ["file1.bat", "file2.cmd", "file3.jar", "file4.ps1", "file5.txt"]),
        (["file1.sys", "file2.drv", "file3.txt"],
         ["file1.sys", "file2.drv", "file3.txt"]),
        
        # script extensions (priority 2)
        (["file1.txt", "file2.js", "file3.jse", "file4.vbs", "file5.pdf"],
         ["file2.js", "file3.jse", "file4.vbs", "file5.pdf", "file1.txt"]),
        (["file1.vbe", "file2.wsf", "file3.wsh", "file4.psm1", "file5.txt"],
         ["file1.vbe", "file2.wsf", "file3.wsh", "file4.psm1", "file5.txt"]),
        (["file1.sh", "file2.py", "file3.rb", "file4.pl", "file5.txt"],
         ["file1.sh", "file2.py", "file3.rb", "file4.pl", "file5.txt"]),
        (["file1.php", "file2.asp", "file3.aspx", "file4.txt"],
         ["file1.php", "file2.asp", "file3.aspx", "file4.txt"]),
        
        # office/pdf extensions (priority 3)
        (["file1.txt", "file2.doc", "file3.docx", "file4.xls", "file5.log"],
         ["file2.doc", "file3.docx", "file4.xls", "file1.txt", "file5.log"]),
        (["file1.xlsx", "file2.ppt", "file3.pptx", "file4.rtf", "file5.txt"],
         ["file1.xlsx", "file2.ppt", "file3.pptx", "file4.rtf", "file5.txt"]),
        (["file1.odt", "file2.ods", "file3.odp", "file4.pdf", "file5.txt"],
         ["file1.odt", "file2.ods", "file3.odp", "file4.pdf", "file5.txt"]),
        (["file1.mht", "file2.mhtml", "file3.xml", "file4.txt"],
         ["file1.mht", "file2.mhtml", "file3.xml", "file4.txt"]),
        
        # other extensions (priority 4) - lowest priority
        (["file1.txt", "file2.log", "file3.dat", "file4.tmp"],
         ["file1.txt", "file2.log", "file3.dat", "file4.tmp"]),
        
        # mixed priorities - testing sorting behavior
        (["file1.txt", "file2.exe", "file3.lnk", "file4.js", "file5.pdf"],
         ["file3.lnk", "file2.exe", "file4.js", "file5.pdf", "file1.txt"]),
        (["file1.pdf", "file2.scr", "file3.vbs", "file4.dll", "file5.doc"],
         ["file2.scr", "file4.dll", "file3.vbs", "file1.pdf", "file5.doc"]),
        
        # case insensitive handling
        (["file1.TXT", "file2.EXE", "file3.LNK", "file4.JS"],
         ["file3.LNK", "file2.EXE", "file4.JS", "file1.TXT"]),
        (["FILE1.PDF", "FILE2.SCR", "FILE3.VBS"],
         ["FILE2.SCR", "FILE3.VBS", "FILE1.PDF"]),
        
        # preserve order within same priority
        (["file1.txt", "file2.log", "file3.dat"],
         ["file1.txt", "file2.log", "file3.dat"]),
        (["file1.exe", "file2.dll", "file3.com"],
         ["file1.exe", "file2.dll", "file3.com"]),
        
        # complex mixed scenario
        (["readme.txt", "setup.exe", "malware.lnk", "script.js", "doc.pdf", 
          "data.log", "virus.scr", "code.py", "info.xml"],
         ["malware.lnk", "virus.scr", "setup.exe", "script.js", "code.py", "doc.pdf", "info.xml", "readme.txt", "data.log"]),
        
        # all same priority
        (["file1.exe", "file2.dll", "file3.com", "file4.bat", "file5.jar"],
         ["file1.exe", "file2.dll", "file3.com", "file4.bat", "file5.jar"]),
    ])
    def test_order_archive_file_list(self, file_list, expected):
        result = order_archive_file_list(file_list)
        assert result == expected
    
    @pytest.mark.unit
    def test_order_archive_file_list_preserves_order_within_priority(self):
        # test that files with same priority maintain their original order
        file_list = ["first.txt", "second.log", "third.dat", "fourth.tmp"]
        result = order_archive_file_list(file_list)
        assert result == ["first.txt", "second.log", "third.dat", "fourth.tmp"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_all_extensions_covered(self):
        # test that all extension categories are properly handled
        file_list = [
            "attack.lnk",     # priority 0
            "exec.exe",       # priority 1  
            "script.js",      # priority 2
            "office.doc",     # priority 3
            "other.txt"       # priority 4
        ]
        result = order_archive_file_list(file_list)
        assert result == ["attack.lnk", "exec.exe", "script.js", "office.doc", "other.txt"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_duplicate_extensions(self):
        # test files with same extensions maintain order
        file_list = ["first.exe", "second.exe", "third.exe", "fourth.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["first.exe", "second.exe", "third.exe", "fourth.txt"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_msi_in_both_categories(self):
        # .msi appears in both attack_exts and executable_exts
        # it should be treated as attack_exts (priority 0) since that's checked first
        file_list = ["file1.msi", "file2.exe", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file1.msi", "file2.exe", "file3.txt"]
        
        # verify msi gets priority 0 treatment
        file_list = ["file1.exe", "file2.msi", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file2.msi", "file1.exe", "file3.txt"]  # msi should come before exe
    
    @pytest.mark.unit
    @pytest.mark.parametrize("file_type_result", [False, None])
    def test_execute_analysis_no_file_type_analysis(self, file_type_result, root_analysis, tmpdir):
        # file type analysis is a declared dependency, but get_and_load_analysis can still
        # return the ``False`` sentinel (analysis ran but produced nothing / was skipped) or
        # None (dependency soft-skipped / disabled). The guard must treat both as "no
        # analysis" and return COMPLETED rather than dereferencing a bool.
        analyzer = ArchiveAnalyzer(
            context=create_test_context(root=root_analysis),
            config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE))

        test_file = tmpdir / "sample.bin"
        test_file.write("not really an archive")
        file_observable = root_analysis.add_file_observable(str(test_file))

        # False sentinel => the dependency ran but produced no analysis; None => absent
        if file_type_result is False:
            file_observable.add_no_analysis(FileTypeAnalysis)

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

    @pytest.mark.unit
    def test_order_archive_file_list_ps1_in_both_categories(self):
        # .ps1 appears in both executable_exts and script_exts
        # it should be treated as executable_exts (priority 1) since that's checked first
        file_list = ["file1.ps1", "file2.js", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file1.ps1", "file2.js", "file3.txt"]
        
        # verify ps1 gets priority 1 treatment
        file_list = ["file1.js", "file2.ps1", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file2.ps1", "file1.js", "file3.txt"]  # ps1 should come before js


def _enum_crash_reports() -> set[str]:
    root_dir = get_crash_report_root_dir()
    return {os.path.basename(path) for path in glob(os.path.join(root_dir, "*", "*", "*", "*"))
            if os.path.isdir(path)}


def _add_member_with_mode(archive: zipfile.ZipFile, name: str, mode: int, data: str = ""):
    info = zipfile.ZipInfo(name)
    info.create_system = 3 # unix, so unzip restores the mode bits
    info.external_attr = mode << 16
    archive.writestr(info, data)


@pytest.mark.integration
def test_unreadable_extracted_members(root_analysis, tmp_path):
    # unzip honours the stored mode bits, so an xlsx member stored as 000 comes out unreadable
    # (and a 000 directory hides its contents from os.walk)
    # NOTE unzip ignores a mode of exactly 0, the file type bits have to be set
    xlsx_path = tmp_path / "report.xlsx"
    with zipfile.ZipFile(xlsx_path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        _add_member_with_mode(archive, "docProps/custom.xml", stat.S_IFREG | 0o000, "<Properties/>")
        _add_member_with_mode(archive, "locked/", stat.S_IFDIR | 0o000)
        archive.writestr("locked/inner.xml", "<inner/>")

    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(xlsx_path))
    root_analysis.save()
    root_analysis.schedule()

    existing_crash_reports = _enum_crash_reports()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_ARCHIVE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert _enum_crash_reports() == existing_crash_reports

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(file_observable.uuid).get_and_load_analysis(ArchiveAnalysis)
    assert analysis

    expected = {"docProps/custom.xml", "locked/inner.xml", "xl/workbook.xml"}
    assert expected <= set(analysis.extracted_files)

    extracted_names = {observable.file_name for observable in analysis.get_observables_by_type(F_FILE)}
    assert {os.path.basename(name) for name in expected} <= extracted_names


@pytest.mark.integration
def test_a_symlink_member_is_skipped(root_analysis, tmp_path, caplog):
    """unzip recreates a symlink member as a symlink. The link out of the root is refused, and
    only that one member: a .lnk sorts first, so failing the module would hide every member."""
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    xlsx_path = tmp_path / "report.xlsx"
    with zipfile.ZipFile(xlsx_path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        _add_member_with_mode(archive, "a.lnk", stat.S_IFLNK | 0o777, str(secret))

    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(xlsx_path))
    root_analysis.save()
    root_analysis.schedule()

    existing_crash_reports = _enum_crash_reports()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_ARCHIVE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert _enum_crash_reports() == existing_crash_reports
    assert any(r.getMessage().startswith("refusing file path") and r.path.endswith("a.lnk")
               and r.resolved_path == os.path.realpath(secret) for r in caplog.records)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(file_observable.uuid).get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert {"[Content_Types].xml", "xl/workbook.xml"} <= set(analysis.extracted_files)
    assert "a.lnk" not in analysis.extracted_files

    extracted_names = {observable.file_name for observable in analysis.get_observables_by_type(F_FILE)}
    assert {"[Content_Types].xml", "workbook.xml"} <= extracted_names
    assert "a.lnk" not in extracted_names
    assert hashlib.sha256(b"secret").hexdigest() not in os.listdir(root_analysis.hardcopy_dir)


@pytest.mark.integration
def test_the_permissions_pass_leaves_link_targets_alone(root_analysis, tmp_path, caplog):
    """unzip recreates symlink members, and chmod follows a link: the targets came out 0o664 and
    0o775, so an archive could make any file ACE owns readable by anyone."""
    secret = tmp_path / "secret.key"
    secret.write_text("secret")
    secret.chmod(0o600)
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir(mode=0o700)
    xlsx_path = tmp_path / "report.xlsx"
    with zipfile.ZipFile(xlsx_path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", "<workbook/>")
        _add_member_with_mode(archive, "key.txt", stat.S_IFLNK | 0o777, str(secret))
        _add_member_with_mode(archive, "dir", stat.S_IFLNK | 0o777, str(secret_dir))
        _add_member_with_mode(archive, "dangling.txt", stat.S_IFLNK | 0o777, str(tmp_path / "missing"))

    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(xlsx_path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_ARCHIVE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret_dir.stat().st_mode) == 0o700
    # the dangling link has nothing to chmod, which is no error either
    assert not [r for r in caplog.records if r.getMessage().startswith("unable to adjust permissions")]

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(file_observable.uuid).get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert sorted(analysis.extracted_files) == ["[Content_Types].xml", "xl/workbook.xml"]



@pytest.fixture
def hanging_tools(monkeypatch):
    """Puts an unrar, unzip, unace and 7z that never finish first on the PATH. Each records its pid.
    They live under the data directory because /tmp is mounted noexec."""
    tool_dir = os.path.join(get_data_dir(), f"hanging-tools-{uuid.uuid4()}")
    os.makedirs(tool_dir)
    pid_file = os.path.join(tool_dir, "pids")
    for tool in ("unrar", "unzip", "unace", "7z"):
        tool_path = os.path.join(tool_dir, tool)
        with open(tool_path, "w") as fp:
            fp.write(f"#!/bin/sh\necho $$ >> {pid_file}\nexec sleep 60\n")
        os.chmod(tool_path, 0o755)

    monkeypatch.setenv("PATH", f"{tool_dir}{os.pathsep}{os.environ['PATH']}")
    pids = []

    def _pids() -> list[int]:
        if os.path.exists(pid_file):
            with open(pid_file) as fp:
                pids[:] = [int(line) for line in fp if line.strip()]
        return pids

    yield _pids

    # what a failing run left behind
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # killed and reaped, as it should be

    shutil.rmtree(tool_dir, ignore_errors=True)


def _archive_observable(root_analysis, name: str, file_type: str, mime_type: str):
    file_path = root_analysis.create_file_path(name)
    with open(file_path, "wb") as fp:
        fp.write(b"not really an archive")

    observable = root_analysis.add_file_observable(file_path)
    file_type_analysis = FileTypeAnalysis()
    file_type_analysis.details = {"type": file_type, "mime": mime_type}
    observable.add_analysis(file_type_analysis)
    return observable


@pytest.mark.integration
@pytest.mark.parametrize("name,file_type,mime_type,tool", [
    ("sample.rar", "RAR archive data, v5", "application/x-rar", "unrar"),
    ("sample.xlsx", "Microsoft Excel 2007+", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "unzip"),
    ("sample.ace", "ACE archive data", "application/octet-stream", "unace"),
    ("sample.zip", "Zip archive data", "application/zip", "7z"),
])
def test_a_listing_that_times_out_is_killed(root_analysis, hanging_tools, monkeypatch, caplog, name, file_type, mime_type, tool):
    analyzer = ArchiveAnalyzer(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE))
    monkeypatch.setattr(analyzer.config, "timeout", 1)
    observable = _archive_observable(root_analysis, name, file_type, mime_type)

    with caplog.at_level(logging.WARNING):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis) is None
    (pid,) = hanging_tools()
    # killed and reaped before execute_analysis returned
    assert not psutil.pid_exists(pid)
    assert any(r.getMessage() == f"timed out listing the files in {observable.full_path} with {tool}"
               for r in caplog.records)


@pytest.mark.unit
@pytest.mark.parametrize("excluded,expected", [
    ("application/x-shockwave-flash,application/x-mach-binary", ["application/x-shockwave-flash", "application/x-mach-binary"]),
    ("application/x-shockwave-flash, ", ["application/x-shockwave-flash"]),
    ("", []),
])
def test_excluded_mime_types(root_analysis, monkeypatch, excluded, expected):
    analyzer = ArchiveAnalyzer(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE))
    monkeypatch.setattr(analyzer.config, "excluded_mime_types", excluded)

    assert analyzer.excluded_mime_types == expected


@pytest.mark.integration
def test_no_excluded_mime_types_still_extracts(root_analysis, tmp_path, monkeypatch):
    """An empty entry used to match every mime type, so nothing was extracted at all."""
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")

    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE), "excluded_mime_types", "")
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(zip_path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_FILE_TYPE, "test_groups")
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_ARCHIVE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(file_observable.uuid).get_and_load_analysis(ArchiveAnalysis)
    assert analysis
    assert sorted(analysis.extracted_files) == ["one.txt", "two.txt"]


@pytest.mark.integration
def test_ole_file_is_skipped_without_excluded_mime_types(root_analysis, monkeypatch):
    analyzer = ArchiveAnalyzer(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE))
    monkeypatch.setattr(analyzer.config, "excluded_mime_types", "")
    observable = _archive_observable(root_analysis, "sample.doc", "Composite Document File V2 Document", "application/x-ole-storage")
    with open(observable.full_path, "wb") as fp:
        fp.write(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(ArchiveAnalysis) is None
