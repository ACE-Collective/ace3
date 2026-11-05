import hashlib
import io
import logging
import os
import shutil
import signal
import stat
import subprocess
import uuid
import zipfile
from glob import glob

import psutil
import pytest

from saq.analysis.root import load_root
from saq.constants import ANALYSIS_MODULE_ARCHIVE, ANALYSIS_MODULE_FILE_TYPE, DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.configuration.config import get_analysis_module_config, get_config
from saq.crash_report import get_crash_report_root_dir
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_base_dir, get_data_dir
from saq.signatures.builtin import ARCHIVE_SINGLE_DANGEROUS_FILE
from saq.modules.file_analysis.archive import ArchiveAnalysis, ArchiveAnalyzer, archive_volumes, normalize_extracted_permissions, order_archive_file_list
from saq.modules.file_analysis.file_type import FileTypeAnalysis
from saq.util.uuid import get_storage_dir
from tests.saq.test_util import create_test_context


class TestOrderArchiveFileList:
    
    @pytest.mark.unit
    @pytest.mark.parametrize("file_list,expected", [
        # edge cases
        ([], []),
        
        # sorting by priority
        
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
        
        # mixed priorities - testing sorting behavior
        (["file1.pdf", "file2.scr", "file3.vbs", "file4.dll", "file5.doc"],
         ["file2.scr", "file4.dll", "file3.vbs", "file1.pdf", "file5.doc"]),
        
        # case insensitive handling
        (["file1.TXT", "file2.EXE", "file3.LNK", "file4.JS"],
         ["file3.LNK", "file2.EXE", "file4.JS", "file1.TXT"]),
        
        # preserve order within same priority
        
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
def tools_that_hang(monkeypatch):
    """Returns a function that puts tools first on the PATH, each running its shell snippet and then
    never finishing, and returns a function listing the pids of those still running. They live under
    the data directory because /tmp is mounted noexec. A tool runs in the sandbox, where it can write
    nothing outside its working directory, so it is found by the unique argument of its sleep."""
    tool_dir = os.path.join(get_data_dir(), f"hanging-tools-{uuid.uuid4()}")
    os.makedirs(tool_dir)
    marker = f"60.{uuid.uuid4().int % 10 ** 9}"

    def _running() -> list[int]:
        return [process.pid for process in psutil.process_iter(["cmdline"])
                if process.info["cmdline"] == ["sleep", marker]]

    def _install(snippets: dict[str, str]):
        for tool, snippet in snippets.items():
            tool_path = os.path.join(tool_dir, tool)
            with open(tool_path, "w") as fp:
                fp.write(f"#!/bin/sh\n{snippet}\nexec sleep {marker}\n")
            os.chmod(tool_path, 0o755)

        monkeypatch.setenv("PATH", f"{tool_dir}{os.pathsep}{os.environ['PATH']}")
        return _running

    yield _install

    # what a failing run left behind
    for pid in _running():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # it finished in the meantime

    shutil.rmtree(tool_dir, ignore_errors=True)


@pytest.fixture
def hanging_tools(tools_that_hang):
    """An unrar, unzip, unace and 7z that never finish."""
    return tools_that_hang({tool: "" for tool in ("unrar", "unzip", "unace", "7z")})


def _archive_observable(root_analysis, name: str, file_type: str, mime_type: str,
                        content: bytes = b"not really an archive"):
    file_path = root_analysis.create_file_path(name)
    with open(file_path, "wb") as fp:
        fp.write(content)

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
    # it ran until it was stopped, and nothing of it is left running. unace runs on a copy of the archive
    assert any(r.getMessage().startswith(f"ArchiveAnalyzer stopped {tool} on /")
               and r.getMessage().endswith(f"/{name}: command timed out after 0:00:01") for r in caplog.records)
    assert hanging_tools() == []


@pytest.mark.unit
@pytest.mark.parametrize("excluded,expected", [
    ("application/x-shockwave-flash,application/x-mach-binary", ["application/x-shockwave-flash", "application/x-mach-binary"]),
    ("application/x-shockwave-flash, ", ["application/x-shockwave-flash"]),
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
    with open(os.path.join(get_base_dir(), "tests/saq/modules/test_file_analysis_full/ole_files/Paid Invoice.doc"), "rb") as fp:
        observable = _archive_observable(root_analysis, "sample.doc", "Composite Document File V2 Document",
                                         "application/x-ole-storage", fp.read())

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_analysis(ArchiveAnalysis) is None


def _analyzer(root_analysis) -> ArchiveAnalyzer:
    return ArchiveAnalyzer(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_ARCHIVE))


def _zip_bytes(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)

    return buffer.getvalue()


ZIP = ("Zip archive data, at least v2.0 to extract", "application/zip")
# goes to unzip rather than 7z
SPREADSHEET_ZIP = ("Zip archive data, at least v2.0 to extract", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@pytest.mark.integration
@pytest.mark.parametrize("name,file_type,mime_type", [
    ("sample.rar", "RAR archive data, v5", "application/x-rar"),
    ("sample.xlsx", "Microsoft Excel 2007+", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("sample.ace", "ACE archive data", "application/octet-stream"),
    ("sample.zip", "Zip archive data", "application/zip"),
])
def test_a_file_the_tool_cannot_list_is_not_analyzed(root_analysis, caplog, name, file_type, mime_type):
    observable = _archive_observable(root_analysis, name, file_type, mime_type)

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis) is None
    assert not os.path.exists(f"{observable.full_path}.extracted")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING and r.module == "archive"]


@pytest.mark.integration
def test_a_jar_it_cannot_read_is_logged(root_analysis, caplog):
    observable = _archive_observable(root_analysis, "sample.jar", "Java archive data (JAR)", "application/java-archive")

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis) is None
    (record,) = [r for r in caplog.records if r.getMessage().startswith("unable to read jar file")]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == f"unable to read jar file {observable.full_path}: File is not a zip file"


@pytest.mark.integration
@pytest.mark.parametrize("name,file_type,mime_type", [
    # email parts are analyzed as attachments under their own names
    ("message.email.rfc822.unknown_application_zip_000.zip", *ZIP),
    ("movie.swf", "Zip archive data", "application/x-shockwave-flash"),
])
def test_files_it_skips(root_analysis, name, file_type, mime_type):
    observable = _archive_observable(root_analysis, name, file_type, mime_type, _zip_bytes({"a.txt": "a"}))

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis) is None
    assert not os.path.exists(f"{observable.full_path}.extracted")


@pytest.mark.integration
def test_a_missing_file_is_logged(root_analysis, caplog):
    observable = _archive_observable(root_analysis, "sample.zip", *ZIP)
    os.remove(observable.full_path)

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis) is None
    assert any(r.levelno == logging.ERROR and r.getMessage() == f"cannot find local file path for {observable}"
               for r in caplog.records)


@pytest.mark.integration
@pytest.mark.parametrize("file_type,mime_type", [SPREADSHEET_ZIP, ZIP], ids=["unzip", "7z"])
@pytest.mark.parametrize("member", [
    "ppt/slides/_rels/slide1.xml.rels",
    "word/document.xml",
    "word/embeddings/oleObject1.bin",
    "xl/embeddings/oleObject1.bin",
    "xl/worksheets/sheet1.xml",
])
def test_an_office_document_is_recognized_by_its_members(root_analysis, monkeypatch, file_type, mime_type, member):
    """Neither the name nor the file type says office document here. What is extracted from one points
    back at the document, so the document is what gets sandboxed, and the file count limit does not apply."""
    analyzer = _analyzer(root_analysis)
    monkeypatch.setattr(analyzer.config, "max_file_count", 1)
    observable = _archive_observable(root_analysis, "data.bin", file_type, mime_type,
                                     _zip_bytes({member: "x", "other.txt": "y"}))

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert sorted(analysis.extracted_files) == sorted([member, "other.txt"])
    extracted = analysis.get_observables_by_type(F_FILE)
    assert len(extracted) == 2
    assert all(o.redirection == observable for o in extracted)


@pytest.mark.integration
@pytest.mark.parametrize("file_type,mime_type", [SPREADSHEET_ZIP, ZIP], ids=["unzip", "7z"])
def test_an_archive_over_the_file_count_is_limited(root_analysis, monkeypatch, caplog, file_type, mime_type):
    analyzer = _analyzer(root_analysis)
    monkeypatch.setattr(analyzer.config, "max_file_count", 1)
    observable = _archive_observable(root_analysis, "data.bin", file_type, mime_type,
                                     _zip_bytes({"notes/document.xml": "x", "other.txt": "y"}))

    with caplog.at_level(logging.INFO):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.file_count == 2
    (extracted,) = analysis.get_observables_by_type(F_FILE)
    assert extracted.redirection is None
    assert len(analysis.extracted_files) == 1
    assert os.listdir(f"{observable.full_path}.extracted") in (["notes"], ["other.txt"])
    assert any(r.getMessage() == "removed 1 files because we've hit the limit" for r in caplog.records)


@pytest.mark.integration
@pytest.mark.parametrize("file_type,mime_type", [SPREADSHEET_ZIP, ZIP], ids=["unzip", "7z"])
def test_an_extraction_that_does_not_finish_is_recorded(root_analysis, monkeypatch, file_type, mime_type):
    # a member padded past the file size limit, a common way to get past scanners, stops the
    # extractor there: it and the members after it are incomplete
    monkeypatch.setattr(get_config().tool_sandbox, "file_size_limit", 1024 * 1024)
    observable = _archive_observable(root_analysis, "data.bin", file_type, mime_type,
                                     _zip_bytes({"a_big.bin": "\0" * 2000000, "b_small.txt": "b"}))

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert "b_small.txt" not in analysis.extracted_files
    assert analysis.extraction_error == "the extractor did not finish"
    assert analysis.generate_summary().endswith("(the extractor did not finish)")


@pytest.mark.integration
@pytest.mark.parametrize("file_type,mime_type", [SPREADSHEET_ZIP, ZIP], ids=["unzip", "7z"])
def test_an_archive_whose_listing_is_too_large_is_still_extracted(root_analysis, monkeypatch, file_type, mime_type):
    # a small archive padded with empty, long-named entries lists more than the sandbox keeps of a
    # tool's output; it is extracted under the file count limit, which takes the executable first
    monkeypatch.setattr(get_config().tool_sandbox, "max_output_bytes", 16 * 1024)
    analyzer = _analyzer(root_analysis)
    monkeypatch.setattr(analyzer.config, "max_file_count", 1)
    members = {f"padding/{'x' * 100}{i}.txt": "" for i in range(300)}
    observable = _archive_observable(root_analysis, "data.bin", file_type, mime_type,
                                     _zip_bytes({**members, "payload.exe": "MZ"}))

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.extracted_files == ["payload.exe"]
    assert analysis.extraction_error == "the listing was larger than 16384 bytes, so the file count is not known"


@pytest.mark.integration
def test_a_rar_extraction_stopped_at_the_file_size_limit_is_recorded(root_analysis, monkeypatch, caplog):
    # unrar does not die at the limit as 7z does: it stops with a write error, and keeps the member cut
    # off there only when told to (-kb). A single dangerous member padded past the limit still alerts
    monkeypatch.setattr(get_config().tool_sandbox, "file_size_limit", 512 * 1024)
    with open(os.path.join(get_base_dir(), "tests/saq/modules/test_file_analysis_full/rar/test.r07"), "rb") as fp:
        # its one member is 900 KB
        observable = _archive_observable(root_analysis, "sample.rar", "RAR archive data, v4", "application/x-rar",
                                         fp.read())

    with caplog.at_level(logging.WARNING):
        assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.extraction_error == "the extractor did not finish"
    assert any(r.levelno == logging.WARNING and "Write error" in r.getMessage() for r in caplog.records)
    assert analysis.extracted_files == ["IMPORTANT DOCUMENT.vbs"]
    (member,) = analysis.get_observables_by_type(F_FILE)
    assert os.path.getsize(member.full_path) == 512 * 1024
    assert [d.signature_uuid for d in member.detections] == [ARCHIVE_SINGLE_DANGEROUS_FILE.uuid]


@pytest.mark.integration
def test_a_multi_volume_archive_is_extracted(root_analysis, tmp_path):
    # a payload split across attachments, which sit next to each other in the files directory
    (tmp_path / "payload.exe").write_bytes(os.urandom(3000))
    subprocess.run(["7z", "a", "-v2k", str(tmp_path / "split.7z"), str(tmp_path / "payload.exe")],
                   check=True, capture_output=True)
    first, second = sorted(tmp_path.glob("split.7z.*"))
    # added as the attachment it is, which ACE hard-links into its .hardcopy store
    second_path = root_analysis.create_file_path(second.name)
    shutil.copyfile(second, second_path)
    root_analysis.add_file_observable(second_path)
    assert os.stat(second_path).st_nlink > 1
    observable = _archive_observable(root_analysis, first.name, "7-zip archive data, version 0.4",
                                     "application/x-7z-compressed", first.read_bytes())

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.extracted_files == ["payload.exe"]
    assert analysis.extraction_error is None


@pytest.mark.integration
def test_unace_gets_the_other_volumes(root_analysis, fake_tools):
    # unace looks for the other volumes next to its copy of the archive
    fake_tools({"unace": 'ls "$(dirname "$2")"'})
    observable = _archive_observable(root_analysis, "split.ace", "ACE archive data", "application/octet-stream")
    with open(root_analysis.create_file_path("split.c00"), "wb") as fp:
        fp.write(b"second volume")

    assert _analyzer(root_analysis)._run_unace("l", observable.full_path).stdout.split() == ["split.ace", "split.c00"]


@pytest.mark.unit
@pytest.mark.parametrize("first,others", [
    ("a.7z.001", ["a.7z.002", "a.7z.010"]),
    ("a.zip.001", ["a.zip.002"]),
    ("a.part1.rar", ["a.part2.rar", "a.PART03.rar"]),
    ("a.rar", ["a.r00", "a.r01"]),
    ("a.zip", ["a.z01"]),
    ("a.ace", ["a.c00"]),
    ("a.7z", []),
])
def test_the_other_volumes_of_an_archive(tmp_path, first, others):
    for name in [first, *others, "b.7z.002", "b.r00", "b.part2.rar", "a.txt", "a.7z.002.txt"]:
        (tmp_path / name).write_bytes(b"x")
    # a symlink could point the tool at a file of ACE's, and a directory is not a volume
    os.symlink("/etc/passwd", tmp_path / ("a.7z.003" if first.endswith(".001") else "a.r02"))
    os.mkdir(tmp_path / "a.z02")
    # every file ACE stores has a hard link in its .hardcopy store
    for name in others:
        os.link(tmp_path / name, tmp_path / f"hardcopy-{name}")

    assert archive_volumes(str(tmp_path / first)) == sorted(str(tmp_path / name) for name in others)


@pytest.mark.integration
def test_a_zip_with_a_manifest_is_extracted_as_a_jar(root_analysis, monkeypatch):
    analyzer = _analyzer(root_analysis)
    monkeypatch.setattr(analyzer.config, "max_file_count", 1)
    monkeypatch.setattr(analyzer.config, "max_jar_file_count", 2)
    observable = _archive_observable(root_analysis, "data.bin", *SPREADSHEET_ZIP,
                                     _zip_bytes({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "a.txt": "a"}))

    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert sorted(analysis.extracted_files) == ["META-INF/MANIFEST.MF", "a.txt"]


@pytest.mark.integration
@pytest.mark.parametrize("member,tag", [
    ("invoice.exe", "exe_in_zip"),
    ("invoice.js", "script_in_zip"),
    ("invoice.lnk", "lnk_in_zip"),
    ("invoice.jnlp", "jnlp_in_zip"),
    ("invoice.one", "one_in_zip"),
])
def test_a_single_dangerous_file_is_a_detection(root_analysis, member, tag):
    observable = _archive_observable(root_analysis, "invoice.zip", *ZIP, _zip_bytes({member: "x"}))

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.has_tag("single_file_zip")
    assert analysis.has_tag(tag)
    (extracted,) = analysis.get_observables_by_type(F_FILE)
    assert extracted.has_directive(DIRECTIVE_SANDBOX)
    assert [d.signature_uuid for d in extracted.detections] == [ARCHIVE_SINGLE_DANGEROUS_FILE.uuid]


@pytest.mark.integration
def test_a_single_harmless_file_is_sandboxed_but_not_a_detection(root_analysis):
    observable = _archive_observable(root_analysis, "invoice.zip", *ZIP, _zip_bytes({"invoice.txt": "x"}))

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.has_tag("single_file_zip")
    (extracted,) = analysis.get_observables_by_type(F_FILE)
    assert extracted.has_directive(DIRECTIVE_SANDBOX)
    assert not extracted.detections


@pytest.mark.integration
def test_an_output_directory_it_cannot_create_is_logged(root_analysis, caplog):
    observable = _archive_observable(root_analysis, "sample.zip", *ZIP, _zip_bytes({"a.txt": "a"}))
    extracted_path = f"{observable.full_path}.extracted"
    with open(extracted_path, "w") as fp:
        fp.write("in the way")

    assert _analyzer(root_analysis).execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    assert observable.get_analysis(ArchiveAnalysis).extracted_files == []
    (record,) = [r for r in caplog.records if r.getMessage() == f"unable to create directory {extracted_path}"]
    assert record.levelno == logging.ERROR
    assert record.exc_info[0] is FileExistsError


@pytest.mark.integration
def test_an_extraction_that_times_out_is_killed(root_analysis, tools_that_hang, monkeypatch, caplog):
    # lists one file, then never finishes extracting it
    pids = tools_that_hang({"7z": 'if [ "$3" = l ]; then echo "2022-04-27 08:55:00   180304  1 files"; exit 0; fi'})
    analyzer = _analyzer(root_analysis)
    monkeypatch.setattr(analyzer.config, "timeout", 1)
    observable = _archive_observable(root_analysis, "sample.zip", *ZIP, _zip_bytes({"a.txt": "a"}))

    with caplog.at_level(logging.WARNING):
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    # it ran until it was stopped, and nothing of it is left running
    assert any(r.getMessage() == f"ArchiveAnalyzer stopped 7z on {os.path.abspath(observable.full_path)}: "
               "command timed out after 0:00:01" for r in caplog.records)
    assert pids() == []
    analysis = observable.get_analysis(ArchiveAnalysis)
    assert analysis.file_count == 1
    assert analysis.extracted_files == []


@pytest.mark.unit
def test_a_permission_it_cannot_fix_is_logged(tmp_path, monkeypatch, caplog):
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "file.txt").write_text("x")

    def _chmod(path, mode):
        raise PermissionError(1, "Operation not permitted", path)

    monkeypatch.setattr(os, "chmod", _chmod)
    normalize_extracted_permissions(str(tmp_path))
    monkeypatch.undo()

    records = {r.getMessage(): r for r in caplog.records}
    for message in (f"unable to adjust permissions on dir {tmp_path / 'dir'}",
                    f"unable to adjust permissions on file {tmp_path / 'dir' / 'file.txt'}"):
        assert records[message].levelno == logging.ERROR
        assert records[message].exc_info[0] is PermissionError


@pytest.mark.unit
def test_summary():
    analysis = ArchiveAnalysis()
    assert analysis.generate_summary() is None

    analysis.file_count = 3
    analysis.extracted_files = ["a.txt", "b/c.txt"]
    assert analysis.generate_summary() == "Archive Analysis: extracted 2 of 3 files: (a.txt, b/c.txt)"
