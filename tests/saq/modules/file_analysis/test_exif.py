import logging
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EXIF, F_FILE, R_EXTRACTED_FROM
from saq.database import pool
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.exif import ExifAnalysis
from saq.modules.file_analysis.file_type import FileTypeAnalyzer
from saq.modules.file_analysis.hash import FileHashAnalyzer
from saq.util.uuid import get_storage_dir

SAMPLES = Path(__file__).parents[1] / "test_file_analysis"


def _analyze(root_analysis, path):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("exif", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    return root_analysis.get_observable(observable.uuid).get_and_load_analysis(ExifAnalysis)


@pytest.mark.integration
def test_pdf_metadata(root_analysis):
    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.error is None
    assert analysis.exifdata["PDF:PageCount"] == 3
    assert analysis.exifdata["PDF:Producer"] == "Skia/PDF m143"
    # a number, not exiftool's formatted "NN kB"
    assert analysis.exifdata["File:FileSize"] == os.path.getsize(SAMPLES / "sample_pdf_with_qr_code.pdf")

    # the summary leaves out exiftool's own and the file system's fields, and the group prefix
    summary = analysis.generate_summary()
    assert summary.startswith("Exiftool Analysis: ")
    assert "PageCount=3" in summary
    assert "Producer=Skia/PDF m143" in summary
    assert "PDF:" not in summary
    assert "FileName" not in summary and "ExifToolVersion" not in summary

    # the metadata is written out for yara, as a file nothing else needs to look at
    outputs = analysis.get_observables_by_type(F_FILE)
    assert [o.file_name for o in outputs] == ["exiftool.out"]
    output = outputs[0]
    assert "type=metadata.exif" in output.yara_meta_tags
    assert output.has_relationship(R_EXTRACTED_FROM)
    assert sorted(output.excluded_analysis) == sorted(
        f"{analyzer.__module__}:{analyzer}" for analyzer in (FileHashAnalyzer, FileTypeAnalyzer))
    with open(output.full_path) as fp:
        assert "'PDF:PageCount': 3" in fp.read()


@pytest.mark.integration
def test_office_document_by_extension(root_analysis):
    analysis = _analyze(root_analysis, SAMPLES / "doc.docx")

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.exifdata["File:FileType"] == "DOCX"


@pytest.mark.integration
def test_ole_document(root_analysis):
    analysis = _analyze(root_analysis, SAMPLES / "doc.doc")

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.exifdata["File:FileType"] == "DOC"


@pytest.mark.parametrize("name", ["report.pdf.pdfparser", "report.gs.pdf"])
@pytest.mark.integration
def test_tool_output_is_skipped(root_analysis, tmp_path, name):
    path = tmp_path / name
    shutil.copy(SAMPLES / "sample_pdf_with_qr_code.pdf", path)

    assert _analyze(root_analysis, path) is False


@pytest.mark.integration
def test_other_files_are_skipped(root_analysis, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a document")

    assert _analyze(root_analysis, path) is False


class _RecordingPopen(subprocess.Popen):
    started = []

    def __init__(self, args, *a, **kw):
        super().__init__(args, *a, **kw)
        _RecordingPopen.started.append((args, self))


def _exiftool_processes():
    return [process for args, process in _RecordingPopen.started if "exiftool" in str(args[0])]


@pytest.fixture
def recording_popen(monkeypatch):
    _RecordingPopen.started = []
    monkeypatch.setattr(subprocess, "Popen", _RecordingPopen)
    yield
    _RecordingPopen.started = []


def _exiftool_returns(monkeypatch, outcome):
    """Makes the module's exiftool run give outcome: a CompletedProcess's (returncode, stdout, stderr), an
    exception to raise, or a command line to run in its place. Every other run is left alone."""
    real_run = subprocess.run

    def run(args, *a, **kw):
        if args[0] != "exiftool":
            return real_run(args, *a, **kw)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, list):
            return real_run(outcome, *a, **kw)
        returncode, stdout, stderr = outcome
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.integration
def test_no_python_runs_in_the_exiftool_child(root_analysis, monkeypatch, recording_popen):
    # every child that runs Python between its fork and its exec runs the at-fork hooks, and in a worker one
    # of them can wait for ever on a lock another thread held at the fork. This hook records who ran it
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    monkeypatch.setattr(pool, "reset_database_after_fork", lambda: os.write(write_fd, f"{os.getpid()} ".encode()))

    def ran_the_hook() -> set[int]:
        try:
            return {int(pid) for pid in os.read(read_fd, 65536).split()}
        except BlockingIOError:
            return set()

    try:
        # the probe sees a child that does
        control = subprocess.Popen(["true"], preexec_fn=lambda: None)
        control.wait()
        assert ran_the_hook() == {control.pid}

        analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")
        assert analysis.exifdata["PDF:PageCount"] == 3

        exiftool = _exiftool_processes()
        assert len(exiftool) == 1
        assert exiftool[0].pid not in ran_the_hook()
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.integration
def test_file_exiftool_cannot_read_records_its_reason(root_analysis, tmp_path, caplog):
    # an OLE header and nothing else: exiftool exits 1, with the reason in its JSON and nothing on stderr
    path = tmp_path / "header_only.doc"
    path.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1"))

    with caplog.at_level(logging.INFO):
        analysis = _analyze(root_analysis, path)

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.error == "File format error"
    assert analysis.exifdata == {}
    assert analysis.generate_summary() == "Exiftool Analysis: ⚠ File format error"
    assert analysis.get_observables_by_type(F_FILE) == []
    assert any(r.levelno == logging.INFO and "Exif data extraction failed" in r.getMessage()
               and r.path.endswith("header_only.doc") for r in caplog.records)


@pytest.mark.parametrize("returncode,stderr,error", [
    # a Perl runtime error on a crafted file: the last line is the one that ended it
    (255, b"Warning: something first\n'x' outside of string in unpack at ExifTool.pm line 5920.\n",
     "'x' outside of string in unpack at ExifTool.pm line 5920."),
    # a long line (a vanished file's path, say) is cut short: it ends up in the summary
    (1, b"first\n" + b"x" * 2000 + b"\n", "x" * 500),
    (1, b"", "exiftool exited with status 1"),
    (-9, b"", "exiftool was killed by signal 9"),
])
@pytest.mark.integration
def test_exiftool_failure_without_its_json(root_analysis, monkeypatch, returncode, stderr, error):
    _exiftool_returns(monkeypatch, (returncode, b"", stderr))

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == error
    assert analysis.get_observables_by_type(F_FILE) == []


@pytest.mark.integration
def test_exiftool_timeout_is_recorded(root_analysis, monkeypatch, recording_popen, caplog):
    get_analysis_module_config(ANALYSIS_MODULE_EXIF).timeout = 1
    _exiftool_returns(monkeypatch, ["sleep", "30"])

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == "exiftool timed out after 1 seconds"
    assert analysis.get_observables_by_type(F_FILE) == []
    # killed and reaped, not left running
    sleeps = [process for args, process in _RecordingPopen.started if args[0] == "sleep"]
    assert [process.returncode for process in sleeps] == [-9]
    assert any(r.levelno == logging.WARNING and "exiftool timed out" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("stdout", [b"not json", b"[]", b"{}", b"[1]"])
@pytest.mark.integration
def test_unreadable_exiftool_output_is_an_error(root_analysis, monkeypatch, caplog, stdout):
    _exiftool_returns(monkeypatch, (0, stdout, b""))

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error.startswith("unreadable exiftool output: ")
    assert analysis.get_observables_by_type(F_FILE) == []
    assert any(r.levelno == logging.ERROR and r.exc_info and "unreadable exiftool output" in r.getMessage()
               for r in caplog.records)


@pytest.mark.integration
def test_exiftool_that_cannot_run_is_an_error(root_analysis, monkeypatch, caplog):
    _exiftool_returns(monkeypatch, FileNotFoundError(2, "No such file or directory", "exiftool"))

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error.startswith("unable to run exiftool: ")
    assert analysis.get_observables_by_type(F_FILE) == []
    assert any(r.levelno == logging.ERROR and r.exc_info and "unable to run exiftool" in r.getMessage()
               for r in caplog.records)
