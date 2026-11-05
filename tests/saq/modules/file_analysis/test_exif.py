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
from saq.environment import get_base_dir
from saq.modules.file_analysis.exif import ExifAnalysis, ExifAnalyzer
from saq.modules.file_analysis.file_type import FileTypeAnalyzer
from saq.modules.file_analysis.hash import FileHashAnalyzer
from saq.sandbox.runner import SandboxResult
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
def test_ole_document(root_analysis, tmp_path):
    # no office extension: only the OLE header says what it is
    path = tmp_path / "renamed.bin"
    shutil.copy(SAMPLES / "doc.doc", path)

    analysis = _analyze(root_analysis, path)

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.exifdata["File:FileType"] == "DOC"


# is_pdf_file already refuses a .pdfparser file, so that case is one the OLE check would accept
@pytest.mark.parametrize("name,sample", [("report.pdf.pdfparser", "doc.doc"), ("report.gs.pdf", "sample_pdf_with_qr_code.pdf")])
@pytest.mark.integration
def test_tool_output_is_skipped(root_analysis, tmp_path, name, sample):
    path = tmp_path / name
    shutil.copy(SAMPLES / sample, path)

    assert _analyze(root_analysis, path) is False


@pytest.mark.integration
def test_other_files_are_skipped(root_analysis, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a document")

    assert _analyze(root_analysis, path) is False


def _nested_title_pdf(depth: int) -> bytes:
    """A PDF whose Info /Title is a string inside depth nested arrays."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [] /Count 0 >>",
        b"<< /Title " + b"[" * depth + b"(nested title)" + b"]" * depth + b" >>",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n%s\nendobj\n" % (number, body)

    xref = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    pdf += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    pdf += b"trailer\n<< /Size %d /Root 1 0 R /Info 3 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return pdf


@pytest.mark.integration
def test_deeply_nested_metadata_is_written_for_yara(root_analysis, tmp_path, caplog):
    # deeper than pprint can recurse, and still quick for exiftool, which slows down with the square of the depth
    depth = 500
    path = tmp_path / "nested.pdf"
    path.write_bytes(_nested_title_pdf(depth))

    with caplog.at_level(logging.INFO):
        analysis = _analyze(root_analysis, path)

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.error is None
    # exiftool reports the outermost one-element array as its element
    nesting = depth - 1
    title = analysis.exifdata["PDF:Title"]
    for _ in range(nesting):
        assert isinstance(title, list) and len(title) == 1
        title = title[0]
    assert title == "nested title"

    outputs = analysis.get_observables_by_type(F_FILE)
    assert [o.file_name for o in outputs] == ["exiftool.out"]
    assert "type=metadata.exif" in outputs[0].yara_meta_tags
    with open(outputs[0].full_path) as fp:
        output = fp.read()
    assert "'PDF:Title': " + "[" * nesting + "'nested title'" + "]" * nesting in output
    assert "'File:FileType': 'PDF'" in output

    assert any(r.levelno == logging.INFO and "nested too deeply to pretty print" in r.getMessage()
               and r.path.endswith("nested.pdf") for r in caplog.records)


class _RecordingPopen(subprocess.Popen):
    started = []

    def __init__(self, args, *a, **kw):
        super().__init__(args, *a, **kw)
        _RecordingPopen.started.append((args, self))


def _exiftool_processes():
    """The sandbox launchers started for exiftool (the launcher execs prlimit, then setpriv, then exiftool)."""
    return [process for args, process in _RecordingPopen.started if any(str(arg).endswith("/exiftool") for arg in args)]


@pytest.fixture
def recording_popen(monkeypatch):
    _RecordingPopen.started = []
    monkeypatch.setattr(subprocess, "Popen", _RecordingPopen)
    yield
    _RecordingPopen.started = []


def _exiftool_returns(monkeypatch, outcome):
    """Makes the module's exiftool run give outcome: a SandboxResult's (returncode, stdout, stderr), or a
    command line to run in the sandbox in its place."""
    real_run = ExifAnalyzer.run_sandboxed_tool

    def run(self, args, target, **kw):
        if isinstance(outcome, list):
            return real_run(self, outcome, target, **kw)
        returncode, stdout, stderr = outcome
        return SandboxResult(returncode, stdout, stderr)

    monkeypatch.setattr(ExifAnalyzer, "run_sandboxed_tool", run)


@pytest.mark.integration
def test_no_python_runs_in_the_exiftool_child(root_analysis, monkeypatch, recording_popen):
    # every child that runs Python between its fork and its exec runs the at-fork hooks, and in a worker one
    # of them can wait for ever on a lock another thread held at the fork. This hook records who ran it.
    # The sandbox launcher is a fresh python, which only starts once the exec is done
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
def test_exiftool_cannot_read_ace(root_analysis, monkeypatch):
    # what the sandbox is for: a file that gets exiftool to run code finds nothing of ACE's to read
    config_file = os.path.join(get_base_dir(), "etc", "saq.default.yaml")
    script = f"cat {config_file} >/dev/null 2>&1 && echo readable >&2 || echo refused >&2; exit 1"
    _exiftool_returns(monkeypatch, ["sh", "-c", script])

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == "refused"


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
    (255, "Warning: something first\n'x' outside of string in unpack at ExifTool.pm line 5920.\n",
     "'x' outside of string in unpack at ExifTool.pm line 5920."),
    # a long line (a vanished file's path, say) is cut short: it ends up in the summary
    (1, "first\n" + "x" * 2000 + "\n", "x" * 500),
    (1, "", "exiftool exited with status 1"),
    (255, "", "exiftool exited with status 255"),
    (128 + 9, "", "exiftool was killed by signal 9"),
])
@pytest.mark.integration
def test_exiftool_failure_without_its_json(root_analysis, monkeypatch, returncode, stderr, error):
    _exiftool_returns(monkeypatch, (returncode, "", stderr))

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == error
    assert analysis.get_observables_by_type(F_FILE) == []


@pytest.mark.integration
def test_exiftool_timeout_is_recorded(root_analysis, monkeypatch, recording_popen, caplog):
    get_analysis_module_config(ANALYSIS_MODULE_EXIF).timeout = 1
    _exiftool_returns(monkeypatch, ["sleep", "30"])

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == "exiftool did not finish"
    assert analysis.get_observables_by_type(F_FILE) == []
    # the launcher has exited, and it kills everything it started before it does
    launchers = [process for args, process in _RecordingPopen.started if any(str(arg).endswith("/sleep") for arg in args)]
    assert len(launchers) == 1 and launchers[0].returncode is not None
    assert any(r.levelno == logging.WARNING and "stopped sleep" in r.getMessage() and "timed out" in r.getMessage()
               for r in caplog.records)


@pytest.mark.parametrize("stdout", ["not json", "[]", '{"File:FileType": "PDF"}', "[1]"])
@pytest.mark.integration
def test_unreadable_exiftool_output_is_an_error(root_analysis, monkeypatch, caplog, stdout):
    _exiftool_returns(monkeypatch, (0, stdout, ""))

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error.startswith("unreadable exiftool output: ")
    assert analysis.get_observables_by_type(F_FILE) == []
    assert any(r.levelno == logging.ERROR and r.exc_info and "unreadable exiftool output" in r.getMessage()
               for r in caplog.records)


@pytest.mark.integration
def test_exiftool_that_cannot_run_is_an_error(root_analysis, monkeypatch, caplog):
    _exiftool_returns(monkeypatch, ["/nonexistent/exiftool", "-j"])

    analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert analysis.error == "exiftool did not finish"
    assert analysis.get_observables_by_type(F_FILE) == []
    assert any(r.levelno == logging.ERROR and r.exc_info and "cannot run /nonexistent/exiftool in the sandbox" in r.getMessage()
               for r in caplog.records)
