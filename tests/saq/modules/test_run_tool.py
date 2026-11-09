"""AnalysisModule.run_tool() and run_sandboxed_tool(), and the modules that run their external tools
through them. A tool that does not finish is stopped before the module's call to analyze() runs out
of time, where it used to run until the engine killed the whole worker."""

import logging
import os
import subprocess
import time
from unittest.mock import Mock

import psutil
import pytest
import rarfile

from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, AnalysisExecutionResult
from saq.environment import get_base_dir, get_data_dir
from saq.modules import base_module
from saq.modules.base_module import TOOL_TIMEOUT_MARGIN_SECONDS
from saq.modules.email.encryption.rar import RarEncryptionAnalysis, RarEncryptionAnalyzer
from saq.modules.email.encryption.zip import ZipEncryptionAnalysis, ZipEncryptionAnalyzer
from saq.modules.file_analysis.autoit import AutoItAnalysis, AutoItAnalyzer
from saq.modules.file_analysis.cve import CVE_2021_30657_Analysis, CVE_2021_30657_Analyzer
from saq.modules.file_analysis.dmg import DMGAnalysis, DMGAnalyzer
from saq.modules.file_analysis.file_type import FileTypeAnalysis, FileTypeAnalyzer
from saq.modules.file_analysis.mse import MicrosoftScriptEncodingAnalysis, MicrosoftScriptEncodingAnalyzer
from saq.modules.file_analysis.pdf import PDFPARSER_TIMEOUT_SECONDS, PDFAnalysis, PDFAnalyzer
from saq.modules.file_analysis.rtf import RTFOLEObjectAnalysis, RTFOLEObjectAnalyzer
from saq.modules.file_analysis.ssdeep import SsdeepAnalysis, SsdeepAnalyzer
from saq.modules.file_analysis.upx import UPXAnalysis, UPXAnalyzer
from saq.sandbox.runner import SandboxResult, landlock_available, sandbox_python
from tests.saq.modules.conftest import HANG, fake_tool_pids, fake_tools_running
from tests.saq.modules.file_analysis.test_cve import MACOS_MEMBER, _add_dmg_analysis, _create_img
from tests.saq.test_util import create_test_context


def _module(cls, config_name: str, root):
    return cls(context=create_test_context(root=root), config=get_analysis_module_config(config_name))


def _out_of_time(module):
    """Leaves the module's call one second of tool time."""
    module.set_analysis_deadline(time.monotonic() + TOOL_TIMEOUT_MARGIN_SECONDS + 1)


def _file(root_analysis, name: str, content: bytes):
    path = root_analysis.create_file_path(name)
    with open(path, "wb") as fp:
        fp.write(content)
    return root_analysis.add_file_observable(path)


def _run(module, observable) -> float:
    started = time.monotonic()
    assert module.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    return time.monotonic() - started


def _assert_stopped(tool_dir: str, count: int = 1):
    pids = fake_tool_pids(tool_dir)
    assert len(pids) == count
    assert not any(psutil.pid_exists(pid) for pid in pids)


def _assert_stopped_in_sandbox(tool_dir: str, caplog, tool: str):
    """The sandbox lets a tool write nothing outside its working directory, so it cannot record its
    pid: it ran until it was stopped, and nothing it started is left running."""
    assert any(f" stopped {tool} on " in r.getMessage() and "timed out" in r.getMessage() for r in caplog.records)
    assert fake_tools_running(tool_dir) == []


#
# run_tool()
#

@pytest.mark.unit
def test_run_tool_returns_what_the_tool_did(root_analysis):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    result = module.run_tool(["sh", "-c", "echo out; echo err >&2; exit 3"], "target", capture_output=True)

    assert result.returncode == 3
    assert result.stdout == b"out\n"
    assert result.stderr == b"err\n"


@pytest.mark.unit
@pytest.mark.parametrize("left,expected", [
    (None, None),  # outside an engine call: maximum_analysis_time
    (100, 100 - TOOL_TIMEOUT_MARGIN_SECONDS),
    # never less than a second
    (-10, 1),
])
def test_run_tool_timeout_is_what_the_call_has_left(root_analysis, monkeypatch, left, expected):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    if left is not None:
        module.set_analysis_deadline(time.monotonic() + left)
    else:
        expected = module.maximum_analysis_time - TOOL_TIMEOUT_MARGIN_SECONDS

    run = Mock()
    monkeypatch.setattr("saq.modules.base_module.subprocess.run", run)
    module.run_tool(["true"], "target")

    assert run.call_args.kwargs["timeout"] == pytest.approx(expected, abs=0.1)


@pytest.mark.unit
@pytest.mark.parametrize("timeout,left,expected", [
    (10, 100, 10),
    (10, TOOL_TIMEOUT_MARGIN_SECONDS + 3, 3),
    (0.1, 100, 1),
])
def test_run_tool_timeout_is_at_most_the_one_given(root_analysis, monkeypatch, timeout, left, expected):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    module.set_analysis_deadline(time.monotonic() + left)

    run = Mock()
    monkeypatch.setattr("saq.modules.base_module.subprocess.run", run)
    module.run_tool(["true"], "target", timeout=timeout)

    assert run.call_args.kwargs["timeout"] == pytest.approx(expected, abs=0.5)


@pytest.mark.integration
def test_run_tool_stops_a_tool_that_does_not_finish(root_analysis, fake_tools, caplog):
    tool_dir = fake_tools({"slowtool": HANG})
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    _out_of_time(module)

    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert module.run_tool(["slowtool", "target.bin"], "target.bin", capture_output=True) is None

    assert time.monotonic() - started < 30
    _assert_stopped(tool_dir)
    assert any(r.getMessage() == "SsdeepAnalyzer stopped slowtool on target.bin after 1 seconds" for r in caplog.records)


#
# the modules
#

@pytest.mark.integration
def test_mse(root_analysis, fake_tools, monkeypatch):
    tool_dir = fake_tools({"decode": HANG})
    module = _module(MicrosoftScriptEncodingAnalyzer, "microsoft_script_encoding_analysis", root_analysis)
    monkeypatch.setattr(module.config, "decryption_program", os.path.join(tool_dir, "decode"))
    _out_of_time(module)
    observable = _file(root_analysis, "encoded.vbe", b"#@~^encoded script")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    # the incomplete output is not kept
    assert not os.path.exists(f"{observable.full_path}.decrypted.vbs")
    analysis = observable.get_analysis(MicrosoftScriptEncodingAnalysis)
    assert not analysis.observables
    assert analysis.error == "the decoder did not finish"
    assert analysis.generate_summary() == "Microsoft Script Encoding Analysis: failed: the decoder did not finish"


@pytest.mark.integration
def test_dmg2img(root_analysis, fake_tools, caplog):
    tool_dir = fake_tools({"dmg2img": f'touch "$2"\n{HANG}'})
    module = _module(DMGAnalyzer, "dmg_analyzer", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "Installer.dmg", b"koly" * 10)

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "dmg2img")
    # the incomplete image is not kept
    assert not os.path.exists(observable.full_path[:-4] + ".img")
    assert not observable.get_analysis(DMGAnalysis).observables
    assert observable.get_analysis(DMGAnalysis).error == "dmg2img did not finish"


@pytest.mark.integration
def test_dmg_listing(root_analysis, fake_tools, caplog):
    tool_dir = fake_tools({"dmg2img": 'echo image > "$2"', "7z": HANG})
    module = _module(DMGAnalyzer, "dmg_analyzer", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "Installer.dmg", b"koly" * 10)

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "7z")
    analysis = observable.get_analysis(DMGAnalysis)
    # the image is analyzed on its own; only its listing is missing
    assert [o.file_name for o in analysis.observables] == ["Installer.img"]
    assert analysis.details["file_list"] == []
    assert analysis.error == "7z l did not finish, so the image's files are not listed"


@pytest.mark.integration
def test_unautoit_list(root_analysis, fake_tools):
    tool_dir = fake_tools({"unautoit": HANG})
    module = _module(AutoItAnalyzer, "autoit", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "compiled.exe", b"MZ autoit")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    assert observable.get_analysis(AutoItAnalysis).error == "unautoit list timed out"


@pytest.mark.integration
def test_unautoit_extract(root_analysis, fake_tools):
    tool_dir = fake_tools({"unautoit": f'[ "$1" = list ] && exit 0\n{HANG}'})
    module = _module(AutoItAnalyzer, "autoit", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "compiled.exe", b"MZ autoit")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir, count=2)
    analysis = observable.get_analysis(AutoItAnalysis)
    assert analysis.error == "unautoit extract-all timed out"
    assert analysis.scripts == []


@pytest.mark.integration
def test_upx_test(root_analysis, fake_tools, caplog):
    tool_dir = fake_tools({"upx": HANG})
    module = _module(UPXAnalyzer, "upx", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "packed.exe", b"MZ packed")

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "upx")
    assert observable.get_analysis(UPXAnalysis) is None


@pytest.mark.integration
def test_upx_unpack(root_analysis, fake_tools, caplog):
    tool_dir = fake_tools({"upx": f'[ "$1" = -t ] && echo "testing $2 [OK]" && exit 0\n'
                                  f'touch "${{2#-o}}"\n{HANG}'})
    module = _module(UPXAnalyzer, "upx", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "packed.exe", b"MZ packed")

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "upx")
    analysis = observable.get_analysis(UPXAnalysis)
    assert analysis.error == "upx -d did not finish"
    assert analysis.generate_summary() == "UPX Analysis: decompression failed: upx -d did not finish"
    assert not analysis.observables
    # the incomplete output is not kept
    assert not os.path.exists(f"{observable.full_path}.upx.exe")


@pytest.mark.integration
def test_upx_failure_without_a_message_is_named_by_its_type(root_analysis, monkeypatch):
    """An exception whose str() is empty still gives the analysis an error, which needs a message."""
    module = _module(UPXAnalyzer, "upx", root_analysis)
    monkeypatch.setattr(module, "test_upx", lambda path: True)

    def _raise(*args, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr(module, "run_sandboxed_tool", _raise)
    observable = _file(root_analysis, "packed.exe", b"MZ packed")

    _run(module, observable)
    assert observable.get_analysis(UPXAnalysis).error == "TimeoutError"


@pytest.mark.integration
def test_ssdeep(root_analysis, fake_tools):
    tool_dir = fake_tools({"ssdeep": HANG})
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "sample.bin", os.urandom(4096))

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    assert observable.get_analysis(SsdeepAnalysis) is None


@pytest.mark.integration
def test_rtfobj(root_analysis, data_dir_tool, monkeypatch):
    rtfobj, pid_file = data_dir_tool
    module = _module(RTFOLEObjectAnalyzer, "rtfole", root_analysis)
    monkeypatch.setattr(module.config, "rtfobj_path", rtfobj)
    _out_of_time(module)
    observable = _file(root_analysis, "document.rtf", b"{\\rtf1 not much of a document}")

    assert _run(module, observable) < 30
    with open(pid_file) as fp:
        assert not psutil.pid_exists(int(fp.read()))
    analysis = observable.get_analysis(RTFOLEObjectAnalysis)
    assert analysis.extracted_files == []
    assert analysis.error == "rtfobj did not finish"


@pytest.mark.integration
def test_pdfparser(root_analysis, data_dir_tool, monkeypatch, caplog):
    pdfparser, pid_file = data_dir_tool
    module = _module(PDFAnalyzer, "pdf_analyzer", root_analysis)
    monkeypatch.setattr(module.config, "pdfparser_path", pdfparser)
    _out_of_time(module)
    observable = _file(root_analysis, "document.pdf", b"%PDF-1.7\nnot much of a document")

    with caplog.at_level(logging.WARNING):
        # stopped when the call runs out of time, before its own PDFPARSER_TIMEOUT_SECONDS
        assert _run(module, observable) < PDFPARSER_TIMEOUT_SECONDS
    with open(pid_file) as fp:
        assert not psutil.pid_exists(int(fp.read()))
    assert any(r.getMessage() == f"PDFAnalyzer stopped python3 on {observable.full_path} after 1 seconds"
               for r in caplog.records)
    # what it wrote before it was stopped is still scanned
    assert [o.file_name for o in observable.get_analysis(PDFAnalysis).observables
            if o.file_name.endswith(".pdfparser")] == ["document.pdf.pdfparser"]
    assert observable.get_analysis(PDFAnalysis).error == \
        "pdfparser did not finish, so its dump of the objects is incomplete"


@pytest.fixture
def data_dir_tool(fake_tools):
    """A python script for the modules that run `python <script>`, that never finishes."""
    tool_dir = fake_tools({})
    script = os.path.join(tool_dir, "rtfobj.py")
    pid_file = os.path.join(tool_dir, "script.pid")
    with open(script, "w") as fp:
        fp.write(f"import os, time\nopen({pid_file!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    return script, pid_file


class _EncryptedRar:
    def __init__(self, path):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def needs_password(self):
        return True


@pytest.mark.integration
def test_rar2john(root_analysis, fake_tools, monkeypatch, caplog):
    monkeypatch.setattr(rarfile, "RarFile", _EncryptedRar)
    tool_dir = fake_tools({"rar2john": HANG})
    module = _module(RarEncryptionAnalyzer, "rar_encryption_analyzer", root_analysis)
    monkeypatch.setattr(module.config, "john_bin_path", tool_dir)
    _out_of_time(module)
    observable = _file(root_analysis, "payload.rar", b"Rar!\x1a\x07\x01\x00")

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "rar2john")
    assert observable.get_analysis(RarEncryptionAnalysis).error == "rar2john did not finish"


@pytest.mark.integration
def test_rar2john_that_finds_no_hash(root_analysis, fake_tools, monkeypatch):
    monkeypatch.setattr(rarfile, "RarFile", _EncryptedRar)
    tool_dir = fake_tools({"rar2john": "echo 'payload.rar: no hash here' >&2"})
    module = _module(RarEncryptionAnalyzer, "rar_encryption_analyzer", root_analysis)
    monkeypatch.setattr(module.config, "john_bin_path", tool_dir)
    observable = _file(root_analysis, "payload.rar", b"Rar!\x1a\x07\x01\x00")

    _run(module, observable)

    assert observable.get_analysis(RarEncryptionAnalysis).error == "rar2john failed: payload.rar: no hash here\n"


@pytest.mark.integration
def test_zip2john(root_analysis, fake_tools, monkeypatch, tmp_path, caplog):
    tool_dir = fake_tools({"zip2john": HANG})
    module = _module(ZipEncryptionAnalyzer, "zip_encryption_analyzer", root_analysis)
    monkeypatch.setattr(module.config, "john_bin_path", tool_dir)
    _out_of_time(module)

    payload = tmp_path / "invoice.txt"
    payload.write_text("payload")
    archive = tmp_path / "invoice.zip"
    subprocess.run(["7z", "a", "-tzip", "-pinfected", str(archive), str(payload)], check=True, capture_output=True)
    observable = _file(root_analysis, "invoice.zip", archive.read_bytes())

    assert _run(module, observable) < 30
    _assert_stopped_in_sandbox(tool_dir, caplog, "zip2john")
    assert observable.get_analysis(ZipEncryptionAnalysis).error == "zip2john did not finish"


def _cve_target(root_analysis, tmpdir):
    observable = root_analysis.add_file_observable(_create_img(tmpdir, b"#!/bin/bash\necho 'malicious script'\n"))
    observable.add_tag("macos")
    observable.add_tag("dmg")
    _add_dmg_analysis(root_analysis, tmpdir, observable, [
        f"2021-04-06 23:33:06 .....        59039        61440  {MACOS_MEMBER}",
        f"2021-04-06 23:33:06 .....        59039        61440  {MACOS_MEMBER}2",
    ])
    return observable


@pytest.mark.integration
def test_cve_extraction(root_analysis, fake_tools, tmpdir, caplog):
    observable = _cve_target(root_analysis, tmpdir)
    tool_dir = fake_tools({"7z": HANG})
    module = _module(CVE_2021_30657_Analyzer, ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, root_analysis)
    _out_of_time(module)

    assert _run(module, observable) < 30
    # out of time: the second file is not tried
    _assert_stopped_in_sandbox(tool_dir, caplog, "7z")
    assert len([r for r in caplog.records if " stopped 7z on " in r.getMessage()]) == 1
    analysis = observable.get_analysis(CVE_2021_30657_Analysis)
    assert analysis.suspect_files == {}
    assert analysis.error.startswith("7z did not finish extracting ")
    assert analysis.error.endswith(", so it and the files after it were not checked")


@pytest.mark.integration
def test_cve_mime_type(root_analysis, fake_tools, tmpdir):
    observable = _cve_target(root_analysis, tmpdir)
    tool_dir = fake_tools({"file": HANG})
    module = _module(CVE_2021_30657_Analyzer, ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, root_analysis)
    _out_of_time(module)

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    analysis = observable.get_analysis(CVE_2021_30657_Analysis)
    assert analysis.suspect_files == {}
    assert analysis.error.startswith("file did not finish on ")


@pytest.mark.integration
def test_file_type(root_analysis, fake_tools):
    tool_dir = fake_tools({"file": HANG})
    module = _module(FileTypeAnalyzer, "file_type", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "document.pdf", b"%PDF-1.4\n%%EOF\n")

    assert _run(module, observable) < 30
    # the description and the mime type
    _assert_stopped(tool_dir, count=2)
    analysis = observable.get_analysis(FileTypeAnalysis)
    assert analysis.error == "file did not finish"
    assert analysis.file_type == ""
    assert analysis.mime_type == ""
    # the checks that read the file themselves still run
    assert analysis.is_pdf_file
    assert observable.has_tag("pdf")


@pytest.mark.integration
def test_file_type_error_output(root_analysis, fake_tools, caplog):
    fake_tools({"file": "echo 'text/plain'; echo 'file: warning' >&2"})
    module = _module(FileTypeAnalyzer, "file_type", root_analysis)
    observable = _file(root_analysis, "notes.txt", b"notes")

    with caplog.at_level(logging.WARNING):
        _run(module, observable)

    analysis = observable.get_analysis(FileTypeAnalysis)
    assert analysis.file_type == "text/plain"
    assert analysis.mime_type == "text/plain"
    # a warning is not a failure
    assert analysis.error is None
    warnings = [r for r in caplog.records if r.getMessage() == f"file command returned error output for {observable.full_path}"]
    assert len(warnings) == 2


#
# run_sandboxed_tool()
#

needs_landlock = pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")


def _sh(script: str, *args: str) -> list[str]:
    return ["sh", "-c", script, "sh", *args]


@pytest.mark.unit
@needs_landlock
def test_sandboxed_tool_reads_its_target_and_keeps_its_outputs(root_analysis):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample content")
    kept = f"{observable.full_path}.out"
    # a relative path, as ACE's often are; the tool runs in its own working directory
    assert not os.path.isabs(observable.full_path)

    result = module.run_sandboxed_tool(
        _sh('cat "$1"; touch "$(dirname "$1")/planted" 2>/dev/null && echo planted >&2; echo result > out.txt',
            observable.full_path), observable.full_path, outputs={"out.txt": kept, "missing.txt": f"{kept}.missing"})

    assert result.returncode == 0
    assert result.stdout == "sample content"
    # it can write nothing next to the file it reads
    assert result.stderr == ""
    assert not os.path.exists(os.path.join(os.path.dirname(observable.full_path), "planted"))
    with open(kept) as fp:
        assert fp.read() == "result\n"
    # an output the tool did not write is skipped
    assert not os.path.exists(f"{kept}.missing")


@pytest.mark.unit
@needs_landlock
def test_sandboxed_tool_cannot_read_ace_or_its_environment(root_analysis, monkeypatch):
    monkeypatch.setenv("ACE_TEST_SECRET", "secret")
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")
    script = (f'cat {get_base_dir()}/etc/saq.default.yaml >/dev/null 2>&1 && echo config; '
              'cat /proc/1/environ >/dev/null 2>&1 && echo proc; '
              '[ -n "$ACE_TEST_SECRET" ] && echo environment; '
              'echo "extra=$EXTRA"')

    result = module.run_sandboxed_tool(_sh(script), observable.full_path, env={"EXTRA": "given"})

    assert result.stdout == "extra=given\n"


@pytest.mark.unit
@needs_landlock
def test_sandboxed_tool_writes_its_write_dirs(root_analysis):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "archive.zip", b"PK")
    output_dir = f"{observable.full_path}.extracted"
    os.mkdir(output_dir)

    # unace takes the archive relative to the directory it extracts into
    result = module.run_sandboxed_tool(_sh('echo member > member.txt; cat "$1"', os.path.relpath(observable.full_path, output_dir)),
                                       observable.full_path, write_dirs=[output_dir], cwd=output_dir)

    assert result.stdout == "PK"
    with open(os.path.join(output_dir, "member.txt")) as fp:
        assert fp.read() == "member\n"


@pytest.mark.unit
@needs_landlock
def test_an_output_that_is_not_a_plain_file_is_not_kept(root_analysis, caplog):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")
    # a link to a file of ACE's would have ACE copy it into the alert
    script = f'ln -s {get_base_dir()}/etc/saq.default.yaml symlink.txt; echo a > a; ln a hardlink.txt'

    with caplog.at_level(logging.WARNING):
        module.run_sandboxed_tool(_sh(script), observable.full_path,
                                  outputs={"symlink.txt": f"{observable.full_path}.1", "hardlink.txt": f"{observable.full_path}.2"})

    assert not os.path.lexists(f"{observable.full_path}.1")
    assert not os.path.lexists(f"{observable.full_path}.2")
    target = os.path.abspath(observable.full_path)
    assert sorted(r.getMessage() for r in caplog.records if "not a plain file" in r.getMessage()) == [
        f"SsdeepAnalyzer did not keep sh's output hardlink.txt on {target}: not a plain file",
        f"SsdeepAnalyzer did not keep sh's output symlink.txt on {target}: not a plain file",
    ]


@pytest.mark.unit
@needs_landlock
def test_a_stopped_tool_keeps_nothing(root_analysis, caplog):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")

    started = time.monotonic()
    with caplog.at_level(logging.WARNING):
        assert module.run_sandboxed_tool(_sh("echo partial > out.txt; exec sleep 60"), observable.full_path, timeout=1,
                                         outputs={"out.txt": f"{observable.full_path}.out"}) is None

    assert time.monotonic() - started < 30
    assert not os.path.exists(f"{observable.full_path}.out")
    assert any(r.getMessage() == f"SsdeepAnalyzer stopped sh on {os.path.abspath(observable.full_path)}: "
               "command timed out after 0:00:01" for r in caplog.records)


@pytest.mark.unit
@needs_landlock
def test_a_cancelled_analysis_stops_the_tool(root_analysis, caplog):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")
    module.cancel_analysis()

    started = time.monotonic()
    with caplog.at_level(logging.INFO):
        assert module.run_sandboxed_tool(_sh("exec sleep 60"), observable.full_path) is None

    assert time.monotonic() - started < 30
    assert any(r.levelno == logging.INFO and "the analysis was stopped" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
@pytest.mark.parametrize("timeout,left,expected", [
    (None, 100, 100 - TOOL_TIMEOUT_MARGIN_SECONDS),
    (10, 100, 10),
    (10, TOOL_TIMEOUT_MARGIN_SECONDS + 3, 3),
    (10, -10, 1),
])
def test_sandboxed_tool_timeout_is_what_the_call_has_left(root_analysis, monkeypatch, timeout, left, expected):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    module.set_analysis_deadline(time.monotonic() + left)
    monkeypatch.setattr(base_module, "landlock_available", lambda: True)
    run = Mock(return_value=SandboxResult(0, "", ""))
    monkeypatch.setattr(base_module, "run_sandboxed", run)

    module.run_sandboxed_tool(["true"], "target", timeout=timeout)

    assert run.call_args.args[4].total_seconds() == pytest.approx(expected, abs=1)


@pytest.mark.unit
@needs_landlock
def test_memory_limit_replaces_the_configured_one(root_analysis):
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")

    result = module.run_sandboxed_tool(_sh("ulimit -v"), observable.full_path, memory_limit=1024 ** 3)

    assert result.stdout.strip() == str(1024 ** 2)


@pytest.mark.unit
@needs_landlock
def test_a_tool_that_writes_past_the_file_size_limit_is_stopped(root_analysis, monkeypatch, caplog):
    monkeypatch.setattr(get_config().tool_sandbox, "file_size_limit", 1024 * 1024)
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")

    with caplog.at_level(logging.WARNING):
        assert module.run_sandboxed_tool(_sh("echo started; exec head -c 2000000 /dev/zero > big.bin"),
                                         observable.full_path, outputs={"big.bin": f"{observable.full_path}.big"}) is None

    # what it wrote was cut off at the limit, so it is not kept
    assert not os.path.exists(f"{observable.full_path}.big")
    [record] = [r for r in caplog.records if "file size limit" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == (f"SsdeepAnalyzer stopped sh on {os.path.abspath(observable.full_path)}: "
                                   f"it wrote a file larger than tool_sandbox's file size limit of 1048576 bytes")
    assert record.path == os.path.abspath(observable.full_path)


@pytest.mark.unit
@needs_landlock
@pytest.mark.skipif((os.cpu_count() or 1) < 4, reason="needs four cores")
def test_a_multithreaded_tool_runs_until_its_timeout(root_analysis):
    # john, 7z and the JVM run a thread per core, and RLIMIT_CPU counts the CPU time of all of them:
    # a limit equal to the timeout killed them a fraction of the way through it
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")
    # sha256 of a large buffer releases the GIL, so four threads keep four cores busy for 3 seconds
    script = ("import hashlib, threading, time\n"
              "def burn():\n"
              "    end = time.monotonic() + 3\n"
              "    while time.monotonic() < end:\n"
              "        hashlib.sha256(bytes(1 << 20)).digest()\n"
              "threads = [threading.Thread(target=burn) for _ in range(4)]\n"
              "for thread in threads: thread.start()\n"
              "for thread in threads: thread.join()\n"
              "print('done')\n")

    result = module.run_sandboxed_tool([sandbox_python(), "-I", "-c", script], observable.full_path, timeout=8)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "done\n"


@pytest.mark.unit
@pytest.mark.parametrize("program,reason", [
    ("/nonexistent/tool", "/nonexistent/tool not found"),
    # the directory of a program is made readable to it, never one that holds SAQ_HOME
    ("ace", "which cannot be made readable to the tool"),
])
def test_a_tool_that_cannot_run_is_reported_once(root_analysis, caplog, program, reason):
    if program == "ace":
        program = os.path.join(get_base_dir(), "ace")
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)

    with caplog.at_level(logging.WARNING):
        assert module.run_sandboxed_tool([program], "first") is None
        assert module.run_sandboxed_tool([program], "second") is None

    records = [r for r in caplog.records if f"cannot run {program} in the sandbox" in r.getMessage()]
    assert [r.levelno for r in records] == [logging.ERROR, logging.WARNING]
    assert reason in records[0].getMessage()
    # an operator's problem, so it gets an error report
    assert records[0].exc_info


@pytest.mark.unit
@needs_landlock
def test_a_program_the_sandbox_cannot_start_is_reported(root_analysis, fake_tools, caplog):
    # a wrapper that execs a binary in a directory the sandbox does not make readable (the de4dot wrapper did)
    fake_tools({"wrapper": f"exec {get_base_dir()}/ace"})
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")

    with caplog.at_level(logging.WARNING):
        assert module.run_sandboxed_tool(["wrapper"], observable.full_path) is None

    [record] = [r for r in caplog.records if "cannot run" in r.getMessage()]
    assert record.levelno == logging.ERROR
    assert "Permission denied" in record.getMessage()


@pytest.mark.unit
def test_a_landlock_probe_that_could_not_run_is_not_blamed_on_the_node(root_analysis, monkeypatch, caplog):
    # landlock_available() reported why the probe could not run (a fork that failed under load)
    monkeypatch.setattr(base_module, "landlock_available", lambda: None)
    run = Mock()
    monkeypatch.setattr(base_module, "run_sandboxed", run)
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)

    with caplog.at_level(logging.WARNING):
        assert module.run_sandboxed_tool(["true"], "target") is None

    run.assert_not_called()
    [record] = [r for r in caplog.records if "SsdeepAnalyzer" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert "the Landlock probe could not run" in record.getMessage()
    # the next tool that cannot run on this node is still reported
    assert not base_module._REPORTED_SANDBOX_FAILURES


@pytest.mark.unit
def test_without_landlock_no_tool_runs(root_analysis, monkeypatch, caplog):
    monkeypatch.setattr(base_module, "landlock_available", lambda: False)
    run = Mock()
    monkeypatch.setattr(base_module, "run_sandboxed", run)
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)

    assert module.run_sandboxed_tool(["true"], "target") is None

    run.assert_not_called()
    assert any(r.levelno == logging.ERROR and "the Landlock sandbox is not available on this node" in r.getMessage()
               for r in caplog.records)


@pytest.mark.unit
@needs_landlock
def test_the_work_root_is_swept_once_per_process(root_analysis, monkeypatch):
    sweeps = []
    monkeypatch.setattr(base_module, "sweep_stale_workdirs", sweeps.append)
    module = _module(SsdeepAnalyzer, "ssdeep", root_analysis)
    observable = _file(root_analysis, "sample.bin", b"sample")

    module.run_sandboxed_tool(["true"], observable.full_path)
    module.run_sandboxed_tool(["true"], observable.full_path)

    assert sweeps == [os.path.abspath(os.path.join(get_data_dir(), get_config().tool_sandbox.work_dir))]
