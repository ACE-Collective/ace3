"""AnalysisModule.run_tool() and the modules that run their external tools through it. A tool that
does not finish is stopped before the module's call to analyze() runs out of time, where it used to
run until the engine killed the whole worker."""

import logging
import os
import subprocess
import time
from unittest.mock import Mock

import psutil
import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, AnalysisExecutionResult
from saq.modules.base_module import TOOL_TIMEOUT_MARGIN_SECONDS
from saq.modules.email.encryption.rar import RarEncryptionAnalysis, RarEncryptionAnalyzer
from saq.modules.email.encryption.zip import ZipEncryptionAnalysis, ZipEncryptionAnalyzer
from saq.modules.file_analysis.autoit import AutoItAnalysis, AutoItAnalyzer
from saq.modules.file_analysis.cve import CVE_2021_30657_Analysis, CVE_2021_30657_Analyzer
from saq.modules.file_analysis.dmg import DMGAnalysis, DMGAnalyzer
from saq.modules.file_analysis.file_type import FileTypeAnalysis, FileTypeAnalyzer
from saq.modules.file_analysis.mse import MicrosoftScriptEncodingAnalysis, MicrosoftScriptEncodingAnalyzer
from saq.modules.file_analysis.rtf import RTFOLEObjectAnalysis, RTFOLEObjectAnalyzer
from saq.modules.file_analysis.ssdeep import SsdeepAnalysis, SsdeepAnalyzer
from saq.modules.file_analysis.upx import UPXAnalysis, UPXAnalyzer
from tests.saq.modules.conftest import HANG, fake_tool_pids
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
    (TOOL_TIMEOUT_MARGIN_SECONDS, 1),
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

    assert run.call_args.kwargs["timeout"] == pytest.approx(expected, abs=1)


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
    assert not observable.get_analysis(MicrosoftScriptEncodingAnalysis).observables


@pytest.mark.integration
def test_dmg2img(root_analysis, fake_tools):
    tool_dir = fake_tools({"dmg2img": f'touch "${{1%.dmg}}.img"\n{HANG}'})
    module = _module(DMGAnalyzer, "dmg_analyzer", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "Installer.dmg", b"koly" * 10)

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    # the incomplete image is not kept
    assert not os.path.exists(observable.full_path[:-4] + ".img")
    assert not observable.get_analysis(DMGAnalysis).observables


@pytest.mark.integration
def test_dmg_listing(root_analysis, fake_tools):
    tool_dir = fake_tools({"dmg2img": 'echo image > "${1%.dmg}.img"', "7z": HANG})
    module = _module(DMGAnalyzer, "dmg_analyzer", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "Installer.dmg", b"koly" * 10)

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir, count=2)
    analysis = observable.get_analysis(DMGAnalysis)
    # the image is analyzed on its own; only its listing is missing
    assert [o.file_name for o in analysis.observables] == ["Installer.img"]
    assert analysis.details["file_list"] == []


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
def test_upx_test(root_analysis, fake_tools):
    tool_dir = fake_tools({"upx": HANG})
    module = _module(UPXAnalyzer, "upx", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "packed.exe", b"MZ packed")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    assert observable.get_analysis(UPXAnalysis) is None


@pytest.mark.integration
def test_upx_unpack(root_analysis, fake_tools):
    tool_dir = fake_tools({"upx": f'[ "$1" = -t ] && echo "testing $2 [OK]" && exit 0\n'
                                  f'touch "${{2#-o}}"\n{HANG}'})
    module = _module(UPXAnalyzer, "upx", root_analysis)
    _out_of_time(module)
    observable = _file(root_analysis, "packed.exe", b"MZ packed")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir, count=2)
    analysis = observable.get_analysis(UPXAnalysis)
    assert analysis.details["error"] == "upx -d timed out"
    assert not analysis.observables
    # the incomplete output is not kept
    assert not os.path.exists(f"{observable.full_path}.upx.exe")


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


@pytest.fixture
def data_dir_tool(fake_tools):
    """A python script for the modules that run `python <script>`, that never finishes."""
    tool_dir = fake_tools({})
    script = os.path.join(tool_dir, "rtfobj.py")
    pid_file = os.path.join(tool_dir, "script.pid")
    with open(script, "w") as fp:
        fp.write(f"import os, time\nopen({pid_file!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    return script, pid_file


@pytest.mark.integration
def test_rar2john(root_analysis, fake_tools, monkeypatch):
    import rarfile

    class _EncryptedRar:
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def needs_password(self):
            return True

    monkeypatch.setattr(rarfile, "RarFile", _EncryptedRar)
    tool_dir = fake_tools({"rar2john": HANG})
    module = _module(RarEncryptionAnalyzer, "rar_encryption_analyzer", root_analysis)
    monkeypatch.setattr(module.config, "john_bin_path", tool_dir)
    _out_of_time(module)
    observable = _file(root_analysis, "payload.rar", b"Rar!\x1a\x07\x01\x00")

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    assert observable.get_analysis(RarEncryptionAnalysis).error == "rar2john timed out"


@pytest.mark.integration
def test_zip2john(root_analysis, fake_tools, monkeypatch, tmp_path):
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
    _assert_stopped(tool_dir)
    assert observable.get_analysis(ZipEncryptionAnalysis).error == "zip2john timed out"


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
def test_cve_extraction(root_analysis, fake_tools, tmpdir):
    observable = _cve_target(root_analysis, tmpdir)
    tool_dir = fake_tools({"7z": HANG})
    module = _module(CVE_2021_30657_Analyzer, ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, root_analysis)
    _out_of_time(module)

    assert _run(module, observable) < 30
    # out of time: the second file is not tried
    _assert_stopped(tool_dir)
    assert observable.get_analysis(CVE_2021_30657_Analysis).suspect_files == {}


@pytest.mark.integration
def test_cve_mime_type(root_analysis, fake_tools, tmpdir):
    observable = _cve_target(root_analysis, tmpdir)
    tool_dir = fake_tools({"file": HANG})
    module = _module(CVE_2021_30657_Analyzer, ANALYSIS_MODULE_CVE_2021_30657_ANALYZER, root_analysis)
    _out_of_time(module)

    assert _run(module, observable) < 30
    _assert_stopped(tool_dir)
    assert observable.get_analysis(CVE_2021_30657_Analysis).suspect_files == {}


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
    warnings = [r for r in caplog.records if r.getMessage() == f"file command returned error output for {observable.full_path}"]
    assert len(warnings) == 2
