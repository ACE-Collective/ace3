import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_SANDBOX
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_base_dir
from saq.modules.file_analysis.vbs import PCODEDMP_KILLED, PCodeAnalysis, VBScriptAnalysis
from saq.signatures.builtin import VBS_HEX_ENCODED_CONTENT
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import wait_for_condition
from tests.saq.modules.conftest import HANG, fake_tool_pids

OLE_FILES = Path(__file__).parent.parent / "test_file_analysis_full" / "ole_files"


def _analyze(root_analysis, path: Path, module: str):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


def _vbs(tmp_path: Path, content: str, name: str = "script.vbs") -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


#
# vbscript_analyzer (thresholds from etc/saq.default.yaml: large string > 50 chars, more than 100
# strings longer than 50 of one length, 15% of the file)
#

@pytest.mark.integration
def test_script_without_hex_strings(root_analysis, tmp_path):
    vbs = _analyze(root_analysis, _vbs(tmp_path, 'WScript.Echo "hello world"\n'), "vbscript_analyzer")

    assert not vbs.get_and_load_analysis(VBScriptAnalysis)


@pytest.mark.integration
def test_large_hex_string(root_analysis, tmp_path):
    hex_string = "4d5a90" * 20
    # mostly ordinary code, so it's under the percentage limit
    content = "' comment 0123456789abcdef0123456789abcdef\n" + 'Dim x\nx = "' + hex_string + '"\n' + "x = now\n" * 300

    vbs = _analyze(root_analysis, _vbs(tmp_path, content), "vbscript_analyzer")

    analysis = vbs.get_and_load_analysis(VBScriptAnalysis)
    # the commented-out hex is not counted
    assert analysis.total_hex_strings == 1
    assert analysis.largest_hex_string == len(hex_string)
    assert vbs.has_tag("large_hex_string")
    assert vbs.has_directive(DIRECTIVE_SANDBOX)
    assert not vbs.detections


@pytest.mark.integration
def test_hex_string_at_the_end_of_the_file(root_analysis, tmp_path):
    content = "x = now\n" * 300 + 'x = "' + "ab" * 40

    vbs = _analyze(root_analysis, _vbs(tmp_path, content), "vbscript_analyzer")

    analysis = vbs.get_and_load_analysis(VBScriptAnalysis)
    assert analysis.largest_hex_string == 80
    assert vbs.has_tag("large_hex_string")


@pytest.mark.integration
def test_mostly_hex(root_analysis, tmp_path):
    content = 'x = "' + "deadbeef" * 20 + '"\n'

    vbs = _analyze(root_analysis, _vbs(tmp_path, content), "vbscript_analyzer")

    analysis = vbs.get_and_load_analysis(VBScriptAnalysis)
    assert analysis.percentage_of_hex_strings > 15
    assert [d.signature_uuid for d in vbs.detections] == [VBS_HEX_ENCODED_CONTENT.uuid]
    assert vbs.detections[0].description.startswith("a large percentage of the file is ascii hex")


@pytest.mark.integration
def test_many_large_hex_strings_of_one_length(root_analysis, tmp_path):
    content = "".join(f'a{i} = "{"0123456789" * 6}"\n' for i in range(101))

    vbs = _analyze(root_analysis, _vbs(tmp_path, content), "vbscript_analyzer")

    descriptions = [d.description for d in vbs.detections]
    assert "large number of large hex strings of same length" in descriptions


@pytest.mark.integration
@pytest.mark.parametrize("name, content", [("script.txt", 'x = "' + "ab" * 40 + '"\n'), ("empty.vbs", "")])
def test_only_vbs_files(root_analysis, tmp_path, name, content):
    vbs = _analyze(root_analysis, _vbs(tmp_path, content, name=name), "vbscript_analyzer")

    assert not vbs.get_and_load_analysis(VBScriptAnalysis)


#
# pcodedmp
#

@pytest.mark.integration
def test_pcodedmp_on_a_document_without_macros(root_analysis, tmp_path):
    shutil.copy(Path(__file__).parent.parent / "test_file_analysis" / "doc.doc", tmp_path / "plain.doc")

    doc = _analyze(root_analysis, tmp_path / "plain.doc", "pcodedmp")

    assert not doc.get_and_load_analysis(PCodeAnalysis)
    # nothing is left behind
    assert not os.path.exists(f"{doc.full_path}.pcode.bas")


def _pcodedmp_pid(tool_dir: str) -> int:
    wait_for_condition(lambda: fake_tool_pids(tool_dir))
    return fake_tool_pids(tool_dir)[0]


def _gone(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fp:
            return fp.read().split(")")[-1].split()[0] == "Z"
    except FileNotFoundError:
        return True


def _run_wrapper(timeout: int, tool_dir: str, target: Path, **kwargs) -> subprocess.Popen:
    return subprocess.Popen([os.path.join(get_base_dir(), "bin", "pcodedmp_wrapper"), str(timeout),
                             os.path.join(tool_dir, "pcodedmp"), str(target)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)


@pytest.mark.unit
def test_pcodedmp_wrapper_stops_pcodedmp_at_its_deadline(tmp_path, fake_tools):
    tool_dir = fake_tools({"pcodedmp": HANG})
    p = _run_wrapper(1, tool_dir, tmp_path, start_new_session=True)
    pid = _pcodedmp_pid(tool_dir)

    # the caller goes away without waiting, as a killed worker would
    p.kill()
    p.wait()

    wait_for_condition(lambda: _gone(pid))


@pytest.mark.unit
def test_pcodedmp_wrapper_reports_a_killed_pcodedmp(tmp_path, fake_tools):
    tool_dir = fake_tools({"pcodedmp": HANG})
    p = _run_wrapper(1, tool_dir, tmp_path)

    assert p.wait(timeout=10) == PCODEDMP_KILLED


@pytest.mark.unit
def test_pcodedmp_wrapper_dies_with_its_callers_process_group(tmp_path, fake_tools):
    tool_dir = fake_tools({"pcodedmp": HANG})
    # the process group stands in for the worker's
    p = _run_wrapper(60, tool_dir, tmp_path, process_group=0)
    pid = _pcodedmp_pid(tool_dir)
    assert os.getpgid(pid) == p.pid

    os.killpg(p.pid, signal.SIGKILL)
    p.wait()

    wait_for_condition(lambda: _gone(pid))


@pytest.mark.integration
def test_pcodedmp_stays_in_the_workers_process_group(root_analysis, tmp_path, monkeypatch, fake_tools):
    # the fifth field of /proc/<pid>/stat is the process group
    tool_dir = fake_tools({"pcodedmp": "cut -d' ' -f5 /proc/$$/stat > \"$(dirname \"$0\")/pgid\""})
    monkeypatch.setattr(get_analysis_module_config("pcodedmp"), "pcodedmp_path", os.path.join(tool_dir, "pcodedmp"))
    shutil.copy(OLE_FILES / "receipt_687790.doc", tmp_path / "receipt.doc")

    # single threaded, the worker is this process
    _analyze(root_analysis, tmp_path / "receipt.doc", "pcodedmp")

    with open(os.path.join(tool_dir, "pgid")) as fp:
        assert int(fp.read()) == os.getpgrp()


@pytest.mark.integration
def test_pcodedmp_timeout(root_analysis, tmp_path, monkeypatch, caplog, fake_tools):
    monkeypatch.setattr("saq.modules.file_analysis.vbs.PCODEDMP_TIMEOUT", 1)
    tool_dir = fake_tools({"pcodedmp": HANG})
    monkeypatch.setattr(get_analysis_module_config("pcodedmp"), "pcodedmp_path", os.path.join(tool_dir, "pcodedmp"))
    shutil.copy(OLE_FILES / "receipt_687790.doc", tmp_path / "receipt.doc")

    doc = _analyze(root_analysis, tmp_path / "receipt.doc", "pcodedmp")

    assert not doc.get_and_load_analysis(PCodeAnalysis)
    assert not os.path.exists(f"{doc.full_path}.pcode.bas")
    assert not os.path.exists(f"{doc.full_path}.pcode.err")
    assert any(r.levelno == logging.WARNING and "pcodedmp timed out" in r.getMessage() for r in caplog.records)
    # the wrapper stopped it, the module did not have to
    assert not any("pcodedmp_wrapper did not exit" in r.getMessage() for r in caplog.records)
    pid = _pcodedmp_pid(tool_dir)
    assert _gone(pid)


@pytest.mark.integration
def test_pcodedmp_wrapper_that_does_not_exit(root_analysis, tmp_path, monkeypatch, caplog, fake_tools):
    # the module gives up on the wrapper a second before the wrapper stops pcodedmp
    monkeypatch.setattr("saq.modules.file_analysis.vbs.PCODEDMP_TIMEOUT", 2)
    monkeypatch.setattr("saq.modules.file_analysis.vbs.PCODEDMP_WAIT_MARGIN", -1)
    tool_dir = fake_tools({"pcodedmp": HANG})
    monkeypatch.setattr(get_analysis_module_config("pcodedmp"), "pcodedmp_path", os.path.join(tool_dir, "pcodedmp"))
    shutil.copy(OLE_FILES / "receipt_687790.doc", tmp_path / "receipt.doc")

    doc = _analyze(root_analysis, tmp_path / "receipt.doc", "pcodedmp")

    assert not doc.get_and_load_analysis(PCodeAnalysis)
    assert not os.path.exists(f"{doc.full_path}.pcode.bas")
    assert not os.path.exists(f"{doc.full_path}.pcode.err")
    assert any(r.levelno == logging.ERROR and r.exc_info and "pcodedmp_wrapper did not exit" in r.getMessage()
               for r in caplog.records)

    # pcodedmp still ends at its own deadline
    pid = _pcodedmp_pid(tool_dir)
    wait_for_condition(lambda: _gone(pid))
