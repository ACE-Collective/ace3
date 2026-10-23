import os
import struct
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.rtf import ExtractedRTFAnalysis, NoWhiteSpaceAnalysis, RTFOLEObjectAnalysis
from saq.signatures.builtin import RTF_EXTRACTED_SUSPECT_FILE
from saq.util.uuid import get_storage_dir

PAYLOAD = b"MZ" + b"\x90" * 64


def _ole1_package(filename: bytes, payload: bytes) -> bytes:
    """An embedded OLE1 Package object (MS-OLEDS 2.2.4) holding one file."""
    source = b"C:\\tmp\\" + filename
    native = struct.pack("<H", 2) + filename + b"\x00" + source + b"\x00" + struct.pack("<II", 0, 0)
    native += source + b"\x00" + struct.pack("<I", len(payload)) + payload
    class_name = b"Package\x00"
    header = struct.pack("<II", 0x00000501, 2) + struct.pack("<I", len(class_name)) + class_name + struct.pack("<II", 0, 0)
    return header + struct.pack("<I", len(native)) + native


def _rtf(tmp_path: Path, name: str = "document.rtf", filename: bytes = b"payload.exe", payload: bytes = PAYLOAD) -> Path:
    path = tmp_path / name
    data = _ole1_package(filename, payload).hex().encode()
    path.write_bytes(b"{\\rtf1\\ansi Hello \\par\r\n{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata " + data + b"}}}")
    return path


def _analyze(root_analysis, path: Path, modules: tuple[str, ...]):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in modules:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


@pytest.mark.integration
def test_extracts_ole_objects(root_analysis, tmp_path):
    rtf = _analyze(root_analysis, _rtf(tmp_path), ("rtfole",))

    analysis = rtf.get_and_load_analysis(RTFOLEObjectAnalysis)
    assert analysis.return_code == 0
    # rtfobj's report is its stdout
    assert "payload.exe" in analysis.stdout
    assert analysis.stderr == ""
    assert [os.path.basename(path) for path in analysis.extracted_files] == ["document.rtf_payload.exe"]
    assert analysis.summary.startswith("RTF OLE Object Analysis: extracted ")

    [extracted] = [o for o in analysis.observables if o.type == F_FILE]
    assert extracted.file_name == "document.rtf_payload.exe"
    assert extracted.has_tag("extracted_rtf")
    assert extracted.redirection.uuid == rtf.uuid
    assert extracted.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == rtf.uuid
    with open(extracted.full_path, "rb") as fp:
        assert fp.read() == PAYLOAD


@pytest.mark.integration
def test_extracted_files_in_subdirectories(root_analysis, tmp_path, monkeypatch):
    real_walk = os.walk

    def _walk(top):
        # what rtfobj would leave if it saved into a subdirectory
        nested = os.path.join(top, "nested")
        os.makedirs(nested, exist_ok=True)
        with open(os.path.join(nested, "inner.bin"), "wb") as fp:
            fp.write(b"inner")
        return real_walk(top)

    monkeypatch.setattr("saq.modules.file_analysis.rtf.os.walk", _walk)
    rtf = _analyze(root_analysis, _rtf(tmp_path), ("rtfole",))

    analysis = rtf.get_and_load_analysis(RTFOLEObjectAnalysis)
    assert sorted(o.file_name for o in analysis.observables if o.type == F_FILE) == ["document.rtf_payload.exe", "inner.bin"]


@pytest.mark.integration
@pytest.mark.parametrize("name, content", [("notes.txt", b"just text"), ("empty.rtf", b"")])
def test_ignores_files_that_are_not_rtf(root_analysis, tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)

    target = _analyze(root_analysis, path, ("rtfole", "nowhitespace_analyzer"))

    assert not target.get_and_load_analysis(RTFOLEObjectAnalysis)
    assert not target.get_and_load_analysis(NoWhiteSpaceAnalysis)


@pytest.mark.integration
def test_rtfobj_failure_is_recorded(root_analysis, tmp_path, monkeypatch):
    from saq.configuration.config import get_analysis_module_config

    script = tmp_path / "rtfobj"
    script.write_text("import sys\nsys.stderr.write('rtfobj blew up')\nsys.exit(2)\n")
    get_analysis_module_config("rtfole").rtfobj_path = str(script)

    analysis = _analyze(root_analysis, _rtf(tmp_path), ("rtfole",)).get_and_load_analysis(RTFOLEObjectAnalysis)

    assert analysis.return_code == 2
    assert analysis.stderr == "rtfobj blew up"
    assert analysis.stdout == ""
    assert analysis.extracted_files == []
    assert analysis.summary is None


@pytest.mark.integration
def test_suspect_extracted_file(root_analysis, tmp_path):
    rtf = _analyze(root_analysis, _rtf(tmp_path), ("rtfole", "file_type", "extracted_rtf_analyzer"))

    [extracted] = [o for o in rtf.get_and_load_analysis(RTFOLEObjectAnalysis).observables if o.type == F_FILE]
    assert extracted.get_and_load_analysis(ExtractedRTFAnalysis)
    # .exe is a suspect extension
    assert extracted.has_directive(DIRECTIVE_SANDBOX)
    assert {d.signature_uuid for d in extracted.detections} == {RTF_EXTRACTED_SUSPECT_FILE.uuid}
    assert "file extracted from RTF has suspect file extension" in [d.description for d in extracted.detections]


@pytest.mark.integration
def test_harmless_extracted_file(root_analysis, tmp_path):
    rtf = _analyze(root_analysis, _rtf(tmp_path, filename=b"notes.txt", payload=b"plain text notes\n" * 10), ("rtfole", "file_type", "extracted_rtf_analyzer"))

    [extracted] = [o for o in rtf.get_and_load_analysis(RTFOLEObjectAnalysis).observables if o.type == F_FILE]
    assert extracted.get_and_load_analysis(ExtractedRTFAnalysis)
    assert not extracted.detections
    assert not extracted.has_directive(DIRECTIVE_SANDBOX)


@pytest.mark.integration
def test_strips_whitespace(root_analysis, tmp_path):
    path = tmp_path / "spaced.rtf"
    path.write_bytes(b"{\\rtf1 \\ansi\r\n\t{\\*\\objdata 01 05\f00\v00 }}" * 1000)

    rtf = _analyze(root_analysis, path, ("nowhitespace_analyzer",))

    analysis = rtf.get_and_load_analysis(NoWhiteSpaceAnalysis)
    assert analysis.count == 9000
    assert analysis.summary == "NoWhiteSpaceAnalysis: Ignore Whitespace Characters (9000 removed)"
    [stripped] = [o for o in analysis.observables if o.type == F_FILE]
    assert stripped.file_name == "spaced.rtf.nowhitespace"
    assert stripped.redirection.uuid == rtf.uuid
    with open(stripped.full_path, "rb") as fp:
        assert fp.read() == b"{\\rtf1\\ansi{\\*\\objdata01050000}}" * 1000
    # the stripped copy is not stripped again
    assert not stripped.get_and_load_analysis(NoWhiteSpaceAnalysis)
