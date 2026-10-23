from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import DIRECTIVE_SANDBOX
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.binary import BinaryFileAnalysis
from saq.util.uuid import get_storage_dir


def _analyze(root_analysis, path: Path):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("binary_file_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


@pytest.mark.integration
@pytest.mark.parametrize("name, content, unexpected", [
    # a null byte past the first read buffer
    ("document.rtf", b"{\\rtf1 " + b"a" * 10000 + b"\x00" + b"}", True),
    # RTF files often end with a null byte, which is ignored
    ("document.rtf", b"{\\rtf1 text}\x00", False),
    ("document.rtf", b"{\\rtf1 text}", False),
    # EPS only counts inside a Word document
    ("image.doc.eps", b"%!PS-Adobe-3.0 EPSF\x00\x00", True),
    ("image.doc.eps", b"\xc5\xd0\xd3\xc6" + b"\x00" * 10, True),
])
def test_unexpected_binary_data(root_analysis, tmp_path, name, content, unexpected):
    path = tmp_path / name
    path.write_bytes(content)

    target = _analyze(root_analysis, path)

    assert target.get_and_load_analysis(BinaryFileAnalysis)
    assert target.has_tag("unexpected_binary_data") == unexpected
    assert target.has_directive(DIRECTIVE_SANDBOX) == unexpected


@pytest.mark.integration
@pytest.mark.parametrize("name, content", [
    ("image.eps", b"%!PS-Adobe-3.0 EPSF\x00\x00"),
    ("program.exe", b"MZ\x00\x00"),
    ("empty.rtf", b""),
])
def test_unsupported_files(root_analysis, tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)

    assert not _analyze(root_analysis, path).get_and_load_analysis(BinaryFileAnalysis)
