import hashlib
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import F_MD5, F_SHA256, R_IS_HASH_OF
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.hash import FileHashAnalysis
from saq.util.uuid import get_storage_dir


def _analyze(root_analysis, path: Path, modules=("file_type", "file_hash_analyzer")):
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
def test_hashes(root_analysis, tmp_path):
    content = b"a document worth hashing\n" * 10
    path = tmp_path / "document.bin"
    path.write_bytes(content)

    target = _analyze(root_analysis, path)

    analysis = target.get_and_load_analysis(FileHashAnalysis)
    assert analysis.md5 == hashlib.md5(content).hexdigest()
    assert analysis.sha1 == hashlib.sha1(content).hexdigest()
    assert analysis.sha256 == hashlib.sha256(content).hexdigest()

    observables = {o.type: o for o in analysis.observables}
    assert observables[F_MD5].value == analysis.md5
    assert observables[F_SHA256].value == analysis.sha256
    for observable in observables.values():
        assert observable.get_relationship_by_type(R_IS_HASH_OF).target.uuid == target.uuid


@pytest.mark.integration
@pytest.mark.parametrize("name, content", [
    # ignore_pattern_pdfparser
    ("report.pdf.pdfparser", b"pdf-parser output\n" * 10),
    # ignore_mime_type_images
    ("image.dat", b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"),
    ("empty.bin", b""),
])
def test_skipped_files(root_analysis, tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)

    assert not _analyze(root_analysis, path).get_and_load_analysis(FileHashAnalysis)


@pytest.mark.integration
def test_needs_file_type_analysis(root_analysis, tmp_path):
    path = tmp_path / "document.bin"
    path.write_bytes(b"content\n")

    assert not _analyze(root_analysis, path, modules=("file_hash_analyzer",)).get_and_load_analysis(FileHashAnalysis)
