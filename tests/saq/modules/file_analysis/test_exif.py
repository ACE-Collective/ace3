import logging
import shutil
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis import exif as exif_module
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


@pytest.mark.integration
def test_exiftool_failure_is_recorded(root_analysis, monkeypatch, caplog):
    class BrokenExifToolHelper:
        def __enter__(self):
            raise RuntimeError("exiftool is not running")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(exif_module.exiftool, "ExifToolHelper", BrokenExifToolHelper)

    with caplog.at_level(logging.INFO):
        analysis = _analyze(root_analysis, SAMPLES / "sample_pdf_with_qr_code.pdf")

    assert isinstance(analysis, ExifAnalysis)
    assert analysis.error == "exiftool is not running"
    assert analysis.generate_summary() == "Exiftool Analysis: ⚠ exiftool is not running"
    assert analysis.get_observables_by_type(F_FILE) == []
    assert "Exif data extraction failed" in caplog.text
