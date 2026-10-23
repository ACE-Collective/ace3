import logging
import shutil
from pathlib import Path

import pytest
from PIL import Image

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_QRCODE, F_FILE
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.qrcode import QRCodeAnalysis, QRCodeAnalyzer, QRCodeFilter
from tests.saq.test_util import create_test_context

DATA_DIR = Path(__file__).parent.parent / "test_file_analysis"
QR_IMAGE = DATA_DIR / "2910293944.gif"
QR_URL = "https://qrco.de/be1uHX"


def _pdf(path: Path, pages: int, qr_page: int) -> Path:
    """A PDF of blank pages with the QR code on page qr_page (1-based)."""
    with Image.open(QR_IMAGE) as qr:
        qr = qr.convert("RGB")
        blank = Image.new("RGB", qr.size, "white")
        images = [qr if page == qr_page else blank for page in range(1, pages + 1)]
        images[0].save(path, save_all=True, append_images=images[1:])
    return path


def _analyze(tmp_path, source: Path, file_name: str = None, **config):
    root = RootAnalysis(storage_dir=str(tmp_path / "root"))
    root.initialize_storage()
    target = Path(root.create_file_path(file_name or source.name))
    shutil.copy(source, target)
    observable = root.add_file_observable(str(target))

    module_config = get_analysis_module_config(ANALYSIS_MODULE_QRCODE).model_copy(update=config)
    analyzer = QRCodeAnalyzer(context=create_test_context(root=root), config=module_config)
    AnalysisModuleAdapter(analyzer).execute_analysis(observable)
    return analyzer, observable, observable.get_and_load_analysis(QRCodeAnalysis)


@pytest.mark.unit
def test_pdf_name_with_glob_characters(tmp_path):
    # the rendered pages are found by globbing the attachment's path, so "[1]" matched nothing
    _, observable, analysis = _analyze(tmp_path, _pdf(tmp_path / "source.pdf", pages=2, qr_page=2), "scan[1].pdf")

    assert analysis.extracted_text == QR_URL
    # the rendered pages are removed
    assert sorted(p.name for p in Path(observable.full_path).parent.glob("*.png")) == []


@pytest.mark.unit
def test_long_pdf_scans_first_and_last_pages(tmp_path):
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=11))

    assert analysis.extracted_text == QR_URL


@pytest.mark.unit
def test_long_pdf_skips_middle_pages(tmp_path):
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=6))

    assert analysis.extracted_text is None


@pytest.mark.unit
@pytest.mark.parametrize("qr_page", [2, 11])
def test_long_pdf_fallback_render_keeps_page_order(tmp_path, monkeypatch, qr_page):
    # without a page count every page is rendered and the first and last ones kept. page files used to be
    # sorted as strings (1, 10, 11, 12, 2, ...), which kept pages 1, 10, 11 and 7, 8, 9 of a 12 page PDF
    monkeypatch.setattr(QRCodeAnalyzer, "_get_pdf_page_count", lambda self, path: None)

    _, observable, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=qr_page))

    assert analysis.extracted_text == QR_URL
    assert list(Path(observable.full_path).parent.glob("*.png")) == []


@pytest.mark.unit
def test_pdf_selective_render_failure_falls_back(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(QRCodeAnalyzer, "_render_pdf_pages", lambda self, *args: False)

    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "short.pdf", pages=2, qr_page=1))

    assert analysis.extracted_text == QR_URL
    assert any("falling back to full render" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_pdf_that_cannot_be_rendered(tmp_path, caplog):
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(b"%PDF-1.7\nnot really a pdf\n")

    _, observable, analysis = _analyze(tmp_path, broken)

    assert analysis is None
    assert any("pdfinfo" in r.getMessage() or "conversion of" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_filtered_url(tmp_path, monkeypatch, caplog):
    filters = tmp_path / "qrcode_filters.txt"
    filters.write_text("\n[unclosed\nqrco\\.de/\n")
    monkeypatch.setattr(QRCodeAnalyzer, "qrcode_filter_path", property(lambda self: str(filters)))

    _, _, analysis = _analyze(tmp_path, QR_IMAGE)

    # scanned, nothing left after filtering: a negative result
    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text is None
    assert analysis.generate_summary() is None
    assert any(r.levelno == logging.ERROR and "[unclosed" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_filter_file_missing(tmp_path, caplog):
    qrcode_filter = QRCodeFilter(str(tmp_path / "missing.txt"))
    qrcode_filter.load()

    assert qrcode_filter.url_filters == []
    assert not qrcode_filter.is_filtered(QR_URL)
    assert not qrcode_filter.is_filtered("")
    assert any("unable to load qr code filters" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_extract_valid_urls_skips_text(tmp_path):
    analyzer, _, _ = _analyze(tmp_path, QR_IMAGE)

    assert analyzer._extract_valid_urls("WIFI\n\nhttps://a.example.com/x\nexample.com\n", None) == [
        "https://a.example.com/x", "example.com"]


@pytest.mark.unit
def test_scan_failures_return_none(tmp_path, caplog):
    analyzer, _, _ = _analyze(tmp_path, QR_IMAGE)
    not_an_image = tmp_path / "notes.txt"
    not_an_image.write_text("just some text")

    assert analyzer._scan_image(str(not_an_image)) is None
    assert analyzer._scan_inverted_image(str(not_an_image)) is None
    assert any("zbarimg failed" in r.getMessage() for r in caplog.records)
    assert any("unable to invert image" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_summary(tmp_path):
    analysis = QRCodeAnalysis()
    analysis.extracted_text = QR_URL
    analysis.inverted = True

    assert analysis.generate_summary() == f"QR Code Analysis: INVERTED: {QR_URL}"
    analysis.details = None
    assert analysis.extracted_text == []
    assert analysis.inverted is False
