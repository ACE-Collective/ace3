import logging
import shutil
from pathlib import Path

import pytest
from PIL import Image, ImageOps

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_QRCODE, F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.file_analysis.qrcode import QRCodeAnalysis, QRCodeAnalyzer, QRCodeFilter, _rendered_pages
from saq.sandbox.runner import SandboxResult
from saq.util.uuid import get_storage_dir
from tests.saq.test_util import create_test_context

DATA_DIR = Path(__file__).parent.parent / "test_file_analysis"
QR_IMAGE = DATA_DIR / "2910293944.gif"
QR_URL = "https://qrco.de/be1uHX"
# a version 8, level H code with a made-up mail icon on a white plate over its center. zbarimg finds no symbol in it
# and OpenCV reads it, as with the logo codes in real quishing PDFs. Generated, so no alert data.
LOGO_QR_IMAGE = DATA_DIR / "qr_with_logo.png"
LOGO_QR_URL = "https://qr-logo.example.com/landing?id=synthetic-fixture&email=user@example.com"
# the same code with concentric squares for an icon, shaped like a code's finder patterns
RINGS_QR_IMAGE = DATA_DIR / "qr_with_logo_rings.png"
LOGO_QR_IMAGE_2 = DATA_DIR / "qr_with_logo_2.png"
LOGO_QR_URL_2 = "https://qr-logo-two.example.com/?id=fixture-two&email=user@example.com"


def _pdf(path: Path, pages: int, qr_page: int, image: Path = QR_IMAGE) -> Path:
    """A PDF of blank pages with the QR code on page qr_page (1-based)."""
    with Image.open(image) as qr:
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
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "source.pdf", pages=2, qr_page=2), "scan[1].pdf")

    assert analysis.extracted_text == QR_URL

    # the rendered pages are found by globbing a path, in page order, so "[1]" in it must match itself
    pages = tmp_path / "pages[1]"
    pages.mkdir()
    for name in ("page-10.png", "page-2.png", "page-x.png"):
        (pages / name).touch()
    assert _rendered_pages(str(pages / "page-")) == [str(pages / "page-2.png"), str(pages / "page-10.png")]


@pytest.mark.unit
def test_long_pdf_scans_first_and_last_pages(tmp_path):
    # the first of the last three pages
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=10))

    assert analysis.extracted_text == QR_URL


@pytest.mark.unit
def test_long_pdf_skips_middle_pages(tmp_path):
    # the page before the last three
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=9))

    assert analysis.extracted_text is None


@pytest.mark.unit
@pytest.mark.parametrize("qr_page,expected", [(2, QR_URL), (6, None), (11, QR_URL)])
def test_long_pdf_fallback_render_keeps_page_order(tmp_path, monkeypatch, qr_page, expected):
    # without a page count every page is rendered and the first and last ones kept. page files used to be
    # sorted as strings (1, 10, 11, 12, 2, ...), which kept pages 1, 10, 11 and 7, 8, 9 of a 12 page PDF
    monkeypatch.setattr(QRCodeAnalyzer, "_get_pdf_page_count", lambda self, path: None)

    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "long.pdf", pages=12, qr_page=qr_page))

    assert analysis.extracted_text == expected


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
    filters.write_text("\n[unclosed\nQRCO\\.DE/\n")
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


@pytest.mark.unit
@pytest.mark.parametrize("result,logged", [
    (None, None),
    (SandboxResult(0, "Title: x\nPages: many\n", ""), "unreadable page count"),
    (SandboxResult(0, "Title: x\n", ""), None),
])
def test_pdf_page_count_that_cannot_be_read(tmp_path, monkeypatch, caplog, result, logged):
    # pdfinfo did not finish or printed no count: every page is rendered instead
    analyzer, _, _ = _analyze(tmp_path, QR_IMAGE)
    monkeypatch.setattr(analyzer, "run_sandboxed_tool", lambda args, target, **kwargs: result)

    assert analyzer._get_pdf_page_count(str(tmp_path / "document.pdf")) is None
    if logged:
        [record] = [r for r in caplog.records if logged in r.getMessage()]
        assert record.path == str(tmp_path / "document.pdf")


@pytest.mark.unit
def test_logo_qr_code_zbar_cannot_read(tmp_path):
    _, observable, analysis = _analyze(tmp_path, LOGO_QR_IMAGE)

    assert analysis.extracted_text == LOGO_QR_URL
    assert analysis.inverted is False
    extracted = [o for o in analysis.observables if o.type == F_FILE]
    assert len(extracted) == 1
    assert extracted[0].has_tag("qr-code")
    assert Path(extracted[0].full_path).read_text() == f"{LOGO_QR_URL}\n"


@pytest.mark.unit
def test_qr_code_with_finder_shaped_icon(tmp_path):
    _, _, analysis = _analyze(tmp_path, RINGS_QR_IMAGE)

    assert analysis.extracted_text == LOGO_QR_URL


@pytest.mark.integration
def test_logo_qr_code_through_the_engine(root_analysis, tmp_path):
    root_analysis.analysis_mode = "test_groups"
    target = Path(root_analysis.create_file_path("lure.png"))
    shutil.copy(LOGO_QR_IMAGE, target)
    observable = root_analysis.add_file_observable(str(target))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(ANALYSIS_MODULE_QRCODE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root.get_observable(observable.uuid).get_and_load_analysis(QRCodeAnalysis)
    assert analysis.extracted_text == LOGO_QR_URL
    [extracted] = [o for o in analysis.observables if o.type == F_FILE]
    assert extracted.has_tag("qr-code")


@pytest.mark.unit
def test_logo_qr_code_on_pdf_page(tmp_path):
    _, _, analysis = _analyze(tmp_path, _pdf(tmp_path / "lure.pdf", pages=2, qr_page=2, image=LOGO_QR_IMAGE))

    assert analysis.extracted_text == LOGO_QR_URL


@pytest.mark.unit
def test_inverted_logo_qr_code(tmp_path):
    inverted = tmp_path / "inverted.png"
    with Image.open(LOGO_QR_IMAGE) as qr:
        ImageOps.invert(qr.convert("RGB")).save(inverted)

    _, _, analysis = _analyze(tmp_path, inverted)

    assert analysis.extracted_text == LOGO_QR_URL
    assert analysis.inverted is True


@pytest.mark.unit
@pytest.mark.parametrize("second,expected", [
    (LOGO_QR_IMAGE, LOGO_QR_URL),
    (LOGO_QR_IMAGE_2, f"{LOGO_QR_URL}, {LOGO_QR_URL_2}"),
])
def test_two_logo_qr_codes_in_one_image(tmp_path, second, expected):
    with Image.open(LOGO_QR_IMAGE) as qr, Image.open(second) as other:
        both = Image.new("RGB", (qr.width + other.width + 40, qr.height + 40), "white")
        both.paste(qr.convert("RGB"), (10, 20))
        both.paste(other.convert("RGB"), (qr.width + 30, 20))
    both.save(tmp_path / "both.png")

    _, _, analysis = _analyze(tmp_path, tmp_path / "both.png")

    assert sorted(analysis.extracted_text.split(", ")) == sorted(expected.split(", "))


@pytest.mark.unit
def test_filter_applies_to_codes_opencv_reads(tmp_path, monkeypatch):
    filters = tmp_path / "qrcode_filters.txt"
    filters.write_text("qr-logo\\.example\\.com/\n")
    monkeypatch.setattr(QRCodeAnalyzer, "qrcode_filter_path", property(lambda self: str(filters)))

    _, _, analysis = _analyze(tmp_path, LOGO_QR_IMAGE)

    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text is None


@pytest.mark.unit
@pytest.mark.parametrize("name", ["blank.png", "blank.ico"])
def test_image_without_a_code_is_a_negative_result(tmp_path, name):
    # OpenCV cannot load an .ico, which is not the same as the scan failing
    Image.new("RGB", (64, 64), "white").save(tmp_path / name)

    _, _, analysis = _analyze(tmp_path, tmp_path / name)

    assert isinstance(analysis, QRCodeAnalysis)
    assert analysis.extracted_text is None


def _running_opencv(monkeypatch, fake_result=None):
    """Records the sandboxed OpenCV runs; with fake_result, they return that instead of running."""
    runs = []
    run_sandboxed_tool = QRCodeAnalyzer.run_sandboxed_tool

    def recording(self, args, target, **kwargs):
        if not any(arg.endswith("qr_decode_opencv.py") for arg in args):
            return run_sandboxed_tool(self, args, target, **kwargs)
        runs.append(target)
        return fake_result or run_sandboxed_tool(self, args, target, **kwargs)

    monkeypatch.setattr(QRCodeAnalyzer, "run_sandboxed_tool", recording)
    return runs


@pytest.mark.unit
def test_opencv_only_runs_when_zbar_finds_nothing(tmp_path, monkeypatch):
    runs = _running_opencv(monkeypatch)

    _, _, analysis = _analyze(tmp_path, QR_IMAGE)

    assert analysis.extracted_text == QR_URL
    assert runs == []


@pytest.mark.unit
def test_opencv_runs_once_on_an_image_without_a_code(tmp_path, monkeypatch):
    runs = _running_opencv(monkeypatch)
    Image.new("RGB", (64, 64), "white").save(tmp_path / "blank.png")

    _, observable, analysis = _analyze(tmp_path, tmp_path / "blank.png")

    assert analysis.extracted_text is None
    assert runs == [observable.full_path]


@pytest.mark.unit
def test_opencv_timeout_is_not_a_negative_result(tmp_path, monkeypatch):
    # run_sandboxed_tool returns None for a tool it stopped, which it has already logged
    def stopped(self, args, target, **kwargs):
        if any(arg.endswith("qr_decode_opencv.py") for arg in args):
            return None
        return real(self, args, target, **kwargs)

    real = QRCodeAnalyzer.run_sandboxed_tool
    monkeypatch.setattr(QRCodeAnalyzer, "run_sandboxed_tool", stopped)
    Image.new("RGB", (64, 64), "white").save(tmp_path / "blank.png")

    _, _, analysis = _analyze(tmp_path, tmp_path / "blank.png")

    assert analysis is None


@pytest.mark.unit
def test_opencv_failure_is_not_a_negative_result(tmp_path, monkeypatch, caplog):
    runs = _running_opencv(monkeypatch, SandboxResult(1, "", "Traceback: cv2.error: bad image"))
    Image.new("RGB", (64, 64), "white").save(tmp_path / "blank.png")

    _, _, analysis = _analyze(tmp_path, tmp_path / "blank.png")

    assert runs
    assert analysis is None
    records = [r for r in caplog.records if "opencv qr decoding failed" in r.getMessage()]
    assert records and "cv2.error: bad image" in records[0].getMessage()
    assert records[0].path in runs


@pytest.mark.unit
def test_opencv_that_cannot_load_is_an_error(tmp_path, monkeypatch, caplog):
    # under this address space limit the interpreter starts but cv2's shared libraries do not map,
    # as on a node whose tool_sandbox.memory_limit is too low for OpenCV
    run_sandboxed_tool = QRCodeAnalyzer.run_sandboxed_tool

    def starved(self, args, target, **kwargs):
        if any(arg.endswith("qr_decode_opencv.py") for arg in args):
            kwargs["memory_limit"] = 175 * 1024 ** 2
        return run_sandboxed_tool(self, args, target, **kwargs)

    monkeypatch.setattr(QRCodeAnalyzer, "run_sandboxed_tool", starved)

    _, observable, analysis = _analyze(tmp_path, LOGO_QR_IMAGE)

    assert analysis is None
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert "cannot load OpenCV" in record.getMessage()
    assert record.exc_info
    assert record.path == observable.full_path


@pytest.mark.unit
def test_code_opencv_reads_is_logged(tmp_path, caplog):
    caplog.set_level(logging.INFO)

    _, observable, _ = _analyze(tmp_path, LOGO_QR_IMAGE)

    [record] = [r for r in caplog.records if "opencv read a QR code" in r.getMessage()]
    assert record.path == observable.full_path
