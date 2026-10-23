import base64
import logging
import subprocess
from pathlib import Path

import pikepdf
import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.archive import ArchiveAnalyzer
from saq.modules.file_analysis.pdf import PDFAnalysis, PDFTextAnalysis
from saq.util.uuid import get_storage_dir

TEXT = "Your invoice is ready"
FORM_PAYLOAD = b"<script>location='https://form.example.com/landing'</script>" * 2


def _pdf(tmp_path: Path, name: str = "document.pdf", annotation_uri: str = None, form_value: str = None, javascript: dict = None) -> Path:
    pdf = pikepdf.new()
    font = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica))
    contents = pdf.make_stream(f"BT /F1 24 Tf 72 720 Td ({TEXT}) Tj ET".encode())
    page = pikepdf.Dictionary(
        Type=pikepdf.Name.Page,
        MediaBox=[0, 0, 612, 792],
        Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)),
        Contents=contents,
    )
    if annotation_uri:
        page.Annots = pdf.make_indirect(pikepdf.Array([pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name.Annot,
            Subtype=pikepdf.Name.Link,
            Rect=[72, 700, 300, 740],
            A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(annotation_uri)),
        ))]))
    pdf.pages.append(pikepdf.Page(page))

    if form_value is not None:
        field = pdf.make_indirect(pikepdf.Dictionary(FT=pikepdf.Name.Tx, T=pikepdf.String("pay load!"), V=pikepdf.Name("/" + form_value)))
        pdf.Root.AcroForm = pikepdf.Dictionary(Fields=pikepdf.Array([field]))

    if javascript:
        names = pikepdf.Array()
        for js_name, code in javascript.items():
            js = pdf.make_stream(code.encode()) if js_name.startswith("stream") else pikepdf.String(code)
            names.append(pikepdf.String(js_name))
            names.append(pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=js)))
        pdf.Root.Names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=names))

    path = tmp_path / name
    pdf.save(path)
    return path


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


def _outputs(analysis) -> dict:
    return {o.file_name: o for o in analysis.observables if o.type == F_FILE}


def _assert_extracted_from(output, pdf_observable):
    assert output.redirection.uuid == pdf_observable.uuid
    assert output.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == pdf_observable.uuid
    assert output.has_directive(DIRECTIVE_EXTRACT_URLS)


#
# pdf_analyzer
#

@pytest.mark.integration
def test_pdf_analyzer_outputs(root_analysis, tmp_path):
    form_value = base64.b64encode(FORM_PAYLOAD).decode()
    pdf = _analyze(root_analysis, _pdf(
        tmp_path,
        annotation_uri="https://annotation.example.com/click",
        form_value=form_value,
        javascript={"open": "app.launchURL('https://js.example.com/a');", "stream js": "this.exportDataObject({cName: 'x'});"},
    ), "pdf_analyzer")

    analysis = pdf.get_and_load_analysis(PDFAnalysis)
    outputs = _outputs(analysis)
    assert set(outputs) == {
        "document.pdf.pdfparser",
        "document.pdf.gs.pdf",
        "document.pdf.annotation_uris.txt",
        "document.pdf.field_pay_load__decoded.bin",
        "document.pdf.js_open.js",
        "document.pdf.js_stream_js.js",
    }
    for output in outputs.values():
        _assert_extracted_from(output, pdf)

    with open(outputs["document.pdf.annotation_uris.txt"].full_path) as fp:
        assert fp.read() == "https://annotation.example.com/click"
    with open(outputs["document.pdf.field_pay_load__decoded.bin"].full_path, "rb") as fp:
        assert fp.read() == FORM_PAYLOAD
    with open(outputs["document.pdf.js_open.js"].full_path) as fp:
        assert fp.read() == "app.launchURL('https://js.example.com/a');"
    with open(outputs["document.pdf.js_stream_js.js"].full_path) as fp:
        assert fp.read() == "this.exportDataObject({cName: 'x'});"

    # the pdf_analyzer doesn't analyze what it extracted
    assert not outputs["document.pdf.gs.pdf"].get_and_load_analysis(PDFAnalysis)


@pytest.mark.integration
@pytest.mark.parametrize("form_value", [
    "short",
    # long enough, but not base64
    "not-base64!" * 10,
    # base64, but decodes to too few bytes to be a payload
    base64.b64encode(b"x" * 20).decode() + "=" * 40,
])
def test_pdf_analyzer_ignores_form_values_that_are_not_payloads(root_analysis, tmp_path, form_value):
    pdf = _analyze(root_analysis, _pdf(tmp_path, form_value=form_value), "pdf_analyzer")

    assert not [name for name in _outputs(pdf.get_and_load_analysis(PDFAnalysis)) if "field_" in name]


@pytest.mark.integration
def test_pdf_analyzer_skips_empty_javascript(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _pdf(tmp_path, javascript={"blank": "   "}), "pdf_analyzer")

    assert not [name for name in _outputs(pdf.get_and_load_analysis(PDFAnalysis)) if ".js_" in name]


@pytest.mark.integration
def test_pdf_analyzer_ignores_files_that_are_not_pdfs(root_analysis, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a pdf")

    assert not _analyze(root_analysis, path, "pdf_analyzer").get_and_load_analysis(PDFAnalysis)


@pytest.mark.integration
def test_pdf_analyzer_survives_a_pdf_pikepdf_cannot_open(root_analysis, tmp_path, caplog):
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.7\n garbage that is not a pdf body")

    pdf = _analyze(root_analysis, path, "pdf_analyzer")

    assert pdf.get_and_load_analysis(PDFAnalysis)
    assert any(r.levelno == logging.WARNING and "pikepdf failed to open" in r.getMessage() for r in caplog.records)


#
# pdftotext
#

@pytest.mark.integration
def test_pdftotext(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _pdf(tmp_path), "pdftotext")

    analysis = pdf.get_and_load_analysis(PDFTextAnalysis)
    assert analysis.summary == "PDF Text Analysis"
    [text] = [o for o in analysis.observables if o.type == F_FILE]
    assert text.file_name == "document.pdf.txt"
    assert analysis.output_path == text.value
    assert text.redirection.uuid == pdf.uuid
    assert any(ArchiveAnalyzer.__name__ in name for name in text.excluded_analysis)
    with open(text.full_path) as fp:
        assert TEXT in fp.read()


@pytest.mark.integration
def test_pdftotext_names_output_of_a_pdf_without_the_extension(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _pdf(tmp_path, name="attachment.bin"), "pdftotext")

    [text] = [o for o in pdf.get_and_load_analysis(PDFTextAnalysis).observables if o.type == F_FILE]
    assert text.file_name == "attachment.bin.pdf.txt"


@pytest.mark.integration
def test_pdftotext_ignores_files_that_are_not_pdfs(root_analysis, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a pdf")

    assert not _analyze(root_analysis, path, "pdftotext").get_and_load_analysis(PDFTextAnalysis)


@pytest.mark.integration
def test_pdftotext_timeout_stops_it(root_analysis, tmp_path, monkeypatch, caplog):
    get_analysis_module_config("pdftotext").timeout = 1
    real_popen = subprocess.Popen
    processes = []

    def _popen(args, *a, **kw):
        process = real_popen(["sleep", "60"], *a, **kw)
        processes.append(process)
        return process

    monkeypatch.setattr("saq.modules.file_analysis.pdf.Popen", _popen)
    pdf = _analyze(root_analysis, _pdf(tmp_path), "pdftotext")

    analysis = pdf.get_and_load_analysis(PDFTextAnalysis)
    assert analysis.output_path is None
    # killed and reaped, not left running
    assert [p.returncode for p in processes] == [-9]
    assert any(r.levelno == logging.WARNING and "timeout executing" in r.getMessage() for r in caplog.records)
