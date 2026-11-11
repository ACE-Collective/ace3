import base64
import logging
import time
import uuid
import zlib
from pathlib import Path
from types import SimpleNamespace

import pikepdf
import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.archive import ArchiveAnalyzer
from saq.modules.file_analysis import pdf as pdf_module
from saq.modules.file_analysis.exif import ExifAnalyzer
from saq.modules.file_analysis.pdf import (
    PDFAnalysis, PDFAnalyzer, PDFLinkTextAnalysis, PDFLinkTextAnalyzer, PDFTextAnalysis, PDFTextAnalyzer)
from saq.modules.file_analysis.qrcode import QRCodeAnalyzer
from saq.sandbox.runner import SandboxResult
from saq.util.uuid import get_storage_dir, storage_dir_from_uuid
from tests.saq.helpers import wait_for_condition

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


def _analyze(root_analysis, path: Path, *modules: str):
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

    # an unencrypted PDF gets no decrypted copy, which the set of outputs above shows, and no encryption details
    assert analysis.encryption is None
    assert analysis.summary is None
    assert not pdf.has_tag("encrypted_pdf_empty_password")


BBOX_OUTPUT = """<doc>
  <page width="612.000000" height="792.000000">
    <word xMin="72.000000" yMin="63.384000" xMax="108.684000" yMax="74.484000">Bids:</word>
    <word xMin="177.396000" yMin="63.384000" xMax="203.400000" yMax="74.484000">View</word>
    <word xMin="227.412000" yMin="63.384000" xMax="288.096000" yMax="74.484000">Documents</word>
    <word xMin="291.432000" yMin="63.384000" xMax="299.436000" yMax="74.484000">&amp;</word>
    <word xMin="72.000000" yMin="103.384000" xMax="108.684000" yMax="114.484000">Next</word>
  </page>
  <page width="612.000000" height="792.000000">
  </page>
</doc>"""


@pytest.mark.unit
def test_parse_bbox_words():
    pages, crowded = pdf_module.parse_bbox_words(BBOX_OUTPUT, 3, 100)

    assert set(pages) == {3, 4}
    assert pages[3][0] == (72.0, 63.384, 108.684, 74.484, "Bids:")
    assert pages[3][3][4] == "&"
    assert pages[4] == []
    assert crowded == []


@pytest.mark.unit
def test_parse_bbox_words_leaves_out_a_crowded_page():
    # the first page has five words
    assert pdf_module.parse_bbox_words(BBOX_OUTPUT, 1, 5)[0][1][4][4] == "Next"
    assert pdf_module.parse_bbox_words(BBOX_OUTPUT, 1, 4) == ({2: []}, [1])


@pytest.mark.unit
def test_parse_bbox_words_stops_reading_a_crowded_page(monkeypatch):
    words = "".join(f'<word xMin="1" yMin="1" xMax="2" yMax="2">w{n}</word>' for n in range(1000))
    short = "".join(f'<word xMin="1" yMin="1" xMax="2" yMax="2">s{n}</word>' for n in range(5))
    output = f'<page width="612" height="792">{words}</page><page width="612" height="792">{short}</page>'
    unescaped = []
    monkeypatch.setattr(pdf_module.html, "unescape", lambda text: unescaped.append(text) or text)

    pages, crowded = pdf_module.parse_bbox_words(output, 1, 10)

    # one word past the limit marks the page crowded; the rest of it is never kept
    assert crowded == [1]
    assert len(pages[2]) == 5
    assert len(unescaped) == 11 + 5


def _index():
    return pdf_module.index_words(pdf_module.parse_bbox_words(BBOX_OUTPUT, 1, 100)[0][1])


@pytest.mark.unit
def test_link_text():
    index = _index()

    # PDF space is from the bottom left: the first line is 717.5 to 728.6 points up the page
    assert pdf_module.link_text([175, 715, 290, 732], [0, 0, 612, 792], index, 500) == (
        "View Documents", "Bids: View Documents &")
    # a media box that does not start at 0 moves the page under the link
    assert pdf_module.link_text([275, 815, 390, 832], [100, 100, 712, 892], index, 500) == (
        "View Documents", "Bids: View Documents &")
    # nothing there
    assert pdf_module.link_text([400, 100, 500, 120], [0, 0, 612, 792], index, 500) == (None, None)


@pytest.mark.unit
def test_link_text_keeps_reading_order():
    # the taller word sits lower, so its center sorts first, but the line still reads left to right
    words = [(72.0, 60.0, 100.0, 70.0, "View"), (104.0, 56.0, 150.0, 72.0, "Documents")]

    assert pdf_module.link_text([70, 715, 160, 735], [0, 0, 612, 792], pdf_module.index_words(words), 500) == (
        "View Documents", "View Documents")


@pytest.mark.unit
def test_link_text_box_over_a_page_gets_no_text():
    index = _index()

    assert pdf_module.link_text([0, 0, 612, 792], [0, 0, 612, 792], index, 3) == (None, None)
    # one line of four words is still more than three
    assert pdf_module.link_text([175, 715, 290, 732], [0, 0, 612, 792], index, 3) == (None, None)
    assert pdf_module.link_text([175, 715, 290, 732], [0, 0, 612, 792], index, 4) == (
        "View Documents", "Bids: View Documents &")


def _pdf_with_links(tmp_path: Path, pages: list[list], rotate: int = 0, texts: list[str] = None) -> Path:
    """A PDF with TEXT (or the given text) on each page and, on each page, the link annotations given for it as
    (uri, rect, contents)."""
    pdf = pikepdf.new()
    font = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica))
    for number, annotations in enumerate(pages):
        text = texts[number] if texts else TEXT
        links = []
        for uri, rect, contents in annotations:
            link = pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=rect,
                                      A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(uri)))
            if contents:
                link.Contents = pikepdf.String(contents)
            links.append(pdf.make_indirect(link))
        if links:
            # the same annotation object, many times over: a few bytes of PDF each
            links.extend([links[0]] * 1000)
        page = pikepdf.Dictionary(
            Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792], Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)),
            Contents=pdf.make_stream(f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()),
            Annots=pdf.make_indirect(pikepdf.Array(links)))
        if rotate:
            page.Rotate = rotate
        pdf.pages.append(pikepdf.Page(page))
    path = tmp_path / "links.pdf"
    pdf.save(path)
    return path


LINK_BOX = [72, 700, 300, 740]


def _links(root_analysis, path: Path) -> list[dict]:
    pdf = _analyze(root_analysis, path, "pdf_link_text")
    analysis = pdf.get_and_load_analysis(PDFLinkTextAnalysis)
    return analysis.links if analysis else None


@pytest.mark.integration
def test_pdf_link_text(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click"),
                   "pdf_link_text")

    analysis = pdf.get_and_load_analysis(PDFLinkTextAnalysis)
    assert analysis.links == [{"url": "https://annotation.example.com/click", "page": 1, "text": TEXT, "line": TEXT}]
    assert analysis.summary == "PDF Link Text Analysis: 1 links, 1 with text"


@pytest.mark.integration
def test_pdf_link_text_records_each_link_once_up_to_a_cap(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(get_analysis_module_config("pdf_link_text"), "max_links", 3)
    annotations = [(f"https://link{n}.example.com/", [72, 700 - n, 300, 740 - n], None) for n in range(5)]

    with caplog.at_level(logging.INFO):
        links = _links(root_analysis, _pdf_with_links(tmp_path, [annotations]))

    # the repeated annotation is recorded once, and the cap stops the rest
    assert [link["url"] for link in links] == ["https://link0.example.com/", "https://link1.example.com/",
                                               "https://link2.example.com/"]
    assert links[0]["text"] == TEXT
    [record] = [r for r in caplog.records if "only the first are recorded" in r.getMessage()]
    assert record.levelno == logging.INFO and record.path.endswith("links.pdf")


@pytest.mark.integration
def test_pdf_link_text_logs_no_cap_it_did_not_reach(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(get_analysis_module_config("pdf_link_text"), "max_links", 1)

    with caplog.at_level(logging.INFO):
        links = _links(root_analysis, _pdf_with_links(tmp_path, [[("https://link0.example.com/", LINK_BOX, None)]]))

    assert len(links) == 1
    assert "only the first are recorded" not in caplog.text


@pytest.mark.integration
def test_pdf_link_text_first_pages_only(root_analysis, tmp_path):
    pages = [[("https://first.example.com/", LINK_BOX, None)], [], [],
             [("https://fourth.example.com/", LINK_BOX, "Open the portal")]]

    links = _links(root_analysis, _pdf_with_links(tmp_path, pages))

    # a link past link_text_pages keeps only its annotation's /Contents
    assert links == [{"url": "https://first.example.com/", "page": 1, "text": TEXT, "line": TEXT},
                     {"url": "https://fourth.example.com/", "page": 4, "text": "Open the portal", "line": None}]


@pytest.mark.integration
def test_pdf_link_text_crowded_page(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(get_analysis_module_config("pdf_link_text"), "max_page_words", 3)
    pages = [[("https://crowded.example.com/", LINK_BOX, None)], [("https://sparse.example.com/", LINK_BOX, None)]]

    with caplog.at_level(logging.INFO):
        links = _links(root_analysis, _pdf_with_links(tmp_path, pages, texts=[TEXT, "View invoice"]))

    # the four words of TEXT are too many, and the page after it is still placed
    assert links == [{"url": "https://crowded.example.com/", "page": 1, "text": None, "line": None},
                     {"url": "https://sparse.example.com/", "page": 2, "text": "View invoice", "line": "View invoice"}]
    [record] = [r for r in caplog.records if "have more than 3 words" in r.getMessage()]
    assert record.levelno == logging.INFO and record.path.endswith("links.pdf")
    assert "pages [1] of" in record.getMessage()


@pytest.mark.integration
def test_pdf_link_text_rotated_page(root_analysis, tmp_path):
    links = _links(root_analysis, _pdf_with_links(
        tmp_path, [[("https://link0.example.com/", LINK_BOX, "Open the portal")]], rotate=90))

    # pdftotext places a rotated page's words in the rotated frame, so only /Contents is kept
    assert links == [{"url": "https://link0.example.com/", "page": 1, "text": "Open the portal", "line": None}]


@pytest.mark.integration
def test_pdf_link_text_max_link_band_words(root_analysis, tmp_path, monkeypatch):
    # the link's box is over the four words of TEXT
    monkeypatch.setattr(get_analysis_module_config("pdf_link_text"), "max_link_band_words", 3)

    assert _links(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click")) == [
        {"url": "https://annotation.example.com/click", "page": 1, "text": None, "line": None}]


@pytest.mark.integration
def test_pdf_link_text_keeps_links_whose_text_it_cannot_place(root_analysis, tmp_path, monkeypatch, caplog):
    def _fail(output, first_page, max_words):
        raise ValueError("bad bbox output")

    monkeypatch.setattr(pdf_module, "parse_bbox_words", _fail)
    pdf = _analyze(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click"),
                   "pdf_link_text")

    analysis = pdf.get_and_load_analysis(PDFLinkTextAnalysis)
    assert analysis.links == [{"url": "https://annotation.example.com/click", "page": 1, "text": None, "line": None}]
    # an error keeps the result out of the analysis cache
    assert analysis.error == "placing the link text raised ValueError, without the text under the links"
    [record] = [r for r in caplog.records if "cannot place the link text" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info
    assert record.path == pdf.full_path


@pytest.mark.integration
def test_pdf_link_text_pdftotext_fails(root_analysis, tmp_path, monkeypatch, caplog):
    # exits 1 with no output, as pdftotext does on a PDF it rejects
    monkeypatch.setattr(get_analysis_module_config("pdf_link_text"), "pdftotext_path", "/bin/false")

    with caplog.at_level(logging.INFO):
        pdf = _analyze(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click"),
                       "pdf_link_text")

    analysis = pdf.get_and_load_analysis(PDFLinkTextAnalysis)
    assert analysis.links == [{"url": "https://annotation.example.com/click", "page": 1, "text": None, "line": None}]
    assert analysis.error == "pdftotext exited with status 1, without the text under the links"
    [record] = [r for r in caplog.records if "pdftotext exited with status 1, placing" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.path == pdf.full_path
    assert "words; their links get no text" not in caplog.text


@pytest.mark.integration
def test_pdf_link_text_pdftotext_crashes(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(PDFLinkTextAnalyzer, "run_sandboxed_tool", lambda self, *args, **kwargs: SandboxResult(
        returncode=139, stdout='<page width="612" height="792">', stderr="Syntax Error: bad stream\nSegmentation fault"))

    pdf = _analyze(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click"),
                   "pdf_link_text")

    assert pdf.get_and_load_analysis(PDFLinkTextAnalysis).error == (
        "pdftotext was killed by signal 11: Segmentation fault, without the text under the links")
    [record] = [r for r in caplog.records if "killed by signal 11" in r.getMessage()]
    assert record.levelno == logging.WARNING


@pytest.mark.integration
def test_pdf_link_text_pdftotext_stopped(root_analysis, tmp_path, monkeypatch):
    # a timeout, or a node where the sandbox cannot run
    monkeypatch.setattr(PDFLinkTextAnalyzer, "run_sandboxed_tool", lambda self, *args, **kwargs: None)

    pdf = _analyze(root_analysis, _pdf(tmp_path, annotation_uri="https://annotation.example.com/click"),
                   "pdf_link_text")

    assert pdf.get_and_load_analysis(PDFLinkTextAnalysis).error == (
        "pdftotext did not finish, without the text under the links")


@pytest.mark.integration
def test_pdf_link_text_nothing_to_place_is_an_answer(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _pdf_with_links(
        tmp_path, [[("https://link0.example.com/", LINK_BOX, "Open the portal")]], rotate=90), "pdf_link_text")

    # nothing was left to pdftotext, so the result is complete and can be cached
    assert pdf.get_and_load_analysis(PDFLinkTextAnalysis).error is None


@pytest.mark.unit
def test_pdf_link_text_custom_requirement(test_context, tmp_path):
    analyzer = PDFLinkTextAnalyzer(context=test_context, config=get_analysis_module_config("pdf_link_text"))
    text = tmp_path / "notes.txt"
    text.write_text("https://example.com/")

    # the cache is looked up only for a PDF
    assert analyzer.custom_requirement(SimpleNamespace(full_path=str(_pdf(tmp_path))))
    assert not analyzer.custom_requirement(SimpleNamespace(full_path=str(text)))
    assert not analyzer.custom_requirement(SimpleNamespace(full_path=str(tmp_path / "missing.pdf")))


@pytest.mark.integration
def test_pdf_link_text_unreadable_pdf(root_analysis, tmp_path, caplog):
    path = tmp_path / "damaged.pdf"
    path.write_bytes(b"%PDF-1.4\nnot a pdf body")

    pdf = _analyze(root_analysis, path, "pdf_link_text")

    assert not pdf.get_and_load_analysis(PDFLinkTextAnalysis)
    [record] = [r for r in caplog.records if "cannot read the links" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info
    assert record.path == pdf.full_path


@pytest.mark.integration
def test_pdf_link_text_skips_pdfs_without_links_and_other_files(root_analysis, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("https://example.com/")

    assert _links(root_analysis, _pdf(tmp_path)) is None
    assert _links(_new_root(), text) is None


@pytest.mark.unit
def test_pdf_link_text_runs_only_on_alerts():
    # pdftotext places the words of the PDFs of alerts, not of every collected email
    assert "pdf_link_text" in get_config().get_module_group_config("correlation").modules
    assert "pdf_link_text" not in get_config().get_module_group_config("file").modules
    assert "pdf_link_text" not in get_config().get_module_group_config("email").modules


@pytest.mark.unit
def test_pdf_link_text_extended_version(test_context, monkeypatch):
    analyzer = PDFLinkTextAnalyzer(context=test_context, config=get_analysis_module_config("pdf_link_text"))

    monkeypatch.setattr(pdf_module, "probe_binary_version", lambda name, args=None: "pdftotext version 24.02.0")
    assert analyzer.extended_version == {"pdftotext": "pdftotext version 24.02.0"}
    # a failed probe leaves the key out rather than poisoning it
    monkeypatch.setattr(pdf_module, "probe_binary_version", lambda name, args=None: None)
    assert analyzer.extended_version == {}


def _encrypted_pdf(tmp_path: Path, encryption: pikepdf.Encryption, name: str = "document.pdf",
                   payload: pikepdf.Array = None) -> Path:
    plain = _pdf(tmp_path, name="plain.pdf", annotation_uri=ENCRYPTED_URI)
    path = tmp_path / name
    with pikepdf.open(plain) as pdf:
        if payload is not None:
            # a stream deflated once per filter, saved without recompressing so the filters stay as built
            data = PAYLOAD
            for _ in payload:
                data = zlib.compress(data)
            stream = pikepdf.Stream(pdf, data)
            stream.Filter = payload
            pdf.Root.Payload = pdf.make_indirect(stream)
        pdf.save(path, encryption=encryption, compress_streams=payload is None)
    return path


def _new_root() -> RootAnalysis:
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(uuid=root_uuid, tool="tool", tool_instance="tool_instance", alert_type="alert_type",
                        desc="Test Alert", storage_dir=storage_dir_from_uuid(root_uuid),
                        analysis_mode=ANALYSIS_MODE_ANALYSIS)
    root.initialize_storage()
    return root


ENCRYPTED_URI = "https://hidden.example.com/lure"
PAYLOAD = b"hidden payload " * 64
RESTRICTED = pikepdf.Permissions(extract=False, modify_other=False, print_highres=False)


@pytest.mark.integration
@pytest.mark.parametrize("encryption, method, bits, owner_password_empty, extract", [
    # RC4 revisions have no crypt filters, so pikepdf reports their stream method as none
    (pikepdf.Encryption(owner="", user="", R=3, aes=False, metadata=False), "rc4", 128, True, True),
    (pikepdf.Encryption(owner="", user="", R=4, aes=True), "aes", 128, True, True),
    # an owner (permissions) password only, with restricted permissions
    (pikepdf.Encryption(owner="secret", user="", R=6, allow=RESTRICTED), "aesv3", 256, False, False),
], ids=["rc4_128", "aes128", "owner_password_only"])
def test_pdf_analyzer_decrypts_pdf_with_empty_user_password(root_analysis, tmp_path, encryption, method, bits,
                                                            owner_password_empty, extract):
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, encryption), "pdf_analyzer")

    analysis = pdf.get_and_load_analysis(PDFAnalysis)
    assert pdf.has_tag("encrypted_pdf_empty_password")
    assert analysis.encryption["filter"] == "/Standard"
    assert analysis.encryption["R"] == encryption.R
    assert analysis.encryption["method"] == method
    assert analysis.encryption["bits"] == bits
    assert analysis.encryption["owner_password_empty"] is owner_password_empty
    assert analysis.encryption["permissions"]["extract"] is extract
    assert analysis.summary == (f"PDF Analysis: encrypted ({method} {bits}-bit, R{encryption.R}, "
                                f"P {analysis.encryption['P']}), opens with an empty user password")

    outputs = _outputs(analysis)
    # pdfparser cannot read the encrypted original's strings
    with open(outputs["document.pdf.pdfparser"].full_path) as fp:
        assert ENCRYPTED_URI not in fp.read()

    decrypted = outputs["document.pdf.decrypted.pdf"]
    assert decrypted.redirection.uuid == pdf.uuid
    assert decrypted.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == pdf.uuid
    assert decrypted.has_tag("decrypted_pdf")
    assert decrypted.has_yara_meta("type", "document.pdf")
    with pikepdf.open(decrypted.full_path) as copy:
        assert not copy.is_encrypted

    # pdfparser reads the decrypted copy's objects in plaintext
    pdfparser = outputs["document.pdf.decrypted.pdf.pdfparser"]
    assert pdfparser.redirection.uuid == pdf.uuid
    assert pdfparser.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == decrypted.uuid
    assert pdfparser.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert pdfparser.has_yara_meta("type", "document.pdf.object")
    with open(pdfparser.full_path) as fp:
        assert ENCRYPTED_URI in fp.read()

    # the copy is not analyzed again, so it is not decrypted again either
    assert not decrypted.get_and_load_analysis(PDFAnalysis)


@pytest.mark.integration
def test_pdf_analyzer_decrypts_without_decoding_streams(root_analysis, tmp_path):
    # decoding is pdfparser's job, under its timeout: a nested-Flate stream a few KB long can inflate to gigabytes
    payload = pikepdf.Array([pikepdf.Name.FlateDecode, pikepdf.Name.FlateDecode])
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6), payload=payload),
                   "pdf_analyzer")

    decrypted = _outputs(pdf.get_and_load_analysis(PDFAnalysis))["document.pdf.decrypted.pdf"]
    with pikepdf.open(decrypted.full_path) as copy:
        assert not copy.is_encrypted
        assert copy.Root.Payload.Filter == payload
        assert copy.Root.Payload.read_bytes() == PAYLOAD


@pytest.mark.integration
def test_pdf_analyzer_decrypts_pdf_with_a_long_name(root_analysis, tmp_path):
    # long enough that <name>.decrypted.pdf.pdfparser does not fit in NAME_MAX, short enough that the original's
    # own outputs still do
    name = "a" * 230 + ".pdf"
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6), name=name),
                   "pdf_analyzer")

    outputs = _outputs(pdf.get_and_load_analysis(PDFAnalysis))
    [decrypted] = [o for o in outputs.values() if o.has_tag("decrypted_pdf")]
    [pdfparser] = [o for o in outputs.values()
                   if o.get_relationship_by_type(R_EXTRACTED_FROM).target.uuid == decrypted.uuid]
    assert pdfparser.has_yara_meta("type", "document.pdf.object")
    with open(pdfparser.full_path) as fp:
        assert ENCRYPTED_URI in fp.read()


@pytest.mark.integration
def test_pdf_analyzer_leaves_the_renderers_to_the_original(root_analysis, tmp_path):
    # ghostscript and poppler open the original with its empty password, so on the copy they would only repeat it
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6)),
                   "pdf_analyzer", "pdftotext")

    assert pdf.get_and_load_analysis(PDFTextAnalysis)
    decrypted = _outputs(pdf.get_and_load_analysis(PDFAnalysis))["document.pdf.decrypted.pdf"]
    assert not decrypted.get_and_load_analysis(PDFTextAnalysis)
    assert not decrypted.get_and_load_analysis(PDFAnalysis)
    for module in (PDFAnalyzer, PDFTextAnalyzer, PDFLinkTextAnalyzer, ExifAnalyzer, QRCodeAnalyzer):
        assert any(module.__name__ in name for name in decrypted.excluded_analysis)


@pytest.mark.integration
def test_pdf_link_text_reads_the_encrypted_original(root_analysis, tmp_path):
    # pikepdf and poppler open a PDF with an empty user password, so the original's links get their text
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6)),
                   "pdf_analyzer", "pdf_link_text")

    assert pdf.get_and_load_analysis(PDFLinkTextAnalysis).links == [
        {"url": ENCRYPTED_URI, "page": 1, "text": TEXT, "line": TEXT}]
    decrypted = _outputs(pdf.get_and_load_analysis(PDFAnalysis))["document.pdf.decrypted.pdf"]
    assert not decrypted.get_and_load_analysis(PDFLinkTextAnalysis)


@pytest.mark.integration
def test_pdf_analyzer_writes_the_same_decrypted_copy_every_time(root_analysis, tmp_path):
    # the copy's sha256 keys every cached result on it, so a later alert with the same attachment reuses them
    path = _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6))

    first = _outputs(_analyze(root_analysis, path, "pdf_analyzer").get_and_load_analysis(PDFAnalysis))
    # a random /ID comes from the clock in whole seconds, so two saves in the same second would match anyway
    later = int(time.time()) + 1
    wait_for_condition(lambda: time.time() >= later, timeout=2)
    second = _outputs(_analyze(_new_root(), path, "pdf_analyzer").get_and_load_analysis(PDFAnalysis))

    assert first["document.pdf.decrypted.pdf"].sha256_hash == second["document.pdf.decrypted.pdf"].sha256_hash


@pytest.mark.integration
def test_pdf_analyzer_leaves_pdf_that_needs_a_user_password(root_analysis, tmp_path):
    pdf = _analyze(root_analysis, _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="owner", user="user", R=6)),
                   "pdf_analyzer")

    analysis = pdf.get_and_load_analysis(PDFAnalysis)
    assert analysis.encryption is None
    assert not pdf.has_tag("encrypted_pdf_empty_password")
    assert not [name for name in _outputs(analysis) if name.endswith(".decrypted.pdf")]


@pytest.mark.integration
def test_pdf_analyzer_survives_a_decrypted_copy_it_cannot_save(root_analysis, tmp_path, monkeypatch, caplog):
    def _save(self, *args, **kwargs):
        raise pikepdf.PdfError("damaged object stream")

    path = _encrypted_pdf(tmp_path, pikepdf.Encryption(owner="", user="", R=6))
    monkeypatch.setattr(pikepdf.Pdf, "save", _save)
    pdf = _analyze(root_analysis, path, "pdf_analyzer")

    analysis = pdf.get_and_load_analysis(PDFAnalysis)
    assert analysis.encryption["R"] == 6
    outputs = _outputs(analysis)
    assert not [name for name in outputs if name.endswith(".decrypted.pdf")]
    # nothing half-written is left behind, and the rest of the extraction still runs
    assert not list(Path(pdf.full_path).parent.glob("*.decrypted.pdf"))
    assert "document.pdf.annotation_uris.txt" in outputs
    [record] = [r for r in caplog.records if "cannot save a decrypted copy" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert record.exc_info
    assert record.path == pdf.full_path


@pytest.mark.integration
@pytest.mark.parametrize("form_value", [
    # valid base64 of a payload long enough, but shorter than a payload is encoded
    base64.b64encode(b"x" * 40).decode(),
    # long enough, but not base64: the decoder would drop the dashes and read the rest
    "abcd-" * 20,
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
def test_pdf_analyzer_stops_a_pdfparser_that_hangs(root_analysis, tmp_path, monkeypatch, caplog):
    hang = tmp_path / "hang.py"
    hang.write_text("import sys, time\nprint('partial', flush=True)\ntime.sleep(60)\n")
    get_analysis_module_config("pdf_analyzer").pdfparser_path = str(hang)
    monkeypatch.setattr(pdf_module, "PDFPARSER_TIMEOUT_SECONDS", 1)

    pdf = _analyze(root_analysis, _pdf(tmp_path), "pdf_analyzer")

    # what it wrote before it was stopped is still scanned
    pdfparser = _outputs(pdf.get_and_load_analysis(PDFAnalysis))["document.pdf.pdfparser"]
    with open(pdfparser.full_path) as fp:
        assert fp.read() == "partial\n"
    # stopped at PDFPARSER_TIMEOUT_SECONDS, long before the call runs out of time
    assert any(r.levelno == logging.WARNING and r.getMessage().startswith("PDFAnalyzer stopped python3 on ")
               and r.getMessage().endswith("document.pdf after 1 seconds") for r in caplog.records)


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
    real_run = PDFTextAnalyzer.run_sandboxed_tool

    def _run(self, args, target, **kwargs):
        # a pdftotext that hangs once it has started writing its output
        return real_run(self, ["sh", "-c", "echo partial > output.txt; exec sleep 60"], target,
                        **kwargs)

    monkeypatch.setattr(PDFTextAnalyzer, "run_sandboxed_tool", _run)
    pdf = _analyze(root_analysis, _pdf(tmp_path), "pdftotext")

    analysis = pdf.get_and_load_analysis(PDFTextAnalysis)
    assert analysis.output_path is None
    assert analysis.error == "pdftotext did not finish"
    # what it wrote before it was stopped is not kept
    assert not [o for o in analysis.observables if o.type == F_FILE]
    assert any(r.levelno == logging.WARNING and "stopped sh" in r.getMessage() and "timed out" in r.getMessage()
               for r in caplog.records)
