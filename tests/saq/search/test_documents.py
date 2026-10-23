import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from saq.constants import F_COMMAND_LINE, F_IPV4
from saq.modules.command_line import CommandLineAnalysis
from saq.modules.email.encryption.msoffice import MSOfficeEncryptionAnalysis
from saq.modules.email.encryption.rar import RarEncryptionAnalysis
from saq.modules.email.encryption.zip import ZipEncryptionAnalysis
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.js import JavaScriptDeobfuscationAnalysis
from saq.modules.file_analysis.ocr import YARA_META_TYPE_OCR, OCRAnalysis
from saq.modules.file_analysis.olevba import KEY_MACROS, OLEVBA_Analysis_v1_2
from saq.modules.file_analysis.pdf import PDFTextAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.modules.file_analysis.xml import KEY_XML_PLAIN_TEXT, XMLPlainTextAnalysis
from saq.modules.rdap import KEY_WHOIS_RAW_TEXT, RdapAnalysis
from saq.search import extractors  # noqa: F401
from saq.search.documents import (
    ALERT_HEADER_KEY,
    DETECTIONS_KEY,
    ExtractContext,
    SearchDocument,
    alert_document,
    comment_documents,
    detection_document,
    extract_documents,
    find_extractor,
    normalize_text,
)
from saq.search.types import KIND_ALERT, KIND_ANALYSIS, KIND_COMMENT, KIND_CONTEXT, KIND_DETECTION

pytestmark = pytest.mark.integration

CAP = 4096


def _comment(comment_id, text, user="analyst"):
    return SimpleNamespace(comment_id=comment_id, comment=text, user=SimpleNamespace(gui_display=user))


def test_normalize_text():
    assert normalize_text("  a   b \n\n\n c  ") == "a b\nc"
    assert normalize_text(None) == ""


def test_alert_document_from_root(root_analysis):
    root_analysis.instructions = "Check the sender reputation."
    root_analysis.add_summary_detail(header="Hunt", content="matched the invoice rule")
    document = alert_document(None, root_analysis)
    assert document.kind == KIND_ALERT and document.key == ALERT_HEADER_KEY
    assert document.title == "Test Alert"
    assert document.embed_title is False  # the text already starts with the description
    assert document.text.startswith("Test Alert\n")
    assert "tool instance" not in document.text and "queue" not in document.text  # boilerplate stays in the payload
    assert "instructions: Check the sender reputation." in document.text
    assert "Hunt: matched the invoice rule" in document.text


def test_alert_document_prefers_alert_row(root_analysis):
    alert = SimpleNamespace(description="DB description", alert_type="phish", tool="splunk", tool_instance="prod", queue="default")
    document = alert_document(alert, root_analysis)
    assert document.title == "DB description"
    assert "alert type: phish" in document.text


def test_comment_documents_skip_empty():
    documents = comment_documents([_comment(1, "looks like a vendor mailer"), _comment(2, "   ")])
    assert len(documents) == 1
    assert documents[0].kind == KIND_COMMENT and documents[0].key == "1"
    assert documents[0].title == "analyst"


def test_detection_document_dedupes(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "10.1.1.1")
    observable.add_detection_point("ip matched a bad list")
    observable.add_detection_point("ip matched a bad list")
    root_analysis.add_detection_point("root level detection")
    document = detection_document(root_analysis)
    assert document.kind == KIND_DETECTION and document.key == DETECTIONS_KEY
    assert document.text.count("ip matched a bad list") == 1
    assert "root level detection" in document.text
    assert detection_document(root_analysis.__class__(uuid="00000000-0000-0000-0000-000000000000", storage_dir=root_analysis.storage_dir)) is None


def test_extractor_lookup_walks_mro():
    class SubEmail(EmailAnalysis):
        pass

    assert find_extractor(SubEmail()) is find_extractor(EmailAnalysis())
    assert find_extractor(Mock(spec=[])) is None


def test_email_extractor(root_analysis, tmpdir):
    body_path = os.path.join(str(tmpdir), "unknown_text_plain_000")
    with open(body_path, "w") as fp:
        fp.write("Please review the attached DocuSign invoice today.")

    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.1")
    analysis = EmailAnalysis()
    observable.add_analysis(analysis)
    analysis.details["email"] = {
        "from": "billing@docusign-invoices.example",
        "to": ["bob@example.com"],
        "subject": "Your invoice",
        "decoded_subject": "Your DocuSign invoice",
        "headers": [["Date", "Mon, 1 Jan 2026 00:00:00 +0000"], ["X-Junk", "ignored"]],
    }
    analysis.add_file_observable(body_path)

    documents = extract_documents(None, root_analysis, max_document_bytes=CAP)
    email_documents = [d for d in documents if d.kind == KIND_ANALYSIS]
    assert len(email_documents) == 1
    document = email_documents[0]
    assert document.key == analysis.uuid
    assert document.title == "Your DocuSign invoice"
    assert "From: billing@docusign-invoices.example" in document.text
    assert "To: bob@example.com" in document.text
    assert "Date: Mon, 1 Jan 2026" in document.text
    assert "X-Junk" not in document.text
    assert "attached DocuSign invoice" in document.text
    assert document.analysis_uuid == analysis.uuid
    assert document.observable_uuid == observable.uuid
    assert document.embed_title is True


def test_details_are_loaded_even_when_defaults_are_present(root_analysis):
    """Analysis classes initialize `details` with default keys; that must not stop the on-disk
    details from being read at index time (this hid every email subject in the first version)."""
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.9")
    analysis = QRCodeAnalysis()
    observable.add_analysis(analysis)
    analysis.extracted_text = "https://on-disk.example/"
    root_analysis.save()

    from saq.analysis.root import load_root
    reloaded = load_root(root_analysis.storage_dir)
    documents = [d for d in extract_documents(None, reloaded, max_document_bytes=CAP) if d.kind == KIND_ANALYSIS]
    assert len(documents) == 1 and "on-disk.example" in documents[0].text


def test_deobfuscated_script_banner_is_stripped():
    from saq.search.extractors import strip_leading_comments

    text = "// ACE3 javascript deobfuscator -- reconstructed from sandbox trace\n// source: /x/y.js\n\nlocation.href = 'x';\n// trailing comment kept\n"
    assert strip_leading_comments(text) == "location.href = 'x';\n// trailing comment kept"
    assert strip_leading_comments("// only a banner\n") == ""


def test_command_line_extractor(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "powershell -enc AAAA")
    analysis = CommandLineAnalysis()
    observable.add_analysis(analysis)
    analysis.file_paths = ["C:\\Users\\bob\\evil.ps1"]

    documents = [d for d in extract_documents(None, root_analysis, max_document_bytes=CAP) if d.kind == KIND_ANALYSIS]
    assert len(documents) == 1
    assert "powershell -enc AAAA" in documents[0].text
    assert "C:\\Users\\bob\\evil.ps1" in documents[0].text
    # a generic label is shown but never embedded; an email subject is
    assert documents[0].title == "command line" and documents[0].embed_title is False


def test_qrcode_extractor_and_byte_cap(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.2")
    analysis = QRCodeAnalysis()
    observable.add_analysis(analysis)
    analysis.extracted_text = "https://mfa-reset.example/login " * 500

    documents = [d for d in extract_documents(None, root_analysis, max_document_bytes=256) if d.kind == KIND_ANALYSIS]
    assert len(documents) == 1
    assert len(documents[0].text.encode()) <= 256


def test_ocr_extractor_reads_file_observable(root_analysis, tmpdir):
    image_path = os.path.join(str(tmpdir), "scan.png")
    with open(image_path, "wb") as fp:
        fp.write(b"\x89PNG")
    ocr_path = os.path.join(str(tmpdir), "scan.png.ocr")
    with open(ocr_path, "w") as fp:
        fp.write("Your mailbox is full, reset your password here")

    image = root_analysis.add_file_observable(image_path)
    analysis = OCRAnalysis()
    image.add_analysis(analysis)
    ocr_file = analysis.add_file_observable(ocr_path)
    ocr_file.add_yara_meta("type", YARA_META_TYPE_OCR)

    documents = [d for d in extract_documents(None, root_analysis, max_document_bytes=CAP) if d.kind == KIND_ANALYSIS]
    assert len(documents) == 1
    assert documents[0].title == "OCR text"
    assert "reset your password" in documents[0].text


def test_large_details_are_not_loaded(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.3")
    analysis = QRCodeAnalysis()
    observable.add_analysis(analysis)
    analysis.details = {}
    analysis.details_size = CAP + 1
    analysis.load_details = Mock()

    extract_documents(None, root_analysis, max_document_bytes=CAP)
    analysis.load_details.assert_not_called()


def test_context_documents(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.4")
    observable.add_llm_context_document("this ip belongs to the corporate vpn pool")
    analysis = QRCodeAnalysis()
    observable.add_analysis(analysis)
    analysis.add_llm_context_document("qr code pointed at a credential harvesting page")

    documents = [d for d in extract_documents(None, root_analysis, max_document_bytes=CAP) if d.kind == KIND_CONTEXT]
    assert {d.text for d in documents} == {"this ip belongs to the corporate vpn pool", "qr code pointed at a credential harvesting page"}
    assert {d.key for d in documents} == {f"{observable.uuid}:0", f"{analysis.uuid}:0"}


def test_no_per_edge_records(root_analysis):
    """The observable graph is served by the lexical lane; it must not be embedded."""
    for i in range(20):
        root_analysis.add_observable_by_spec(F_IPV4, f"10.0.0.{i}")

    documents = extract_documents(None, root_analysis, [_comment(1, "hi")], max_document_bytes=CAP)
    assert [d.kind for d in documents] == [KIND_ALERT, KIND_COMMENT]


def test_documents_are_stable_across_calls(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "whoami")
    observable.add_analysis(CommandLineAnalysis())
    first = extract_documents(None, root_analysis, [_comment(7, "c")], max_document_bytes=CAP)
    second = extract_documents(None, root_analysis, [_comment(7, "c")], max_document_bytes=CAP)
    assert [(d.kind, d.key) for d in first] == [(d.kind, d.key) for d in second]
    assert all(isinstance(d, SearchDocument) for d in first)


def _analysis_documents(root_analysis):
    return [d for d in extract_documents(None, root_analysis, max_document_bytes=CAP) if d.kind == KIND_ANALYSIS]


def _write(tmpdir, name, content):
    path = os.path.join(str(tmpdir), name)
    with open(path, "w") as fp:
        fp.write(content)
    return path


def test_email_extractor_falls_back_to_the_html_body(root_analysis, tmpdir):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.10")
    analysis = EmailAnalysis()
    observable.add_analysis(analysis)
    analysis.details["email"] = {
        "subject": "Mailbox quota",
        # a malformed entry in the raw header list is skipped, not fatal
        "headers": [["Return-Path"], ["Return-Path", "<bounce@quota.example>"]],
    }
    # a blank plain text part is no body
    analysis.add_file_observable(_write(tmpdir, "email.rfc822.unknown_text_plain_000", "  \n"))
    analysis.add_file_observable(_write(
        tmpdir, "email.rfc822.unknown_text_html_000",
        "<html><body><p>Your <b>mailbox</b> is over quota.</p></body></html>"))

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    text = documents[0].text
    assert "Return-Path: <bounce@quota.example>" in text
    assert "Your **mailbox** is over quota." in text
    assert "<p>" not in text


def test_email_extractor_keeps_html_html2text_cannot_convert(root_analysis, tmpdir, monkeypatch):
    def broken_html2text(html):
        raise ValueError("unconvertible")

    monkeypatch.setattr(extractors, "html2text", broken_html2text)
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.11")
    analysis = EmailAnalysis()
    observable.add_analysis(analysis)
    analysis.details["email"] = {"subject": "Mailbox quota"}
    analysis.add_file_observable(_write(tmpdir, "email.rfc822.unknown_text_html_000", "<p>over quota</p>"))

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert "<p>over quota</p>" in documents[0].text


def test_email_extractor_without_a_body(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.12")
    analysis = EmailAnalysis()
    observable.add_analysis(analysis)
    analysis.details["email"] = {}

    assert _analysis_documents(root_analysis) == []


def test_olevba_extractor(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.13")
    analysis = OLEVBA_Analysis_v1_2()
    observable.add_analysis(analysis)
    analysis.details[KEY_MACROS] = [
        {"vba_code": "Sub AutoOpen()\n  Shell \"powershell -enc AAAA\"\nEnd Sub"},
        {"vba_code": None},
        "not a macro",
    ]

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "VBA macro"
    assert "Shell \"powershell -enc AAAA\"" in documents[0].text


def test_olevba_extractor_without_code(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.14")
    analysis = OLEVBA_Analysis_v1_2()
    observable.add_analysis(analysis)
    analysis.details[KEY_MACROS] = [{"vba_code": "   "}]

    assert _analysis_documents(root_analysis) == []


def test_rdap_extractor(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.15")
    analysis = RdapAnalysis()
    observable.add_analysis(analysis)
    analysis.details[KEY_WHOIS_RAW_TEXT] = "Registrar: Example Registrar\nCreation Date: 2026-10-01"

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "whois"
    assert "Creation Date: 2026-10-01" in documents[0].text


@pytest.mark.parametrize("analysis_class", [ZipEncryptionAnalysis, RarEncryptionAnalysis, MSOfficeEncryptionAnalysis])
def test_encrypted_attachment_email_body_extractor(root_analysis, analysis_class):
    observable = root_analysis.add_observable_by_spec(F_IPV4, "192.0.2.16")
    analysis = analysis_class()
    observable.add_analysis(analysis)
    analysis.details["email_body"] = "The password for the attached invoice is 1234"

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "email body"
    assert "password for the attached invoice" in documents[0].text


def test_xml_plain_text_extractor_reads_the_named_file(root_analysis, tmpdir):
    document = root_analysis.add_file_observable(_write(tmpdir, "document.xml", "<?xml version='1.0'?><w/>"))
    analysis = XMLPlainTextAnalysis()
    document.add_analysis(analysis)
    analysis.add_file_observable(_write(tmpdir, "other.txt", "not the document text"))
    noxml = analysis.add_file_observable(_write(tmpdir, "document.xml.noxml", "Enable editing to view this invoice"))
    analysis.details = {KEY_XML_PLAIN_TEXT: noxml.file_path}

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "document text"
    assert documents[0].text == "Enable editing to view this invoice"


def test_pdf_text_extractor_reads_the_output_file(root_analysis, tmpdir):
    pdf = root_analysis.add_file_observable(_write(tmpdir, "invoice.pdf", "%PDF-1.4"))
    analysis = PDFTextAnalysis()
    pdf.add_analysis(analysis)
    analysis.add_file_observable(_write(tmpdir, "other.txt", "not the pdf text"))
    output = analysis.add_file_observable(_write(tmpdir, "invoice.pdf.txt", "Scan the code to sign the document"))
    # the analyzer records the output observable's value
    analysis.output_path = output.value

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "PDF text"
    assert documents[0].text == "Scan the code to sign the document"


def test_pdf_text_extractor_skips_empty_output(root_analysis, tmpdir):
    pdf = root_analysis.add_file_observable(_write(tmpdir, "blank.pdf", "%PDF-1.4"))
    analysis = PDFTextAnalysis()
    pdf.add_analysis(analysis)
    output = analysis.add_file_observable(_write(tmpdir, "blank.pdf.txt", "\n\n"))
    analysis.output_path = output.value

    assert _analysis_documents(root_analysis) == []


def test_deobfuscated_script_extractor(root_analysis, tmpdir):
    script = root_analysis.add_file_observable(_write(tmpdir, "loader.js", "eval(atob('...'))"))
    analysis = JavaScriptDeobfuscationAnalysis()
    script.add_analysis(analysis)
    analysis.add_file_observable(_write(tmpdir, "payload.bin", "MZ"))
    analysis.add_file_observable(_write(
        tmpdir, "deobfuscated-loader.js",
        "// ACE3 javascript deobfuscator\n// source: loader.js\n\nwindow.location = 'https://login.example/';\n"))

    documents = _analysis_documents(root_analysis)
    assert len(documents) == 1
    assert documents[0].title == "deobfuscated script"
    assert documents[0].text == "window.location = 'https://login.example/';"
