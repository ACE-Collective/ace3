import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from saq.constants import F_COMMAND_LINE, F_IPV4
from saq.modules.command_line import CommandLineAnalysis
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.ocr import YARA_META_TYPE_OCR, OCRAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
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
