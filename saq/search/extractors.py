"""Built-in text extractors: where the human-readable text of each analysis type lives.

Importing this module registers the extractors. Each extractor receives an analysis whose
details have been loaded (when they fit under the byte cap) and returns (title, text) pairs.
Text that lives on disk (email bodies, OCR/pdf output, deobfuscated scripts) is read through
the ExtractContext so the byte cap applies uniformly.
"""

from typing import Optional

from html2text import html2text

from saq.modules.command_line import CommandLineAnalysis
from saq.modules.email.constants import (
    KEY_CC,
    KEY_DECODED_SUBJECT,
    KEY_FROM,
    KEY_MESSAGE_ID,
    KEY_REPLY_TO,
    KEY_SUBJECT,
    KEY_TO,
)
from saq.modules.email.encryption.msoffice import MSOfficeEncryptionAnalysis
from saq.modules.email.encryption.rar import RarEncryptionAnalysis
from saq.modules.email.encryption.zip import ZipEncryptionAnalysis
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.js import DEOBFUSCATED_PREFIX, JavaScriptDeobfuscationAnalysis
from saq.modules.file_analysis.ocr import YARA_META_TYPE_OCR, OCRAnalysis
from saq.modules.file_analysis.olevba import KEY_MACROS, OLEVBA_Analysis_v1_2
from saq.modules.file_analysis.pdf import KEY_OUTPUT_PATH, PDFTextAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.modules.file_analysis.xml import KEY_XML_PLAIN_TEXT, XMLPlainTextAnalysis
from saq.modules.rdap import KEY_WHOIS_RAW_TEXT, RdapAnalysis
from saq.search.documents import Extracted, ExtractContext, find_file_observables, register_extractor

# the email headers an analyst searches by; the full header block is mostly routing noise
EMAIL_HEADER_NAMES = ("from", "to", "cc", "reply-to", "subject", "date", "message-id", "return-path", "sender")


def strip_leading_comments(text: str) -> str:
    """Drops the leading `//` comment banner the deobfuscator writes (source path, pass notes):
    it is the same on every sample and would dominate a short script's embedding."""
    lines = text.splitlines()
    start = 0
    while start < len(lines) and (not lines[start].strip() or lines[start].lstrip().startswith("//")):
        start += 1
    return "\n".join(lines[start:])


def _details(analysis) -> dict:
    return analysis.details if isinstance(analysis.details, dict) else {}


def _listing(value) -> Optional[str]:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value if item)
    return str(value) if value else None


def _email_header_block(analysis: EmailAnalysis) -> str:
    """The searchable headers of an email, preferring the parsed fields over the raw list."""
    email = _details(analysis).get("email") or {}
    lines = []
    for label, key in (("From", KEY_FROM), ("To", KEY_TO), ("Cc", KEY_CC), ("Reply-To", KEY_REPLY_TO), ("Message-ID", KEY_MESSAGE_ID)):
        value = _listing(email.get(key))
        if value:
            lines.append(f"{label}: {value}")

    subject = email.get(KEY_DECODED_SUBJECT) or email.get(KEY_SUBJECT)
    if subject:
        lines.append(f"Subject: {subject}")

    # anything else interesting from the raw header list (date, return-path, ...)
    covered = {"from", "to", "cc", "reply-to", "subject", "message-id"}
    for header in analysis.headers or []:
        try:
            name, value = header[0], header[1]
        except (TypeError, IndexError):
            continue
        if name.lower() in EMAIL_HEADER_NAMES and name.lower() not in covered and value:
            lines.append(f"{name}: {value}")

    return "\n".join(lines)


def _email_body(analysis: EmailAnalysis, context: ExtractContext) -> str:
    text = analysis.body_text
    if text and text.strip():
        return text[:context.max_document_bytes]

    html = analysis.body_html
    if html and html.strip():
        try:
            return html2text(html[:context.max_document_bytes])
        except Exception:
            return html[:context.max_document_bytes]

    return ""


@register_extractor(EmailAnalysis)
def extract_email(analysis: EmailAnalysis, context: ExtractContext):
    email = _details(analysis).get("email") or {}
    title = email.get(KEY_DECODED_SUBJECT) or email.get(KEY_SUBJECT)
    text = "\n".join(part for part in (_email_header_block(analysis), _email_body(analysis, context)) if part)
    if text:
        yield title, text


@register_extractor(CommandLineAnalysis)
def extract_command_line(analysis: CommandLineAnalysis, context: ExtractContext):
    observable = getattr(analysis, "observable", None)
    lines = []
    if observable is not None and observable.value:
        lines.append(str(observable.value))
    lines.extend(str(path) for path in _details(analysis).get("file_paths") or [] if path)
    if lines:
        yield Extracted("command line", "\n".join(lines), label=True)


@register_extractor(QRCodeAnalysis)
def extract_qrcode(analysis: QRCodeAnalysis, context: ExtractContext):
    text = _details(analysis).get(QRCodeAnalysis.KEY_EXTRACTED_TEXT)
    if text:
        yield Extracted("QR code", str(text), label=True)


@register_extractor(OLEVBA_Analysis_v1_2)
def extract_olevba(analysis: OLEVBA_Analysis_v1_2, context: ExtractContext):
    macros = _details(analysis).get(KEY_MACROS) or []
    code = "\n".join(str(macro.get("vba_code") or "") for macro in macros if isinstance(macro, dict))
    if code.strip():
        yield Extracted("VBA macro", code, label=True)


@register_extractor(RdapAnalysis)
def extract_rdap(analysis: RdapAnalysis, context: ExtractContext):
    text = _details(analysis).get(KEY_WHOIS_RAW_TEXT)
    if text:
        yield Extracted("whois", str(text), label=True)


def _extract_email_body_details(analysis, context: ExtractContext):
    text = _details(analysis).get("email_body")
    if text:
        yield Extracted("email body", str(text), label=True)


register_extractor(ZipEncryptionAnalysis)(_extract_email_body_details)
register_extractor(RarEncryptionAnalysis)(_extract_email_body_details)
register_extractor(MSOfficeEncryptionAnalysis)(_extract_email_body_details)


@register_extractor(XMLPlainTextAnalysis)
def extract_xml_plain_text(analysis: XMLPlainTextAnalysis, context: ExtractContext):
    # the details hold the relative path of the .noxml file observable holding the text
    target = _details(analysis).get(KEY_XML_PLAIN_TEXT)
    for observable in find_file_observables(analysis, lambda o: not target or o.file_path == target):
        text = context.read_file_observable(observable)
        if text.strip():
            yield Extracted("document text", text, label=True)
            return


@register_extractor(OCRAnalysis)
def extract_ocr(analysis: OCRAnalysis, context: ExtractContext):
    for observable in find_file_observables(analysis, lambda o: f"type={YARA_META_TYPE_OCR}" in o.yara_meta_tags):
        text = context.read_file_observable(observable)
        if text.strip():
            yield Extracted("OCR text", text, label=True)
            return


@register_extractor(PDFTextAnalysis)
def extract_pdf_text(analysis: PDFTextAnalysis, context: ExtractContext):
    target = _details(analysis).get(KEY_OUTPUT_PATH)
    for observable in find_file_observables(analysis, lambda o: not target or o.value == target or o.file_path == target):
        text = context.read_file_observable(observable)
        if text.strip():
            yield Extracted("PDF text", text, label=True)
            return


@register_extractor(JavaScriptDeobfuscationAnalysis)
def extract_deobfuscated_js(analysis: JavaScriptDeobfuscationAnalysis, context: ExtractContext):
    for observable in find_file_observables(analysis, lambda o: o.file_name.startswith(DEOBFUSCATED_PREFIX)):
        text = strip_leading_comments(context.read_file_observable(observable))
        if text.strip():
            yield Extracted("deobfuscated script", text, label=True)
            return
