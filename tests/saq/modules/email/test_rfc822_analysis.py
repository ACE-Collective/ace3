"""What EmailAnalysis records about an email and reads back from it: the sender identity headers,
the body and attachments, the summary, and the office365 journal envelope without its meta block."""

import logging
import os

import pytest

from saq.analysis.root import load_root
from saq.constants import (
    DIRECTIVE_ORIGINAL_EMAIL,
    F_FILE,
    F_EMAIL_X_AUTH_ID,
    F_EMAIL_X_MAILER,
    F_EMAIL_X_ORIGINAL_SENDER,
    F_EMAIL_X_SENDER,
    F_EMAIL_X_SENDER_ID,
    F_USER_AGENT,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email.constants import KEY_EMAIL, KEY_PARTS
from saq.modules.email.rfc822 import EmailAnalysis
from saq.util.uuid import get_storage_dir

MULTIPART_EMAIL = b"""\
Received: from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.org with ESMTP; Fri, 23 Oct 2026 10:00:05 +0000
From: Sender <sender@example.com>
To: Recipient <recipient@example.org>
Subject: quarterly report
Message-ID: <synthetic-analysis@example.com>
Date: Fri, 23 Oct 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset="utf-8"

the plain text body
--INNER
Content-Type: text/html; charset="utf-8"

<html><body><p>the html body</p></body></html>
--INNER--
--OUTER
Content-Type: text/plain; name="invoice.txt"
Content-Disposition: attachment; filename="invoice.txt"

the attachment
--OUTER--
"""

SENDER_HEADERS_EMAIL = b"""\
From: Sender <sender@example.com>
To: Recipient <recipient@example.org>
Subject: sender headers
Message-ID: <synthetic-sender-headers@example.com>
X-Sender: Relay.Sender@Example.com
X-Sender-Id: sender-id@example.com
X-Auth-Id: auth-id@example.com
X-Original-Sender: original@example.com
User-Agent: Synthetic Mail Client 1.0
X-Mailer: Synthetic Mailer 2.0

body
"""

# an office365 journal report: the envelope carries the parent message-id, and there is no
# text/plain part with the sender/subject/recipients block in it
JOURNAL_WITHOUT_META = b"""\
From: journal@example.org
To: journal-archive@example.org
Subject: journal report
X-MS-Exchange-Parent-Message-Id: <synthetic-journaled@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="JOURNAL"

--JOURNAL
Content-Type: text/html

<html><body>no meta block here</body></html>
--JOURNAL
Content-Type: message/rfc822

From: Sender <sender@example.com>
To: Recipient <recipient@example.org>
Subject: the journaled message
Message-ID: <synthetic-journaled@example.com>

journaled body
--JOURNAL--
"""


def _analyze(root_analysis, content: bytes, file_name: str = "email.rfc822", directive: bool = True):
    path = root_analysis.create_file_path(file_name)
    with open(path, "wb") as fp:
        fp.write(content)

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(path)
    if directive:
        observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)

    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("file_type", "test_groups")
    engine.configuration_manager.enable_module("email_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    observable = root.get_observable(observable.uuid)
    return observable, observable.get_and_load_analysis(EmailAnalysis)


@pytest.mark.integration
def test_sender_identity_headers(root_analysis):
    _, analysis = _analyze(root_analysis, SENDER_HEADERS_EMAIL)
    assert isinstance(analysis, EmailAnalysis)

    # addresses are normalized (lowercased) like every other address the analyzer records
    assert analysis.x_sender == "relay.sender@example.com"
    assert analysis.x_sender_id == "sender-id@example.com"
    assert analysis.x_auth_id == "auth-id@example.com"
    assert analysis.x_original_sender == "original@example.com"
    assert analysis.user_agent == "Synthetic Mail Client 1.0"
    assert analysis.x_mailer == "Synthetic Mailer 2.0"

    values = {(o.type, o.value) for o in analysis.observables}
    assert (F_EMAIL_X_SENDER, "relay.sender@example.com") in values
    assert (F_EMAIL_X_SENDER_ID, "sender-id@example.com") in values
    assert (F_EMAIL_X_AUTH_ID, "auth-id@example.com") in values
    assert (F_EMAIL_X_ORIGINAL_SENDER, "original@example.com") in values
    assert (F_USER_AGENT, "Synthetic Mail Client 1.0") in values
    assert (F_EMAIL_X_MAILER, "Synthetic Mailer 2.0") in values

    # no Received: headers
    assert analysis.received == []
    assert analysis.received_time is None


@pytest.mark.integration
def test_body_and_attachments(root_analysis):
    # not named email.rfc822, which the attachments list skips by name as well
    _, analysis = _analyze(root_analysis, MULTIPART_EMAIL, file_name="message.eml")
    assert isinstance(analysis, EmailAnalysis)

    assert analysis.body_text.strip() == "the plain text body"
    assert "<p>the html body</p>" in analysis.body_html
    # with both, the html part is the body
    assert "unknown_text_html" in analysis.body.file_name

    # the headers and combined files the analyzer writes next to the email are not attachments,
    # whatever the email file is named
    assert analysis.attachment_names == ["invoice.txt"]
    assert "invoice.txt" in [a.file_name for a in analysis.attachments]


@pytest.mark.integration
def test_headers_and_summary(root_analysis):
    _, analysis = _analyze(root_analysis, MULTIPART_EMAIL)

    assert analysis.received_time.isoformat() == "2026-10-23T10:00:05+00:00"
    assert "Subject: quarterly report\n" in analysis.headers_formatted
    assert analysis.log_entry["message_id"] == "<synthetic-analysis@example.com>"
    assert analysis.generate_summary() == (
        "Email Analysis: From Sender <sender@example.com> To Recipient <recipient@example.org> "
        "Subject quarterly report")


@pytest.mark.integration
def test_email_with_an_undecodable_name(root_analysis, unlogged):
    """An email whose file name is not UTF-8 (an archive member, as os.listdir returns it) is parsed
    like any other: its body parts and headers file are named after it."""
    name = b"\xe9\xe9.eml".decode("utf-8", "surrogateescape")
    _, analysis = _analyze(root_analysis, MULTIPART_EMAIL, file_name=name)

    assert isinstance(analysis, EmailAnalysis)
    assert analysis.body_text.strip() == "the plain text body"
    assert "<p>the html body</p>" in analysis.body_html
    assert analysis.attachment_names == ["invoice.txt"]
    assert f"{name}.headers" in [o.file_path for o in analysis.observables if o.type == "file"]


@pytest.mark.integration
def test_office365_journal_without_meta_block(root_analysis, caplog):
    with caplog.at_level(logging.INFO):
        _, analysis = _analyze(root_analysis, JOURNAL_WITHOUT_META)

    assert isinstance(analysis, EmailAnalysis)
    # the envelope has no Message-ID of its own
    assert any(
        "unable to find meta block for message-id unknown" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_text_file_is_not_an_email(root_analysis):
    observable, analysis = _analyze(root_analysis, b"just some text\n", file_name="notes.txt", directive=False)
    assert observable is not None
    assert not analysis


@pytest.mark.unit
def test_empty_analysis_accessors():
    analysis = EmailAnalysis()
    assert not analysis.email
    assert analysis.extraction_errors == []
    assert analysis.headers is None
    assert analysis.received is None
    assert analysis.received_time is None
    assert analysis.headers_formatted == ""
    assert analysis.log_entry is None
    assert analysis.mail_to == []
    assert analysis.cc == []
    assert analysis.x_sender is None


# an attachment whose sender-chosen name looks like the name EmailAnalyzer gives an unnamed body
# part, placed before the real body
DECOY_BODY_NAME_EMAIL = b"""\
From: Sender <sender@example.com>
To: Recipient <recipient@example.org>
Subject: decoy body name
Message-ID: <synthetic-decoy-body-name@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: text/html; name="notes.unknown_text_html_000.html"
Content-Disposition: attachment; filename="notes.unknown_text_html_000.html"

<html><body><p>the attachment</p></body></html>
--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset="utf-8"

the plain text body
--INNER
Content-Type: text/html; charset="utf-8"

<html><body><p>the html body</p></body></html>
--INNER--
--OUTER--
"""


@pytest.mark.integration
def test_a_named_attachment_is_never_a_body_part(root_analysis):
    """The role of each part is what the analyzer recorded, not what its file name looks like."""
    _, analysis = _analyze(root_analysis, DECOY_BODY_NAME_EMAIL, file_name="message.eml")
    assert isinstance(analysis, EmailAnalysis)

    attachment = analysis.find_observable(
        lambda o: o.type == F_FILE and o.file_name == "notes.unknown_text_html_000.html")
    assert attachment is not None
    assert not analysis.is_body_part(attachment)
    assert not analysis.is_html_body_part(attachment)

    assert [o.file_name for o in analysis.body_parts] == ["message.eml.unknown_text_plain_000.txt",
                                                          "message.eml.unknown_text_html_000.html"]
    assert [analysis.is_html_body_part(o) for o in analysis.body_parts] == [False, True]
    assert analysis.body.file_name == "message.eml.unknown_text_html_000.html"
    assert "<p>the html body</p>" in analysis.body_html
    assert analysis.body_text.strip() == "the plain text body"


def _email_analysis_with_files(root_analysis, tmp_path, names: list[str]):
    """An EmailAnalysis built by hand, with a file observable for each name."""
    def _file(analysis, name):
        path = tmp_path / name
        path.write_text(f"<p>{name}</p>" if name.endswith(".html") else name)
        return analysis.add_file_observable(str(path))

    analysis = EmailAnalysis()
    _file(root_analysis, "message.email.rfc822").add_analysis(analysis)
    analysis.details[KEY_EMAIL] = {}
    return analysis, [_file(analysis, name) for name in names]


@pytest.mark.integration
def test_an_email_analyzed_before_parts_were_recorded_reads_the_file_names(root_analysis, tmp_path):
    """An alert analyzed before EmailAnalysis recorded its parts tells its body parts by name."""
    analysis, (plain, html, attachment) = _email_analysis_with_files(root_analysis, tmp_path, [
        "message.email.rfc822.unknown_text_plain_000.txt",
        "message.email.rfc822.unknown_text_html_000.html",
        "invoice.html"])

    assert analysis.body_parts == [plain, html]
    assert analysis.is_html_body_part(html) and not analysis.is_html_body_part(plain)
    assert not analysis.is_body_part(attachment)
    assert analysis.body is html
    assert analysis.body_html == "<p>message.email.rfc822.unknown_text_html_000.html</p>"
    assert analysis.body_text == "message.email.rfc822.unknown_text_plain_000.txt"


@pytest.mark.integration
def test_recorded_parts_are_not_second_guessed_by_file_name(root_analysis, tmp_path):
    """Once the parts are recorded, a file named like a body part that was not recorded as one is not one."""
    analysis, (named_like_a_body,) = _email_analysis_with_files(root_analysis, tmp_path, [
        "message.email.rfc822.unknown_text_html_000.html"])
    analysis.details[KEY_PARTS] = []

    assert analysis.body_parts == []
    assert not analysis.is_body_part(named_like_a_body)
    assert analysis.body is None
    assert analysis.body_html == ""
    assert analysis.body_text == ""


@pytest.mark.integration
def test_a_single_plain_text_part_is_the_body(root_analysis):
    _, analysis = _analyze(root_analysis, SENDER_HEADERS_EMAIL, file_name="message.eml")

    assert [o.file_name for o in analysis.body_parts] == ["message.eml.unknown_text_plain_000.txt"]
    assert analysis.body is analysis.body_parts[0]
    assert analysis.body_text.strip() == "body"
    assert analysis.body_html == ""
