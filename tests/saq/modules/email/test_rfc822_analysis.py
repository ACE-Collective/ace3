"""What EmailAnalysis records about an email and reads back from it: the sender identity headers,
the body and attachments, the summary, and the office365 journal envelope without its meta block."""

import logging
import os

import pytest

from saq.analysis.root import load_root
from saq.constants import (
    DIRECTIVE_ORIGINAL_EMAIL,
    F_EMAIL_X_AUTH_ID,
    F_EMAIL_X_MAILER,
    F_EMAIL_X_ORIGINAL_SENDER,
    F_EMAIL_X_SENDER,
    F_EMAIL_X_SENDER_ID,
    F_USER_AGENT,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
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
@pytest.mark.parametrize("file_name", ["email.rfc822", "message.eml"])
def test_body_and_attachments(root_analysis, file_name):
    _, analysis = _analyze(root_analysis, MULTIPART_EMAIL, file_name=file_name)
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
