"""What the email analyzer does when it cannot parse an email, or one of its parts."""

import email.parser
import logging
import os

import pytest

from saq.analysis.root import load_root
from saq.constants import DIRECTIVE_ORIGINAL_EMAIL
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_data_dir
from saq.modules.email.rfc822 import EmailAnalysis
from saq.util.uuid import get_storage_dir

EMAIL = b"""\
From: Sender <sender@example.com>
To: Recipient <recipient@example.com>
Subject: quarterly report
Message-ID: <synthetic-failures@example.com>
Date: Fri, 23 Oct 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

see attached
--BOUNDARY
Content-Type: text/plain; name="boom.txt"
Content-Disposition: attachment; filename="boom.txt"

the attachment that fails to extract
--BOUNDARY--
"""


def _review_files() -> set[str]:
    return set(os.listdir(os.path.join(get_data_dir(), "review", "rfc822")))


def _analyze(root_analysis, file_path: str):
    path = root_analysis.create_file_path(file_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fp:
        fp.write(EMAIL)

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(path)
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


@pytest.fixture
def failing_attachment(monkeypatch):
    from saq.modules.email import rfc822

    real_safe_file_name = rfc822.safe_file_name

    def safe_file_name(name):
        if name == "boom.txt":
            raise RuntimeError("cannot extract this part")
        return real_safe_file_name(name)

    monkeypatch.setattr(rfc822, "safe_file_name", safe_file_name)


@pytest.mark.integration
@pytest.mark.parametrize("file_path", [
    "email.rfc822",
    # an email extracted from an archive lives in a subdirectory of the storage directory
    "attachments.zip.extracted/email.rfc822",
])
def test_a_part_that_cannot_be_extracted_is_recorded(root_analysis, failing_attachment, caplog, file_path):
    before = _review_files()

    observable, analysis = _analyze(root_analysis, file_path)

    assert isinstance(analysis, EmailAnalysis)
    analysis.load_details()
    [error] = analysis.extraction_errors
    assert error["filename"] == "boom.txt"
    assert error["exception"] == "RuntimeError: cannot extract this part"
    assert observable.has_tag("email_parse_incomplete")
    # the other part is still extracted
    assert analysis.body_text.strip() == "see attached"
    # and a copy is kept for review, named after the email
    [copied] = _review_files() - before
    assert copied.startswith("email.rfc822.")
    assert "analysis module crash recorded" not in caplog.text


@pytest.mark.integration
def test_a_review_copy_that_cannot_be_saved_keeps_the_analysis(root_analysis, failing_attachment, monkeypatch, caplog):
    from saq.modules.email import rfc822

    def no_space(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(rfc822.shutil, "copy", no_space)

    with caplog.at_level(logging.ERROR):
        observable, analysis = _analyze(root_analysis, "email.rfc822")

    assert isinstance(analysis, EmailAnalysis)
    analysis.load_details()
    assert len(analysis.extraction_errors) == 1
    [record] = [r for r in caplog.records if "for review" in r.getMessage()]
    assert record.exc_info is not None


@pytest.mark.integration
def test_an_email_that_cannot_be_parsed_is_kept_for_review(root_analysis, monkeypatch, caplog):
    def broken(self, fp, headersonly=False):
        raise ValueError("not an email")

    monkeypatch.setattr(email.parser.BytesParser, "parse", broken)
    before = _review_files()

    with caplog.at_level(logging.ERROR):
        _, analysis = _analyze(root_analysis, "email.rfc822")

    assert not analysis
    [record] = [r for r in caplog.records if r.getMessage().startswith("unable to parse email")]
    assert record.exc_info is not None
    assert len(_review_files() - before) == 1


@pytest.mark.integration
def test_an_unparsable_email_whose_review_copy_fails(root_analysis, monkeypatch, caplog):
    from saq.modules.email import rfc822

    def broken(self, fp, headersonly=False):
        raise ValueError("not an email")

    def no_space(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(email.parser.BytesParser, "parse", broken)
    monkeypatch.setattr(rfc822.shutil, "copy", no_space)

    with caplog.at_level(logging.ERROR):
        _, analysis = _analyze(root_analysis, "email.rfc822")

    assert not analysis
    [record] = [r for r in caplog.records if "for review" in r.getMessage()]
    assert "email.rfc822" in record.getMessage()
    assert record.exc_info is not None
