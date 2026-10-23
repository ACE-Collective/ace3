import logging
import shutil
from email.message import EmailMessage
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_TYPE_MAILBOX,
    DB_BROCESS,
    DIRECTIVE_SANDBOX,
    F_EMAIL_CONVERSATION,
    F_FILE,
    F_URL,
    create_email_conversation,
)
from saq.database import get_db_connection
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email import EmailAnalysis
from saq.modules.email.fa import (
    EmailConversationAttachmentAnalysis,
    EmailConversationFrequencyAnalysis,
    EmailConversationLinkAnalysis,
)
from saq.signatures.builtin import EMAIL_MACRO_NEW_SENDER, EMAIL_SUSPECT_URL_NEW_SENDER
from saq.util.uuid import get_storage_dir

SENDER = "sender@external.example.com"
RECIPIENT = "recipient@internal.example.com"
MACRO_DOCUMENT = Path(__file__).parent.parent / "test_file_analysis_full" / "ole_files" / "mortgage_payment-0873821-0565.docm"

FREQUENCY = "email_conversation_frequency_analyzer"


def _seen(source: str, destination: str, count: int):
    with get_db_connection(DB_BROCESS) as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO smtplog (source, destination, numconnections) VALUES (%s, %s, %s)", (source, destination, count))
        db.commit()


def _analyze_conversation(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    conversation = root_analysis.add_observable_by_spec(F_EMAIL_CONVERSATION, create_email_conversation(SENDER, RECIPIENT))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(FREQUENCY, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(conversation.uuid)


#
# frequency
#

@pytest.mark.integration
def test_first_time_sender(root_analysis):
    conversation = _analyze_conversation(root_analysis)

    assert conversation.has_tag("new_sender")
    analysis = conversation.get_and_load_analysis(EmailConversationFrequencyAnalysis)
    assert analysis.source_count == 0
    assert analysis.dest_count is None
    assert analysis.summary == "Email Conversation Frequency Analysis - first time received"


@pytest.mark.integration
@pytest.mark.parametrize("conversations, frequent", [(5, True), (4, False)])
def test_known_sender(root_analysis, conversations, frequent):
    _seen(SENDER, RECIPIENT, conversations)
    _seen(SENDER, "someone.else@internal.example.com", 10)

    conversation = _analyze_conversation(root_analysis)

    assert not conversation.has_tag("new_sender")
    # the threshold is 5
    assert conversation.has_tag("frequent_conversation") == frequent
    analysis = conversation.get_and_load_analysis(EmailConversationFrequencyAnalysis)
    assert analysis.source_count == conversations + 10
    assert analysis.dest_count == conversations
    assert analysis.summary == f"Email Conversation Frequency Analysis - {conversations + 10} emails received before, {conversations} to this user"


@pytest.mark.integration
@pytest.mark.parametrize("failing_query", ["query_brocess_by_source_email", "query_brocess_by_email_conversation"])
def test_brocess_failure(root_analysis, monkeypatch, caplog, failing_query):
    _seen(SENDER, RECIPIENT, 1)

    def _fail(*args):
        raise RuntimeError("brocess is down")

    monkeypatch.setattr(f"saq.modules.email.fa.{failing_query}", _fail)
    conversation = _analyze_conversation(root_analysis)

    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info and "unable to query brocess" in r.getMessage()]
    assert len(errors) == 1
    analysis = conversation.get_and_load_analysis(EmailConversationFrequencyAnalysis)
    if failing_query == "query_brocess_by_source_email":
        assert not analysis
    else:
        assert analysis.dest_count is None


#
# attachments and links from new senders
#

def _email(tmp_path: Path, attachment: Path = None, body: str = "hello") -> Path:
    message = EmailMessage()
    message["From"] = SENDER
    message["To"] = RECIPIENT
    message["Subject"] = "payment"
    message["Message-ID"] = "<conversation-frequency-test@example.com>"
    message.set_content(body)
    if attachment:
        message.add_attachment(attachment.read_bytes(), maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename=attachment.name)
    path = tmp_path / "message.email.rfc822"
    path.write_bytes(bytes(message))
    return path


def _analyze_email(root_analysis, path: Path, modules: tuple[str, ...]):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    email_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in ("file_type", "email_analyzer", FREQUENCY) + modules:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    email_observable = root.get_observable(email_observable.uuid)
    return root, email_observable.get_and_load_analysis(EmailAnalysis)


@pytest.mark.integration
@pytest.mark.parametrize("known_sender", [False, True])
def test_macro_from_new_sender(root_analysis, tmp_path, known_sender):
    if known_sender:
        _seen(SENDER, RECIPIENT, 1)
    shutil.copy(MACRO_DOCUMENT, tmp_path / "payment.docm")

    _, email_analysis = _analyze_email(root_analysis, _email(tmp_path, attachment=tmp_path / "payment.docm"),
                                       ("olevba_v1_2", "email_conversation_attachment_analyzer"))

    attachment = email_analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == "payment.docm")
    detected = bool(attachment.get_and_load_analysis(EmailConversationAttachmentAnalysis))
    assert detected != known_sender
    if not known_sender:
        assert attachment.has_directive(DIRECTIVE_SANDBOX)
    assert (EMAIL_MACRO_NEW_SENDER.uuid in [d.signature_uuid for d in attachment.detections]) != known_sender


@pytest.mark.integration
@pytest.mark.parametrize("url, known_sender, detected", [
    ("https://evil.example.com/login", False, True),
    ("https://evil.example.com/login", True, False),
    # not one of the patterns
    ("https://www.example.org/news", False, False),
])
def test_suspect_url_from_new_sender(root_analysis, tmp_path, url, known_sender, detected):
    # the shipped config has no url_pattern_* entries
    setattr(get_analysis_module_config("email_conversation_link_analyzer"), "url_pattern_login", r"/login$")
    if known_sender:
        _seen(SENDER, RECIPIENT, 1)

    root, email_analysis = _analyze_email(root_analysis, _email(tmp_path, body=f"please sign in at {url} today"),
                                          ("url_extraction", "email_conversation_link_analyzer"))

    [url_observable] = [o for o in root.all_observables if o.type == F_URL and o.value == url]
    assert bool(url_observable.get_and_load_analysis(EmailConversationLinkAnalysis)) == (url.endswith("/login"))
    assert (EMAIL_SUSPECT_URL_NEW_SENDER.uuid in [d.signature_uuid for d in url_observable.detections]) == detected
