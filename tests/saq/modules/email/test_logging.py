import logging
import os
from unittest.mock import Mock

import pytest
from fluent import sender as fluent_sender

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EMAIL_LOGGER, DIRECTIVE_ORIGINAL_EMAIL, F_URL
from saq.environment import get_base_dir
from saq.modules.email import logging as email_logging
from saq.modules.email.archive import EmailArchiveResults
from saq.modules.email.constants import KEY_LOG_ENTRY
from saq.modules.email.logging import EmailLoggingAnalyzer, FluentBitTags
from saq.modules.email.rfc822 import EmailAnalysis
from tests.saq.test_util import create_test_context

TAGS = FluentBitTags(main="main", urls="urls", headers="headers", lookalike="lookalike")


@pytest.fixture
def emitted(monkeypatch):
    records = []

    def fake_emit(self, label, data):
        records.append((self.tag, data))
        return True

    monkeypatch.setattr(fluent_sender.FluentSender, "emit", fake_emit)
    return records


def make_analyzer(root, **overrides) -> EmailLoggingAnalyzer:
    settings = {
        "brocess_logging_enabled": False,
        "thread_recording_enabled": False,
        "lookalike_telemetry_enabled": False,
        "fluent_bit_logging_enabled": True,
        "fluent_bit_tags": TAGS,
    }
    settings.update(overrides)
    config = get_analysis_module_config(ANALYSIS_MODULE_EMAIL_LOGGER).model_copy(update=settings)
    return EmailLoggingAnalyzer(context=create_test_context(root=root), config=config)


def log_entry(**overrides) -> dict:
    entry = {
        "date": "2026-10-25 12:00:00.000000 +0000",
        "message_id": "<test@example.com>",
        "mail_from": "sender@example.com",
        "env_rcpt_to": ["rcpt@example.com"],
        "headers": ["From: sender@example.com", "Subject: hello"],
    }
    entry.update(overrides)
    return entry


def add_email(root, entry=None, email=True, urls=(), archive_path=None, name="test.email.rfc822"):
    path = root.create_file_path(name)
    with open(path, "wb") as fp:
        fp.write(b"Subject: hello\n\nbody\n")

    observable = root.add_file_observable(path)
    observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)

    analysis = EmailAnalysis()
    if email:
        analysis.email = {KEY_LOG_ENTRY: entry} if entry is not None else {"subject": "hello"}
    observable.add_analysis(analysis)
    for url in urls:
        analysis.add_observable_by_spec(F_URL, url)

    if archive_path:
        archive = EmailArchiveResults()
        archive.archive_path = archive_path
        observable.add_analysis(archive)

    return observable


def records_for(emitted, tag):
    return [data for record_tag, data in emitted if record_tag == tag]


@pytest.mark.unit
def test_every_sender_uses_the_configured_port(root_analysis):
    analyzer = make_analyzer(root_analysis, fluent_bit_hostname="fluent.example", fluent_bit_port=24299)

    senders = [
        analyzer.fluent_bit_main_sender,
        analyzer.fluent_bit_urls_sender,
        analyzer.fluent_bit_headers_sender,
        analyzer.fluent_bit_lookalike_sender,
    ]
    assert [(s.tag, s.host, s.port) for s in senders] == [
        ("main", "fluent.example", 24299),
        ("urls", "fluent.example", 24299),
        ("headers", "fluent.example", 24299),
        ("lookalike", "fluent.example", 24299),
    ]


@pytest.mark.unit
def test_post_analysis_exports_each_original_email(root_analysis, emitted):
    archive_path = os.path.join(get_base_dir(), "archive", "test.gz.e")
    add_email(root_analysis, log_entry(), urls=["http://a.example/", "http://b.example/", "http://a.example/"],
              archive_path=archive_path)
    # a file that is not an original email is not logged
    other_path = root_analysis.create_file_path("other.txt")
    with open(other_path, "wb") as fp:
        fp.write(b"other")
    root_analysis.add_file_observable(other_path)

    assert make_analyzer(root_analysis).execute_post_analysis()

    [main] = records_for(emitted, "main")
    assert main["message_id"] == "<test@example.com>"
    assert main["archive_path"] == os.path.join("archive", "test.gz.e")
    assert main["timestamp"] == "1792929600.0"
    # urls and headers go to their own sources
    assert "extracted_urls" not in main
    assert "headers" not in main

    urls = records_for(emitted, "urls")
    assert sorted(r["url"] for r in urls) == ["http://a.example/", "http://b.example/"]
    assert all(r["message_id"] == "<test@example.com>" and r["timestamp"] == "1792929600.0" for r in urls)

    assert records_for(emitted, "headers") == [
        {"timestamp": "1792929600.0", "message_id": "<test@example.com>",
         "header": "From: sender@example.com", "header_index": 0},
        {"timestamp": "1792929600.0", "message_id": "<test@example.com>",
         "header": "Subject: hello", "header_index": 1},
    ]


@pytest.mark.unit
def test_entry_without_message_id_goes_to_the_main_source_only(root_analysis, emitted, caplog):
    add_email(root_analysis, log_entry(message_id=None), urls=["http://a.example/"])

    with caplog.at_level(logging.WARNING):
        make_analyzer(root_analysis).execute_post_analysis()

    [main] = records_for(emitted, "main")
    assert main["extracted_urls"] == ["http://a.example/"]
    assert main["headers"] == ["From: sender@example.com", "Subject: hello"]
    assert main["archive_path"] is None
    assert records_for(emitted, "urls") == []
    assert records_for(emitted, "headers") == []
    assert any(r.getMessage().startswith("missing message_id for") for r in caplog.records)


@pytest.mark.unit
def test_without_separate_sources_everything_goes_to_main(root_analysis, emitted):
    add_email(root_analysis, log_entry(), urls=["http://a.example/"])

    make_analyzer(root_analysis, fluent_bit_tags=FluentBitTags(main="main")).execute_post_analysis()

    [main] = records_for(emitted, "main")
    # extracted urls are dropped from the main entry even when they have no source of their own
    assert "extracted_urls" not in main
    assert main["headers"] == ["From: sender@example.com", "Subject: hello"]
    assert len(emitted) == 1


@pytest.mark.unit
@pytest.mark.parametrize("setup, warning", [
    ("no_analysis", "missing EmailAnalysis for"),
    ("no_analysis_whitelisted", None),
    ("no_email", "missing analysis.email for"),
    ("whitelisted", None),
    ("no_log_entry", "missing log entry for"),
])
def test_emails_that_are_not_logged(root_analysis, emitted, caplog, setup, warning):
    if setup.startswith("no_analysis"):
        path = root_analysis.create_file_path("test.email.rfc822")
        with open(path, "wb") as fp:
            fp.write(b"Subject: hello\n\nbody\n")
        observable = root_analysis.add_file_observable(path)
        observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    elif setup == "no_email":
        observable = add_email(root_analysis, email=False)
    elif setup == "no_log_entry":
        observable = add_email(root_analysis, entry=None)
    else:
        observable = add_email(root_analysis, log_entry())

    if setup.endswith("whitelisted"):
        observable.add_tag("whitelisted")

    with caplog.at_level(logging.WARNING):
        make_analyzer(root_analysis).execute_post_analysis()

    assert emitted == []
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    if warning:
        assert any(m.startswith(warning) for m in warnings)
    else:
        assert warnings == []


@pytest.mark.unit
def test_a_failed_export_is_logged_and_the_others_still_run(root_analysis, monkeypatch, caplog):
    observable = add_email(root_analysis, log_entry())
    analyzer = make_analyzer(root_analysis, brocess_logging_enabled=True, thread_recording_enabled=True)
    for name in ("export_to_brocess", "export_to_fluent_bit", "export_lookalike_telemetry"):
        monkeypatch.setattr(analyzer, name, Mock(side_effect=RuntimeError(name)))

    with caplog.at_level(logging.ERROR):
        assert analyzer.process_email(observable)

    failures = {r.getMessage(): r for r in caplog.records if r.levelno == logging.ERROR}
    for message in (
        f"unable to create brocess log export for {observable}: export_to_brocess",
        f"unable to create fluent-bit log export for {observable}: export_to_fluent_bit",
        f"unable to create lookalike telemetry for {observable}: export_lookalike_telemetry",
    ):
        assert failures[message].exc_info is not None


@pytest.mark.unit
def test_lookalike_telemetry_needs_a_thread(root_analysis, monkeypatch):
    monkeypatch.setattr("saq.modules.email.conversation.derive_thread_context",
                        Mock(return_value=Mock(thread_id=None, message_id="<test@example.com>")))
    record_thread = Mock()
    monkeypatch.setattr("saq.modules.email.conversation.record_thread", record_thread)
    analyzer = make_analyzer(root_analysis, thread_recording_enabled=True, lookalike_telemetry_enabled=True)

    assert analyzer.export_lookalike_telemetry(log_entry(), Mock()) is False
    record_thread.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("entry, expected", [
    ({"timestamp": "123.0", "date": "not a date"}, "123.0"),
    ({"date": "2026-10-25 12:00:00.000000 +0000"}, "1792929600.0"),
    ({"date": "not a date"}, None),
    ({"date": None}, None),
    ({}, None),
])
def test_entry_timestamp(entry, expected):
    assert EmailLoggingAnalyzer._entry_timestamp(entry) == expected


@pytest.mark.unit
def test_brocess_export_without_a_sender_does_nothing(root_analysis, monkeypatch):
    get_db_connection = Mock()
    monkeypatch.setattr(email_logging, "get_db_connection", get_db_connection)

    make_analyzer(root_analysis).export_to_brocess({"mail_from": "", "env_rcpt_to": ["rcpt@example.com"]})

    get_db_connection.assert_not_called()


@pytest.mark.unit
def test_brocess_export_failure_is_logged(root_analysis, monkeypatch, caplog):
    monkeypatch.setattr(email_logging, "get_db_connection", Mock(side_effect=RuntimeError("no database")))

    with caplog.at_level(logging.ERROR):
        make_analyzer(root_analysis).export_to_brocess(log_entry())

    [record] = [r for r in caplog.records if r.getMessage() == "unable to update brocess: no database"]
    assert record.exc_info is not None


@pytest.mark.integration
def test_brocess_export_skips_empty_recipients(root_analysis, monkeypatch):
    execute_with_retry = Mock()
    monkeypatch.setattr(email_logging, "execute_with_retry", execute_with_retry)

    make_analyzer(root_analysis).export_to_brocess(log_entry(env_rcpt_to=["", "rcpt@example.com"]))

    [call] = execute_with_retry.call_args_list
    assert call.args[3] == (b"sender@example.com", b"rcpt@example.com")
