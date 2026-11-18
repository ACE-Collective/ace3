import logging
import os
import shutil
import pytest

from saq.analysis.analysis import UnknownAnalysis, load_analysis_from_module_path
from saq.analysis.file_manager.file_manager_factory import create_file_manager
from saq.analysis.observable import Observable
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EMAIL_ARCHIVER, DIRECTIVE_ARCHIVE, F_FILE, TAG_DECRYPTED_EMAIL, AnalysisExecutionResult
from saq.email_archive import find_archived_email, query_archive_hashes
from saq.environment import get_data_dir
from saq.modules.email.constants import KEY_ENV_RCPT_TO, KEY_MESSAGE_ID
from saq.modules.email.rfc822 import TAG_OUTBOUND_EMAIL, EmailAnalysis
from saq.modules.email.archive import EmailArchiveAction, EmailArchiveResults
from saq.observables.file import FileObservable
from saq.util.hashing import sha256_str
from tests.saq.test_util import create_test_context

TEST_MESSAGE_ID = "<test-message-id>"
TEST_RECIPIENT = "test@local"

@pytest.mark.unit
def test_email_archive_results(tmpdir):
    analysis = EmailArchiveResults()
    analysis.file_manager = create_file_manager(str(tmpdir))
    assert analysis.message_id is None
    assert analysis.hash is None
    assert analysis.generate_summary() is None

    analysis.message_id = TEST_MESSAGE_ID
    analysis.hash = sha256_str("test")

    assert analysis.generate_summary() == f"Archived Email: {sha256_str('test')}"

def _email_file(root_analysis, name: str, message_id: str | None = TEST_MESSAGE_ID) -> FileObservable:
    """An email file with the EmailAnalysis the engine would have given it first (a declared
    dependency), or none when message_id is None."""
    file_path = root_analysis.create_file_path(name)
    with open(file_path, "w") as fp:
        fp.write(f"email {name}")

    file_observable = root_analysis.add_file_observable(file_path)
    assert isinstance(file_observable, FileObservable)
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    if message_id is not None:
        email_analysis = EmailAnalysis()
        email_analysis.email = {KEY_MESSAGE_ID: message_id, KEY_ENV_RCPT_TO: [TEST_RECIPIENT]}
        file_observable.add_analysis(email_analysis)
    return file_observable

def _archived() -> list[str]:
    """The emails archived under TEST_MESSAGE_ID."""
    return query_archive_hashes(TEST_MESSAGE_ID)

@pytest.mark.integration
@pytest.mark.parametrize("case,expected_log", [
    ("decrypted", "detected decrypted email"),
    ("no_email_analysis", "unable to obtain EmailAnalysis"),
    # scan_inbound_only skipped its email analysis on purpose
    ("outbound_not_analyzed", None),
])
def test_email_archive_action_skips_files_it_should_not_archive(root_analysis, caplog, case, expected_log):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))
    assert analyzer.valid_observable_types == [ F_FILE ]
    assert analyzer.required_directives == [ DIRECTIVE_ARCHIVE ]

    # the decrypted one has everything archiving needs, so only the check under test stops it
    has_email_analysis = case == "decrypted"
    file_observable = _email_file(root_analysis, "email.rfc822", message_id=TEST_MESSAGE_ID if has_email_analysis else None)
    if case == "decrypted":
        file_observable.add_tag(TAG_DECRYPTED_EMAIL)
    elif case == "outbound_not_analyzed":
        file_observable.add_tag(TAG_OUTBOUND_EMAIL)

    assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED

    assert file_observable.get_analysis(EmailArchiveResults) is None
    assert _archived() == []
    if expected_log:
        assert any(expected_log in r.getMessage() and r.levelname == "WARNING" for r in caplog.records)
    else:
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

@pytest.mark.integration
def test_an_email_tagged_whitelisted_is_still_archived(root_analysis):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    file_observable = _email_file(root_analysis, "email.rfc822")
    file_observable.add_tag("whitelisted")

    assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED

    archive_results = file_observable.get_analysis(EmailArchiveResults)
    assert isinstance(archive_results, EmailArchiveResults)
    assert _archived() == [sha256_str(open(file_observable.full_path).read())]
    # the email itself is in the pool, under the hash the analysis records
    assert find_archived_email(TEST_MESSAGE_ID) == archive_results.hash

@pytest.mark.integration
def test_an_email_without_envelope_recipients_is_still_archived(root_analysis):
    # the archive is found by Message-ID alone; it no longer records who received the email
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    file_observable = _email_file(root_analysis, "email.rfc822")
    file_observable.get_analysis(EmailAnalysis).email[KEY_ENV_RCPT_TO] = None

    assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED
    archive_results = file_observable.get_analysis(EmailArchiveResults)
    assert isinstance(archive_results, EmailArchiveResults)
    assert find_archived_email(TEST_MESSAGE_ID) == archive_results.hash

@pytest.mark.unit
def test_email_archive_action_skips_an_email_without_a_message_id(root_analysis, tmpdir, caplog):
    message_id, env_rcpt_to, expected_log_fragment = None, [TEST_RECIPIENT], "missing message-id header"
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    review_dir = os.path.join(get_data_dir(), "review", "rfc822")
    if os.path.isdir(review_dir):
        shutil.rmtree(review_dir)

    file_path = root_analysis.create_file_path("email.rfc822")
    with open(file_path, "w") as fp:
        fp.write("test")

    file_observable = root_analysis.add_file_observable(file_path)
    assert isinstance(file_observable, Observable)
    file_observable.add_directive(DIRECTIVE_ARCHIVE)

    # EmailAnalysis is a declared dependency; provide it directly since we invoke
    # execute_analysis outside the engine (which would normally seed it)
    email_analysis = EmailAnalysis()
    email_analysis.email = {KEY_MESSAGE_ID: message_id, KEY_ENV_RCPT_TO: env_rcpt_to}
    file_observable.add_analysis(email_analysis)
    root_analysis.save()

    result = analyzer.execute_analysis(file_observable)
    assert result == AnalysisExecutionResult.COMPLETED

    # verify the email was saved to the review directory
    assert os.path.isdir(review_dir)
    review_files = os.listdir(review_dir)
    assert len(review_files) == 1
    assert review_files[0].endswith(".rfc822")
    assert open(os.path.join(review_dir, review_files[0])).read() == "test"

    # verify the error was logged
    assert expected_log_fragment in caplog.text

@pytest.mark.unit
@pytest.mark.parametrize("module_path", [
    "saq.modules.email.correlation:URLEmailPivotAnalysis_v2",
    "saq.modules.email.archive:EncryptedArchiveAnalysis",
])
def test_an_alert_with_an_analysis_of_a_removed_archive_module_still_loads(module_path, caplog):
    # alerts analyzed before the archive stopped being searchable reference these classes
    with caplog.at_level(logging.DEBUG):
        analysis = load_analysis_from_module_path(module_path)

    assert isinstance(analysis, UnknownAnalysis)
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
