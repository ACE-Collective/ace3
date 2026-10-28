import os
import shutil
import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.file_manager.file_manager_factory import create_file_manager
from saq.analysis.observable import Observable
from saq.configuration.config import get_analysis_module_config
from saq.database.pool import get_db_connection
from saq.constants import ANALYSIS_MODULE_EMAIL_ARCHIVER, DB_EMAIL_ARCHIVE, DIRECTIVE_ARCHIVE, F_FILE, F_URL, TAG_DECRYPTED_EMAIL, AnalysisExecutionResult
from saq.email_archive import archive_email, get_email_archive_dir, query_by_message_id
from saq.environment import get_global_runtime_settings
from saq.environment import get_data_dir
from saq.modules.email.constants import KEY_ENV_RCPT_TO, KEY_MESSAGE_ID
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.email.archive import EmailArchiveAction, EmailArchiveResults, EncryptedArchiveAnalysis, EncryptedArchiveAnalyzer
from saq.observables.file import FileObservable
from saq.util.hashing import sha256_str
from saq.util.time import local_time
from tests.saq.helpers import inject_deadlock
from tests.saq.test_util import create_test_context

TEST_MESSAGE_ID = "<test-message-id>"
TEST_RECIPIENT = "test@local"

@pytest.fixture
def archived_email(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    return archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())

@pytest.mark.unit
def test_encrypted_archive_analysis(tmpdir):
    analysis = EncryptedArchiveAnalysis()
    analysis.file_manager = create_file_manager(str(tmpdir))
    assert analysis.decrypted_file is None
    assert analysis.generate_summary() is None
    analysis.decrypted_file = "test"
    assert analysis.generate_summary()

@pytest.mark.unit
def test_encrypted_archive_analyzer(root_analysis, archived_email, monkeypatch, tmpdir):
    analyzer = EncryptedArchiveAnalyzer(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))
    analyzer.verify_environment()
    assert analyzer.generated_analysis_type is EncryptedArchiveAnalysis
    assert analyzer.valid_observable_types == F_FILE

    shutil.copy(archived_email.archive_path, root_analysis.storage_dir)

    observable = root_analysis.add_file_observable(archived_email.archive_path)
    assert isinstance(observable, Observable)

    with monkeypatch.context() as mp:
        mp.setattr(get_global_runtime_settings(), "encryption_initialized", False)
        # returns False if encryption is not initialized
        assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED

    # skip files that do not end with .gz.e
    target_path = tmpdir / "invalid"
    target_path.write_binary(b"test")
    target_path = str(target_path)

    invalid_observable = root_analysis.add_file_observable(target_path)
    assert isinstance(invalid_observable, Observable)
    assert analyzer.execute_analysis(invalid_observable) == AnalysisExecutionResult.COMPLETED

    # handle corrupt file
    invalid_path = tmpdir / "invalid.gz.e"
    invalid_path.write_binary(b'blahblahblah')

    corrupt_file = root_analysis.add_file_observable(str(invalid_path))
    assert isinstance(corrupt_file, Observable)
    assert analyzer.execute_analysis(corrupt_file) == AnalysisExecutionResult.COMPLETED

    # hand valid file
    analysis_result = analyzer.execute_analysis(observable)
    assert analysis_result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(EncryptedArchiveAnalysis)
    assert isinstance(analysis, EncryptedArchiveAnalysis)

    assert analysis.decrypted_file == "files/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.rfc822"
    file_observable = analysis.get_observable_by_type(F_FILE)
    assert isinstance(file_observable, FileObservable)
    assert file_observable.has_tag(TAG_DECRYPTED_EMAIL)
    with open(file_observable.full_path, "rb") as fp:
        assert fp.read() == b'test'

@pytest.mark.unit
def test_email_archive_results(tmpdir):
    analysis = EmailArchiveResults()
    analysis.file_manager = create_file_manager(str(tmpdir))
    assert analysis.message_id is None
    assert analysis.archive_id is None
    assert analysis.archive_path is None
    assert analysis.hash is None
    assert analysis.generate_summary() is None

    analysis.message_id = TEST_MESSAGE_ID
    analysis.archive_id = 1
    analysis.archive_path = "/some/path"
    analysis.hash = sha256_str("test")

    assert analysis.generate_summary()

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

def _archive_entries() -> list[str]:
    archive_dir = get_email_archive_dir()
    return os.listdir(archive_dir) if os.path.isdir(archive_dir) else []

def _url_index_count(archive_id: int, url: str) -> int:
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM archive_index WHERE field = 'url' AND hash = UNHEX(SHA2(%s, 256)) AND archive_id = %s",
            (url, archive_id))
        return cursor.fetchone()[0]

@pytest.mark.integration
@pytest.mark.parametrize("case,expected_log", [
    ("whitelisted", None),
    ("decrypted", "detected decrypted email"),
    ("no_email_analysis", "unable to obtain EmailAnalysis"),
])
def test_email_archive_action_skips_files_it_should_not_archive(root_analysis, caplog, case, expected_log):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))
    assert analyzer.valid_observable_types == [ F_FILE ]
    assert analyzer.required_directives == [ DIRECTIVE_ARCHIVE ]

    # the first two have everything archiving needs, so only the check under test stops them
    file_observable = _email_file(root_analysis, "email.rfc822", message_id=None if case == "no_email_analysis" else TEST_MESSAGE_ID)
    if case == "whitelisted":
        file_observable.whitelist()
    elif case == "decrypted":
        file_observable.add_tag(TAG_DECRYPTED_EMAIL)

    assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED

    assert file_observable.get_analysis(EmailArchiveResults) is None
    assert _archive_entries() == []
    assert not query_by_message_id(TEST_MESSAGE_ID)
    if expected_log:
        assert any(expected_log in r.getMessage() and r.levelname == "WARNING" for r in caplog.records)

@pytest.mark.integration
def test_post_analysis_indexes_the_urls_found_under_each_archived_email(root_analysis):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    archived = _email_file(root_analysis, "archived.rfc822")
    assert analyzer.execute_analysis(archived) == AnalysisExecutionResult.COMPLETED
    assert len(_archive_entries()) == 1
    archive_results = archived.get_analysis(EmailArchiveResults)
    assert isinstance(archive_results, EmailArchiveResults)

    # a URL that an analysis of the email found
    content_analysis = Analysis()
    archived.add_analysis(content_analysis)
    content_analysis.add_observable_by_spec(F_URL, "http://archived.example.com/")

    # an email that was analyzed but never archived has nothing to index under
    not_archived = _email_file(root_analysis, "not_archived.rfc822", message_id="<other-message-id>")
    other_analysis = Analysis()
    not_archived.add_analysis(other_analysis)
    other_analysis.add_observable_by_spec(F_URL, "http://not-archived.example.com/")

    # a URL that is not under any email
    root_analysis.add_observable_by_spec(F_URL, "http://elsewhere.example.com/")

    analyzer.execute_post_analysis()

    assert _url_index_count(archive_results.archive_id, "http://archived.example.com/") == 1
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM archive_index WHERE field = 'url'")
        assert cursor.fetchone()[0] == 1

@pytest.mark.integration
def test_indexing_the_urls_runs_again_from_the_start_after_a_deadlock(root_analysis, monkeypatch):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    archived = _email_file(root_analysis, "archived.rfc822")
    assert analyzer.execute_analysis(archived) == AnalysisExecutionResult.COMPLETED
    archive_results = archived.get_analysis(EmailArchiveResults)
    content_analysis = Analysis()
    archived.add_analysis(content_analysis)
    content_analysis.add_observable_by_spec(F_URL, "http://first.example.com/")
    content_analysis.add_observable_by_spec(F_URL, "http://second.example.com/")

    # the second URL's row is the deadlock victim, after the first one's was written
    failed = inject_deadlock(monkeypatch, "INSERT IGNORE INTO archive_index", skip=1)
    analyzer.index_email(archived)

    assert len(failed) == 1
    assert _url_index_count(archive_results.archive_id, "http://first.example.com/") == 1
    assert _url_index_count(archive_results.archive_id, "http://second.example.com/") == 1

@pytest.mark.unit
@pytest.mark.parametrize("message_id,env_rcpt_to,expected_log_fragment", [
    (None, [TEST_RECIPIENT], "missing message-id header"),
    (TEST_MESSAGE_ID, None, "missing envelope recipients"),
], ids=["missing_message_id", "missing_env_rcpt_to"])
def test_email_archive_action_skips_on_missing_fields(root_analysis, tmpdir, caplog, message_id, env_rcpt_to, expected_log_fragment):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))

    # clean up review directory from previous parametrized runs
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
