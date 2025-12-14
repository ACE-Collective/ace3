from collections import namedtuple
import os
import shutil
import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.file_manager.file_manager_factory import create_file_manager
from saq.analysis.observable import Observable
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EMAIL_ARCHIVER, DIRECTIVE_ARCHIVE, F_FILE, F_URL, TAG_DECRYPTED_EMAIL, AnalysisExecutionResult
from saq.email_archive import archive_email, get_email_archive_dir, query_by_message_id
from saq.environment import get_global_runtime_settings
from saq.modules.email.archive import EmailArchiveAction, EmailArchiveResults, EncryptedArchiveAnalysis, EncryptedArchiveAnalyzer
from saq.observables.file import FileObservable
from saq.util.hashing import sha256_str
from saq.util.time import local_time
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

@pytest.mark.skip()
@pytest.mark.integration
def test_email_archive_action(root_analysis, tmpdir, monkeypatch):
    analyzer = EmailArchiveAction(
        context=create_test_context(root=root_analysis),
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ARCHIVER))
    assert analyzer.valid_observable_types == [ F_FILE ]
    assert analyzer.required_directives == [ DIRECTIVE_ARCHIVE ]
    assert analyzer.generated_analysis_type is EmailArchiveResults

    whitelisted_path = tmpdir / "whitelisted"
    whitelisted_path.write_binary(b"")

    # whitelisted files are skipped
    whitelisted_observable = root_analysis.add_file_observable(whitelisted_path)
    assert isinstance(whitelisted_observable, Observable)
    whitelisted_observable.whitelist()
    assert analyzer.execute_analysis(whitelisted_observable) == AnalysisExecutionResult.COMPLETED

    # files tagged as decrypted_archive do not need to be archived
    tagged_path = tmpdir / "tagged"
    tagged_path.write_binary(b"")
    tagged_observable = root_analysis.add_file_observable(tagged_path)
    assert isinstance(tagged_observable, Observable)
    tagged_observable.add_tag(TAG_DECRYPTED_EMAIL)
    assert analyzer.execute_analysis(tagged_observable) == AnalysisExecutionResult.COMPLETED

    MockEmailAnalysis = namedtuple("MockEmailAnalysis", ["message_id", "env_rcpt_to"])
    def mock_wait_for_analysis(*args, **kwargs):
        return MockEmailAnalysis(message_id=TEST_MESSAGE_ID, env_rcpt_to=[TEST_RECIPIENT])

    monkeypatch.setattr(analyzer, "wait_for_analysis", mock_wait_for_analysis)

    file_path = root_analysis.create_file_path("email.rfc822")
    with open(file_path, "w") as fp:
        fp.write("test")

    file_observable = root_analysis.add_file_observable(file_path)
    assert isinstance(file_observable, Observable)
    file_observable.add_directive(DIRECTIVE_ARCHIVE)

    # archive directory should be empty
    assert not len(os.listdir(get_email_archive_dir()))

    assert analyzer.execute_analysis(file_observable) == AnalysisExecutionResult.COMPLETED

    # archive directory should have one entry 
    assert len(os.listdir(get_email_archive_dir())) == 1

    from saq.modules.email.rfc822 import EmailAnalysis
    file_observable.add_analysis(EmailAnalysis())

    some_analysis = Analysis()
    file_observable.add_analysis(some_analysis)
    some_analysis.add_observable_by_spec(F_URL, "http://www.test.com/")

    analyzer.execute_post_analysis()

    # make sure it got indexed
    assert query_by_message_id(TEST_MESSAGE_ID)
