import hashlib

import pytest

from saq.configuration import get_config
from saq.configuration.config import get_analysis_module_config
import saq.email_archive
import saq.modules.email.message_id

from saq.analysis import RootAnalysis
from saq.constants import ANALYSIS_MODULE_MESSAGE_ID_ANALYZER_V2, F_MESSAGE_ID, F_FILE, DB_EMAIL_ARCHIVE, AnalysisExecutionResult
from saq.database import get_db_connection
from saq.modules.email.message_id import MessageIDAnalysisV2, MessageIDAnalyzerV2
from tests.saq.test_util import create_test_context

# TODO put this into a common email archive testing library
@pytest.fixture(autouse=True)
def reset_database(request, pytestconfig):
    if request.node.get_closest_marker('integration') is None:
        return

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        c = db.cursor()
        c.execute("DELETE FROM archive_server")
        db.commit()

    saq.email_archive.SERVER_ID = None

@pytest.mark.unit
def test_message_id_analysis_v2():
    analysis = MessageIDAnalysisV2()
    assert analysis.generate_summary() is None
    analysis.error = "test"
    assert analysis.generate_summary() == "Message ID Analysis: ERROR: test"
    analysis.error = None
    analysis.extracted_email = "test"
    assert analysis.generate_summary() == "Message ID Analysis: archived email extracted test"

@pytest.mark.integration
def test_message_id_analyzer_v2(test_context, tmpdir, monkeypatch):
    root = RootAnalysis(storage_dir=str(tmpdir / "root"))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_MESSAGE_ID, "<test@local>")

    def mock_iter_archived_email(message_id: str):
        yield b"This is a test."

    monkeypatch.setattr(saq.modules.email.message_id, "iter_archived_email", mock_iter_archived_email)
    monkeypatch.setattr(saq.modules.email.message_id, "email_is_archived", lambda message_id: True)
    analyzer = MessageIDAnalyzerV2(get_analysis_module_config(ANALYSIS_MODULE_MESSAGE_ID_ANALYZER_V2), context=create_test_context(root=root))
    analyzer.execute_analysis(observable)
    analysis = observable.get_and_load_analysis(analyzer.generated_analysis_type)
    observable = analysis.get_observable_by_type(F_FILE)
    expected_name = f"{hashlib.sha256('<test@local>'.encode()).hexdigest()}.rfc822"
    assert observable.file_name == expected_name
    assert observable.has_tag("decrypted_email")
    with open(observable.full_path, "r") as fp:
        assert fp.read() == "This is a test."

@pytest.mark.integration
def test_message_id_analyzer_v2_emtpy_result(test_context, tmpdir, monkeypatch):
    root = RootAnalysis(storage_dir=str(tmpdir / "root"))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_MESSAGE_ID, "<test@local>")

    def mock_iter_archived_email(message_id: str):
        yield b""

    monkeypatch.setattr(saq.modules.email.message_id, "iter_archived_email", mock_iter_archived_email)
    analyzer = MessageIDAnalyzerV2(get_analysis_module_config(ANALYSIS_MODULE_MESSAGE_ID_ANALYZER_V2), context=create_test_context(root=root))
    assert analyzer.execute_analysis(observable) == AnalysisExecutionResult.COMPLETED
    assert observable.get_and_load_analysis(analyzer.generated_analysis_type) is None

@pytest.mark.integration
def test_message_id_analyzer_v2_unknown_message_id(tmpdir, monkeypatch):
    root = RootAnalysis(storage_dir=str(tmpdir / "root"))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_MESSAGE_ID, "<test@local>")

    # unknown message_id or unable to process

    def mock_iter_archived_email(message_id: str):
        raise RuntimeError("Unknown message id")

    monkeypatch.setattr(saq.modules.email.message_id, "iter_archived_email", mock_iter_archived_email)
    analyzer = MessageIDAnalyzerV2(get_analysis_module_config(ANALYSIS_MODULE_MESSAGE_ID_ANALYZER_V2), context=create_test_context(root=root))
    analyzer.execute_analysis(observable)
    analysis = observable.get_and_load_analysis(analyzer.generated_analysis_type)
    assert analysis is None

@pytest.mark.integration
def test_message_id_analyzer_v2_target_file_exists(test_context, tmpdir, monkeypatch):
    root = RootAnalysis(storage_dir=str(tmpdir / "root"))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_MESSAGE_ID, "<test@local>")
    hashed_name = f"{hashlib.sha256('<test@local>'.encode()).hexdigest()}.rfc822"
    target_path = root.create_file_path(hashed_name)
    with open(target_path, "w") as fp:
        fp.write("Already exists.")

    file_observable = root.add_file_observable(hashed_name)

    def mock_iter_archived_email(message_id: str):
        yield b"This is a test."

    monkeypatch.setattr(saq.modules.email.message_id, "iter_archived_email", mock_iter_archived_email)
    monkeypatch.setattr(saq.modules.email.message_id, "email_is_archived", lambda message_id: True)
    analyzer = MessageIDAnalyzerV2(get_analysis_module_config(ANALYSIS_MODULE_MESSAGE_ID_ANALYZER_V2), context=create_test_context(root=root))
    analyzer.execute_analysis(observable)
    analysis = observable.get_and_load_analysis(analyzer.generated_analysis_type)
    observable = analysis.get_observable_by_type(F_FILE)
    assert observable.file_name == hashed_name
    assert observable.has_tag("decrypted_email")
    with open(observable.full_path, "r") as fp:
        assert fp.read() == "Already exists."
