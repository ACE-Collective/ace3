import os
import pytest

from saq.database import get_db_connection
from saq.constants import DB_EMAIL_ARCHIVE
from saq.email_archive import (
    ArchiveEmailResult,
    archive_email,
    archive_email_file,
    get_archive_path_by_hash,
    get_archived_email_server,
    get_email_archive_local_server_name,
    get_email_archive_server_id,
    get_recipients_by_message_id,
    index_email_history,
    get_archived_email_path,
    iter_decrypt_email,
)
from saq.email_archive.types import EmailArchiveTargetType
from saq.environment import get_data_dir
from saq.util.time import local_time

@pytest.fixture(autouse=True, scope="function", params=[EmailArchiveTargetType.LOCAL])
def patch_email_archive_target_type(monkeypatch, request):
    monkeypatch.setattr("saq.email_archive.factory.get_email_archive_type", lambda: request.param)
    return request.param

@pytest.mark.integration
def test_register_email_archive():
    assert get_email_archive_server_id() is not None

TEST_MESSAGE_ID = "<test-message-id>"
TEST_RECIPIENT = "test@local"
TEST_RECIPIENT_2 = "test2@local"

@pytest.fixture
def archived_email(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    return archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())

@pytest.mark.unit
def test_archive_email_file(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    md5_hash = archive_email_file(str(email), TEST_MESSAGE_ID)
    assert os.path.exists(get_archive_path_by_hash(md5_hash))

    # should return existing
    assert archive_email_file(str(email), TEST_MESSAGE_ID) == md5_hash

    # should error on missing file
    with pytest.raises(IOError):
        archive_email_file("unknown", TEST_MESSAGE_ID)

@pytest.mark.integration
def test_archive_email(archived_email: ArchiveEmailResult):
    assert isinstance(archived_email.archive_id, int)
    assert isinstance(archived_email.hash, str) and archived_email.hash

@pytest.mark.integration
def test_get_archived_email_server(archived_email):
    assert get_archived_email_server(TEST_MESSAGE_ID) == get_email_archive_local_server_name()
    assert get_archived_email_server("unknown") is None

@pytest.mark.integration
def test_get_archived_email_path(archived_email):
    assert get_archived_email_path(TEST_MESSAGE_ID) == os.path.join(get_data_dir(), "archive/email/ace/9f/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.gz.e")
    assert get_archived_email_path("unknown") is None

@pytest.mark.integration
def test_duplicate(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    insert_date = local_time()
    result_1 = archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], insert_date)
    result_2 = archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], insert_date)
    assert result_1 == result_2

@pytest.mark.integration
def test_multiple_recipients(archived_email):
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        index_email_history(db, cursor, TEST_MESSAGE_ID, [TEST_RECIPIENT_2], archived_email.insert_date)
        db.commit()

    result = get_recipients_by_message_id(TEST_MESSAGE_ID)
    assert len(result) == 2
    assert TEST_RECIPIENT in result
    assert TEST_RECIPIENT_2 in result

@pytest.mark.integration
def test_duplicate_index(archived_email):
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        index_email_history(db, cursor, TEST_MESSAGE_ID, [TEST_RECIPIENT], archived_email.insert_date)
        db.commit()

    result = get_recipients_by_message_id(TEST_MESSAGE_ID)
    assert len(result) == 1

@pytest.mark.integration
def test_iter_decrypt_email(archived_email):
    result = []
    for chunk in iter_decrypt_email(get_archived_email_path(TEST_MESSAGE_ID), chunk_size=1):
        result.append(chunk)

    assert result == [b't', b'e', b's', b't']

