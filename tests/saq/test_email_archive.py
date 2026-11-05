import copy
import os
import pytest
from pydantic import ValidationError

from saq.configuration.config import get_config
from saq.configuration.schema import ACEConfig
from saq.database import get_db_connection
from saq.constants import DB_EMAIL_ARCHIVE
from saq.email_archive import (
    archive_email,
    archive_email_file,
    get_archive_path_by_hash,
    get_archived_email_server,
    get_email_archive_dir,
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
from tests.saq.helpers import inject_deadlock

@pytest.fixture(autouse=True, scope="function", params=[EmailArchiveTargetType.LOCAL])
def patch_email_archive_target_type(monkeypatch, request):
    monkeypatch.setattr(get_config().email_archive, "target", request.param.value)
    return request.param

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
    # content no other test archives: unit tests get no data dir reset, and this one overwrites
    # its archive file
    email = tmpdir / "email"
    email.write_binary(b"test_archive_email_file")

    sha256_hash = archive_email_file(str(email), TEST_MESSAGE_ID)
    archive_path = get_archive_path_by_hash(sha256_hash)
    try:
        assert os.path.exists(archive_path)

        # an email already in the archive is left as it is
        with open(archive_path, "wb") as fp:
            fp.write(b"already archived")

        assert archive_email_file(str(email), TEST_MESSAGE_ID) == sha256_hash
        with open(archive_path, "rb") as fp:
            assert fp.read() == b"already archived"
    finally:
        os.remove(archive_path)

    # should error on missing file
    with pytest.raises(IOError):
        archive_email_file("unknown", TEST_MESSAGE_ID)

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

    # the archive row is de-duplicated on (server_id, hash, insert_date), so the insert_date we pass in
    # has to be the one that gets written -- not whatever the server clock said at insert time, which
    # made this depend on both calls landing in the same wall clock second
    assert result_1.insert_date.microsecond == 0

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*), MIN(insert_date) FROM archive")
        count, stored_insert_date = cursor.fetchone()

    assert count == 1
    assert stored_insert_date == result_1.insert_date.replace(tzinfo=None)

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


@pytest.mark.unit
def test_the_archive_dir_comes_from_the_email_archive_section(monkeypatch):
    monkeypatch.setattr(get_config().email_archive, "archive_dir", "archive/elsewhere")
    assert get_email_archive_dir() == os.path.join(get_data_dir(), "archive/elsewhere")


@pytest.mark.unit
def test_the_archive_dir_on_the_archiver_module_fails_instead_of_being_ignored():
    data = copy.deepcopy(get_config().raw._data)
    data["analysis_module_email_archiver"]["archive_dir"] = "archive/email"
    with pytest.raises(ValidationError, match="email_archive.archive_dir"):
        ACEConfig.model_validate(data)

@pytest.mark.integration
def test_archive_email_runs_again_from_the_start_after_a_deadlock(tmpdir, monkeypatch):
    email = tmpdir / "email"
    email.write_binary(b"test")

    # the recipient's history row is the deadlock victim, after the archive and index rows were written
    failed = inject_deadlock(monkeypatch, "INSERT INTO email_history")
    result = archive_email(str(email), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())

    assert len(failed) == 1
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM archive WHERE archive_id = %s", (result.archive_id,))
        assert cursor.fetchone()[0] == 1

    assert get_archived_email_path(TEST_MESSAGE_ID) == result.archive_path
    assert get_recipients_by_message_id(TEST_MESSAGE_ID) == [TEST_RECIPIENT]
