import copy
import hashlib
import logging
from datetime import timedelta

import pytest
from pydantic import ValidationError

from saq.configuration.config import get_config
from saq.configuration.schema import ACEConfig
from saq.constants import DB_EMAIL_ARCHIVE
from saq.database import get_db_connection
from saq.email_archive import (
    archive_email,
    email_is_archived,
    find_archived_email,
    get_email_archive_pool,
    get_recipients_by_message_id,
    index_email_history,
    iter_archived_email,
    query_archive_hashes,
)
from saq.util.time import local_time
from tests.saq.helpers import inject_deadlock

TEST_MESSAGE_ID = "<test-message-id>"
TEST_RECIPIENT = "test@local"
TEST_RECIPIENT_2 = "test2@local"
TEST_EMAIL = b"Subject: test\r\n\r\ntest"


def _write(tmpdir, content: bytes, name: str = "email") -> str:
    path = tmpdir / name
    path.write_binary(content)
    return str(path)


@pytest.fixture
def archived_email(tmpdir):
    return archive_email(_write(tmpdir, TEST_EMAIL), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())


@pytest.mark.integration
def test_archive_email_stores_the_email_in_the_pool(archived_email):
    assert archived_email.hash == hashlib.sha256(TEST_EMAIL).hexdigest()

    pool = get_email_archive_pool()
    assert pool.name == "email_archive"
    stat = pool.stat(archived_email.hash)
    # encrypted, and the digest is of the email itself, not of what is stored
    assert stat.key_id is not None and stat.size == len(TEST_EMAIL)

    assert find_archived_email(TEST_MESSAGE_ID) == archived_email.hash
    assert b"".join(iter_archived_email(archived_email.hash)) == TEST_EMAIL


@pytest.mark.integration
def test_iter_archived_email_in_chunks(archived_email):
    assert list(iter_archived_email(archived_email.hash, chunk_size=8)) == [
        TEST_EMAIL[i:i + 8] for i in range(0, len(TEST_EMAIL), 8)]


@pytest.mark.integration
def test_an_unknown_message_id_is_not_archived():
    assert find_archived_email("<unknown>") is None
    assert not email_is_archived("<unknown>")


@pytest.mark.integration
def test_the_message_id_is_normalized(archived_email):
    assert find_archived_email(" <test-message-id> ") == archived_email.hash


@pytest.mark.integration
def test_the_newest_email_the_pool_still_has_is_found(tmpdir, caplog):
    # one Message-ID, two different emails: the newest first, but only while its bytes are there
    now = local_time()
    older = archive_email(_write(tmpdir, b"older copy", "older"), TEST_MESSAGE_ID, [TEST_RECIPIENT], now - timedelta(minutes=5))
    newer = archive_email(_write(tmpdir, b"newer copy", "newer"), TEST_MESSAGE_ID, [TEST_RECIPIENT], now)

    assert query_archive_hashes(TEST_MESSAGE_ID) == [newer.hash, older.hash]
    assert find_archived_email(TEST_MESSAGE_ID) == newer.hash

    pool = get_email_archive_pool()
    pool.purge(newer.hash, reason="test", actor="tester")
    assert find_archived_email(TEST_MESSAGE_ID) == older.hash

    # every email of the Message-ID has expired: its rows outlive it, and it is no longer archived
    pool.purge(older.hash, reason="test", actor="tester")
    with caplog.at_level(logging.INFO):
        assert not email_is_archived(TEST_MESSAGE_ID)

    assert any("has expired from the archive" in r.getMessage() and getattr(r, "message_id", None) == TEST_MESSAGE_ID
               for r in caplog.records)


@pytest.mark.integration
def test_archiving_an_expired_email_again_stores_it_again(tmpdir, archived_email):
    pool = get_email_archive_pool()
    pool.purge(archived_email.hash, reason="test", actor="tester")
    assert not email_is_archived(TEST_MESSAGE_ID)

    archive_email(_write(tmpdir, TEST_EMAIL, "again"), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())
    assert find_archived_email(TEST_MESSAGE_ID) == archived_email.hash


@pytest.mark.integration
def test_archive_email_fails_for_a_missing_file():
    with pytest.raises(FileNotFoundError):
        archive_email("unknown", TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())

    # nothing was indexed for an email the pool does not have
    assert query_archive_hashes(TEST_MESSAGE_ID) == []


@pytest.mark.integration
def test_duplicate(tmpdir):
    email = _write(tmpdir, TEST_EMAIL)

    insert_date = local_time()
    result_1 = archive_email(email, TEST_MESSAGE_ID, [TEST_RECIPIENT], insert_date)
    result_2 = archive_email(email, TEST_MESSAGE_ID, [TEST_RECIPIENT], insert_date)
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


@pytest.mark.unit
def test_the_archive_dir_on_the_archiver_module_fails_instead_of_being_ignored():
    data = copy.deepcopy(get_config().raw._data)
    data["analysis_module_email_archiver"]["archive_dir"] = "archive/email"
    with pytest.raises(ValidationError, match="email_archive.archive_dir"):
        ACEConfig.model_validate(data)


@pytest.mark.unit
def test_an_s3_target_fails_instead_of_falling_back_to_local():
    data = copy.deepcopy(get_config().raw._data)
    data["email_archive"]["target"] = "s3"
    with pytest.raises(ValidationError, match="email_archive.target: 's3' was removed"):
        ACEConfig.model_validate(data)

    # the old local setting changes nothing
    data["email_archive"]["target"] = "local"
    ACEConfig.model_validate(data)


@pytest.mark.integration
def test_archive_email_runs_again_from_the_start_after_a_deadlock(tmpdir, monkeypatch):
    # the recipient's history row is the deadlock victim, after the archive and index rows were written
    failed = inject_deadlock(monkeypatch, "INSERT INTO email_history")
    result = archive_email(_write(tmpdir, TEST_EMAIL), TEST_MESSAGE_ID, [TEST_RECIPIENT], local_time())

    assert len(failed) == 1
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM archive WHERE archive_id = %s", (result.archive_id,))
        assert cursor.fetchone()[0] == 1

    assert find_archived_email(TEST_MESSAGE_ID) == result.hash
    assert get_recipients_by_message_id(TEST_MESSAGE_ID) == [TEST_RECIPIENT]
