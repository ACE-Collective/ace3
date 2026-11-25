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
    ArchivedCopy,
    archive_email,
    find_archived_email,
    get_email_archive_pool,
    query_archive_hashes,
    query_archived_copies,
)
from saq.util.time import local_time
from tests.saq.helpers import inject_deadlock

TEST_MESSAGE_ID = "<test-message-id>"
TEST_EMAIL = b"Subject: test\r\n\r\ntest"


def _read(digest: str) -> bytes:
    with get_email_archive_pool().open(digest) as fp:
        return fp.read()


def _write(tmpdir, content: bytes, name: str = "email") -> str:
    path = tmpdir / name
    path.write_binary(content)
    return str(path)


def _rows() -> list[tuple]:
    """Every archived_messages row as (message_id_hash hex, digest hex, insert_date)."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT LOWER(HEX(message_id_hash)), LOWER(HEX(digest)), insert_date FROM archived_messages")
        return list(cursor.fetchall())


@pytest.fixture
def archived_email(tmpdir):
    return archive_email(_write(tmpdir, TEST_EMAIL), TEST_MESSAGE_ID, local_time())


@pytest.mark.integration
def test_archive_email_stores_the_email_in_the_pool_and_one_row(archived_email):
    assert archived_email == hashlib.sha256(TEST_EMAIL).hexdigest()

    pool = get_email_archive_pool()
    assert pool.name == "email_archive"
    stat = pool.stat(archived_email)
    # encrypted, and the digest is of the email itself, not of what is stored
    assert stat.key_id is not None and stat.size == len(TEST_EMAIL)

    [(message_id_hash, digest, _)] = _rows()
    assert message_id_hash == hashlib.sha256(TEST_MESSAGE_ID.encode()).hexdigest()
    assert digest == archived_email

    assert find_archived_email(TEST_MESSAGE_ID) == archived_email
    assert _read(archived_email) == TEST_EMAIL


@pytest.mark.integration
def test_an_unknown_message_id_is_not_archived():
    assert find_archived_email("<unknown>") is None


@pytest.mark.integration
def test_the_message_id_is_normalized(tmpdir):
    digest = archive_email(_write(tmpdir, TEST_EMAIL), "test-message-id", local_time())
    assert find_archived_email(" <test-message-id> ") == digest


@pytest.mark.integration
def test_the_newest_email_the_pool_still_has_is_found(tmpdir, caplog):
    # one Message-ID, two different emails: the newest first, but only while its bytes are there
    now = local_time()
    older = archive_email(_write(tmpdir, b"older copy", "older"), TEST_MESSAGE_ID, now - timedelta(minutes=5))
    newer = archive_email(_write(tmpdir, b"newer copy", "newer"), TEST_MESSAGE_ID, now)

    assert query_archive_hashes(TEST_MESSAGE_ID) == [newer, older]
    assert find_archived_email(TEST_MESSAGE_ID) == newer

    pool = get_email_archive_pool()
    pool.purge(newer, reason="test", actor="tester")
    assert find_archived_email(TEST_MESSAGE_ID) == older

    # every email of the Message-ID has expired: its rows outlive it, and it is no longer archived
    pool.purge(older, reason="test", actor="tester")
    with caplog.at_level(logging.INFO):
        assert find_archived_email(TEST_MESSAGE_ID) is None

    assert any("has expired from the archive" in r.getMessage() and getattr(r, "message_id", None) == TEST_MESSAGE_ID
               for r in caplog.records)


@pytest.mark.integration
def test_query_archived_copies_of_many_message_ids(tmpdir):
    now = local_time().replace(microsecond=0)
    earlier, later = now - timedelta(minutes=10), now - timedelta(minutes=5)
    older = archive_email(_write(tmpdir, b"older copy", "older"), "<a@example.com>", earlier)
    newer = archive_email(_write(tmpdir, b"newer copy", "newer"), "<a@example.com>", later)
    # archived again later: one copy, at its newest time
    archive_email(_write(tmpdir, b"older copy", "older again"), "<a@example.com>", now)
    other = archive_email(_write(tmpdir, b"other email", "other"), "<b@example.com>", earlier)

    copies = query_archived_copies(["a@example.com", " <b@example.com> ", "<unknown@example.com>"])

    naive = lambda when: when.replace(tzinfo=None)  # noqa: E731
    assert copies == {
        "<a@example.com>": [ArchivedCopy(older, naive(now)), ArchivedCopy(newer, naive(later))],
        "<b@example.com>": [ArchivedCopy(other, naive(earlier))],
    }
    assert query_archived_copies([]) == {}


@pytest.mark.integration
def test_query_archived_copies_spans_batches(tmpdir, monkeypatch):
    monkeypatch.setattr("saq.email_archive.archive._LOOKUP_BATCH", 2)
    digests = {f"<{n}@example.com>": archive_email(_write(tmpdir, f"email {n}".encode(), str(n)), f"<{n}@example.com>", local_time())
               for n in range(5)}

    copies = query_archived_copies(list(digests))

    assert {message_id: [copy.digest for copy in found] for message_id, found in copies.items()} == {
        message_id: [digest] for message_id, digest in digests.items()}


@pytest.mark.integration
def test_archiving_an_expired_email_again_stores_it_again(tmpdir, archived_email):
    pool = get_email_archive_pool()
    pool.purge(archived_email, reason="test", actor="tester")
    assert find_archived_email(TEST_MESSAGE_ID) is None

    archive_email(_write(tmpdir, TEST_EMAIL, "again"), TEST_MESSAGE_ID, local_time())
    assert find_archived_email(TEST_MESSAGE_ID) == archived_email


@pytest.mark.integration
def test_archive_email_fails_for_a_missing_file():
    with pytest.raises(FileNotFoundError):
        archive_email("unknown", TEST_MESSAGE_ID, local_time())

    # nothing was indexed for an email the pool does not have
    assert _rows() == []


@pytest.mark.integration
def test_archiving_the_same_email_at_the_same_time_is_one_row(tmpdir):
    email = _write(tmpdir, TEST_EMAIL)

    # the column has no fractional seconds and MySQL rounds, so without the truncation these two
    # would be written as different seconds whenever the microseconds straddle .5
    insert_date = local_time().replace(microsecond=600000)
    assert archive_email(email, TEST_MESSAGE_ID, insert_date) == archive_email(email, TEST_MESSAGE_ID, insert_date.replace(microsecond=100000))

    [(_, _, stored_insert_date)] = _rows()
    assert stored_insert_date == insert_date.replace(microsecond=0, tzinfo=None)

    # a later archive of the same email is another row, and the lookup still names it once
    archive_email(email, TEST_MESSAGE_ID, insert_date + timedelta(minutes=1))
    assert len(_rows()) == 2
    assert query_archive_hashes(TEST_MESSAGE_ID) == [hashlib.sha256(TEST_EMAIL).hexdigest()]


@pytest.mark.integration
def test_archive_email_runs_the_insert_again_after_a_deadlock(tmpdir, monkeypatch):
    failed = inject_deadlock(monkeypatch, "INSERT IGNORE INTO archived_messages")
    digest = archive_email(_write(tmpdir, TEST_EMAIL), TEST_MESSAGE_ID, local_time())

    assert len(failed) == 1
    assert len(_rows()) == 1
    assert find_archived_email(TEST_MESSAGE_ID) == digest


@pytest.mark.unit
def test_the_archive_dir_on_the_archiver_module_fails_instead_of_being_ignored():
    data = copy.deepcopy(get_config().raw._data)
    data["analysis_module_email_archiver"]["archive_dir"] = "archive/email"
    with pytest.raises(ValidationError, match="email_archive.archive_dir"):
        ACEConfig.model_validate(data)


@pytest.mark.unit
def test_a_remote_target_fails_instead_of_falling_back_to_local():
    data = copy.deepcopy(get_config().raw._data)
    data["email_archive"]["target"] = "remote"
    with pytest.raises(ValidationError, match="email_archive.target: 'remote' was removed"):
        ACEConfig.model_validate(data)

    # the old local setting changes nothing
    data["email_archive"]["target"] = "local"
    ACEConfig.model_validate(data)


@pytest.mark.unit
def test_an_archive_retention_shorter_than_the_pools_ttl_fails_to_load():
    # rows dropped before their emails would lose emails the pool still has
    data = copy.deepcopy(get_config().raw._data)
    data["email_archive"]["partition_retention_days"] = 29
    with pytest.raises(ValidationError, match=r"partition_retention_days \(29\) must be at least the ttl_days of cas pool email_archive \(30\)"):
        ACEConfig.model_validate(data)

    data["email_archive"]["partition_retention_days"] = 30
    ACEConfig.model_validate(data)

    # a site that keeps the archive in a pool without a ttl has no floor to keep
    data["email_archive"]["partition_retention_days"] = 7
    data["cas"]["pools"]["email_archive"]["retention"] = "held"
    del data["cas"]["pools"]["email_archive"]["ttl_days"]
    data["cas"]["pools"]["email_archive"]["index_database"] = "ace"
    ACEConfig.model_validate(data)


@pytest.mark.unit
def test_the_removed_email_archive_settings_are_ignored():
    # a site overlay may still set them; they do nothing now
    data = copy.deepcopy(get_config().raw._data)
    data["email_archive"]["primary"] = "email_archive"
    data["email_archive"]["email_history_retention_days"] = 30
    ACEConfig.model_validate(data)
