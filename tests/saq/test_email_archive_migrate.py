"""`ace email-archive migrate`: copying the legacy Message-ID rows into archived_messages and moving
the archive's files from before the CAS into the pool."""

import gzip
import hashlib
import logging
import os
import socket
from argparse import Namespace
from datetime import datetime, timedelta
from typing import Optional

import pytest

from saq.cli.commands.email_archive import cli_migrate
from saq.constants import DB_EMAIL_ARCHIVE
from saq.crypto import FORMAT_V0, encrypt
from saq.database import get_db_connection
from saq.email import normalize_message_id
from saq.email_archive import find_archived_email, get_email_archive_pool, query_archive_hashes
from saq.email_archive import migrate
from saq.email_archive.migrate import (
    MigrationStats,
    backfill_archived_messages,
    get_legacy_archive_dir,
    migrate_legacy_archive,
)
from saq.util.time import local_time
from tests.saq.helpers import inject_deadlock

pytestmark = pytest.mark.integration


@pytest.fixture
def legacy_dir(tmp_path):
    return str(tmp_path / "archive" / "email")


def write_legacy(legacy_dir: str, content: bytes, hostname: str = None, name_hash: str = None) -> str:
    """A file as the old archive wrote it: <hostname>/<sha[:2]>/<sha>.gz.e, gzip then encrypted (v0)."""
    hostname = hostname or socket.gethostname().lower()
    sha256 = name_hash or hashlib.sha256(content).hexdigest()
    target = os.path.join(legacy_dir, hostname, sha256[:2], f"{sha256}.gz.e")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    compressed = target[:-2]
    with gzip.open(compressed, "wb") as fp:
        fp.write(content)

    encrypt(compressed, target, format_version=FORMAT_V0)
    os.remove(compressed)
    return target


def index_legacy(sha256: str, message_id: str, hostname: str = None, insert_date: Optional[datetime] = None,
                 urls: tuple[str, ...] = ()) -> None:
    """The rows the old archive wrote for an email: its host in archive_server, the archive row, and
    the archive_index rows of its Message-ID and of the URLs found in it."""
    hostname = hostname or socket.gethostname().lower()
    insert_date = (insert_date or local_time()).replace(microsecond=0)
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("INSERT IGNORE INTO archive_server (hostname) VALUES (%s)", (hostname,))
        cursor.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (hostname,))
        server_id = cursor.fetchone()[0]
        cursor.execute("INSERT INTO archive (server_id, hash, insert_date) VALUES (%s, UNHEX(%s), %s)",
                       (server_id, sha256, insert_date))
        archive_id = cursor.lastrowid
        for field, value in [("message_id", normalize_message_id(message_id))] + [("url", url) for url in urls]:
            cursor.execute("INSERT INTO archive_index (field, hash, archive_id, insert_date) "
                           "VALUES (%s, UNHEX(SHA2(%s, 256)), %s, %s)", (field, value, archive_id, insert_date))
        db.commit()


def archived_messages() -> list[tuple]:
    """Every archived_messages row as (message_id_hash hex, digest hex, insert_date), sorted."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT LOWER(HEX(message_id_hash)), LOWER(HEX(digest)), insert_date FROM archived_messages "
                       "ORDER BY insert_date")
        return list(cursor.fetchall())


def _message_id_hash(message_id: str) -> str:
    return hashlib.sha256(normalize_message_id(message_id).encode()).hexdigest()


def legacy_email(legacy_dir: str, content: bytes, message_id: str, hostname: str = None) -> tuple[str, str]:
    path = write_legacy(legacy_dir, content, hostname)
    sha256 = hashlib.sha256(content).hexdigest()
    index_legacy(sha256, message_id, hostname)
    return path, sha256


def test_the_backfill_copies_each_message_id_with_its_insert_date(legacy_dir):
    # three legacy emails, one batch each; the URL rows stay behind
    then = local_time().replace(microsecond=0) - timedelta(days=3)
    expected = []
    for n in range(3):
        sha256 = hashlib.sha256(f"legacy {n}".encode()).hexdigest()
        index_legacy(sha256, f"<backfill-{n}@local>", insert_date=then + timedelta(hours=n), urls=(f"https://example.com/{n}",))
        expected.append((_message_id_hash(f"<backfill-{n}@local>"), sha256, (then + timedelta(hours=n)).replace(tzinfo=None)))

    stats = MigrationStats(dry_run=False)
    backfill_archived_messages(stats, batch_size=1)
    assert stats.rows_backfilled == 3
    assert archived_messages() == expected

    # a second run (another node, or after a stop) copies nothing twice
    again = MigrationStats(dry_run=False)
    backfill_archived_messages(again, batch_size=1)
    assert again.rows_backfilled == 0
    assert archived_messages() == expected


def test_the_backfill_runs_a_batch_again_after_a_deadlock(monkeypatch):
    for n in range(2):
        index_legacy(hashlib.sha256(f"deadlock {n}".encode()).hexdigest(), f"<deadlock-{n}@local>")

    # one batch holds both rows (the reset keeps archive's AUTO_INCREMENT, so their ids depend on
    # the tests that ran before, but stay far below the batch size), and its first attempt is the victim
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT MAX(archive_id) FROM archive")
        assert cursor.fetchone()[0] < 5000

    failed = inject_deadlock(monkeypatch, "INSERT IGNORE INTO archived_messages")
    stats = MigrationStats(dry_run=False)
    backfill_archived_messages(stats, batch_size=5000)

    assert len(failed) == 1
    assert stats.rows_backfilled == 2
    assert len(archived_messages()) == 2
    assert all(query_archive_hashes(f"<deadlock-{n}@local>") for n in range(2))


def test_the_backfill_starts_at_the_oldest_legacy_row(monkeypatch):
    # rows partition maintenance already dropped leave the ids below the oldest kept row empty
    for n in range(3):
        index_legacy(hashlib.sha256(f"dropped {n}".encode()).hexdigest(), f"<dropped-{n}@local>")

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM archive")
        db.commit()

    for n in range(2):
        index_legacy(hashlib.sha256(f"kept {n}".encode()).hexdigest(), f"<kept-{n}@local>")

    batches = []
    copy = migrate._copy_message_ids
    monkeypatch.setattr(migrate, "_copy_message_ids", lambda session, low, high: batches.append(low) or copy(session, low, high))
    stats = MigrationStats(dry_run=False)
    backfill_archived_messages(stats, batch_size=1)

    assert stats.rows_backfilled == 2
    # one batch per kept row, none for the dropped ones
    assert len(batches) == 2


def test_the_backfill_logs_its_progress(monkeypatch, caplog):
    for n in range(3):
        index_legacy(hashlib.sha256(f"progress {n}".encode()).hexdigest(), f"<progress-{n}@local>")

    monkeypatch.setattr(migrate, "_BACKFILL_PROGRESS_EVERY", 2)
    with caplog.at_level(logging.INFO):
        backfill_archived_messages(MigrationStats(dry_run=False), batch_size=1)

    # three batches: a progress line after the second, then the total
    progress = [r for r in caplog.records if "message-id rows copied, up to archive_id" in r.getMessage()]
    assert [r.rows_backfilled for r in progress] == [2]


def test_a_dry_run_backfill_counts_and_copies_nothing():
    index_legacy(hashlib.sha256(b"dry").hexdigest(), "<dry@local>", urls=("https://example.com/dry",))
    stats = MigrationStats(dry_run=True)
    backfill_archived_messages(stats)
    assert stats.rows_backfilled == 1
    assert archived_messages() == []


def test_with_no_legacy_rows_the_backfill_copies_nothing():
    stats = MigrationStats(dry_run=False)
    backfill_archived_messages(stats)
    assert stats.rows_backfilled == 0


def test_migrate_moves_a_referenced_email_into_the_pool(legacy_dir):
    path, sha256 = legacy_email(legacy_dir, b"Subject: migrated\r\n\r\nbody", "<m1@local>")
    assert find_archived_email("<m1@local>") is None

    stats = migrate_legacy_archive(legacy_dir)

    assert (stats.scanned, stats.migrated, stats.failed, stats.sources_removed) == (1, 1, 0, 1)
    assert stats.bytes_migrated == len(b"Subject: migrated\r\n\r\nbody")
    assert find_archived_email("<m1@local>") == sha256
    with get_email_archive_pool().open(sha256) as fp:
        assert fp.read() == b"Subject: migrated\r\n\r\nbody"
    assert not os.path.exists(path)
    # the emptied <hostname>/<xx> directories go; the archive directory itself stays
    assert os.listdir(legacy_dir) == []


def test_migrate_reads_every_hostname_directory(legacy_dir):
    # a directory left by an earlier hostname (a renamed container) has its own archive_server row
    _, sha256 = legacy_email(legacy_dir, b"from the old hostname", "<old@local>", hostname="old-node")
    stats = migrate_legacy_archive(legacy_dir)
    assert stats.migrated == 1
    assert find_archived_email("<old@local>") == sha256


def test_an_unreferenced_file_is_left_for_the_cron_task(legacy_dir):
    path = write_legacy(legacy_dir, b"no archive row any more")
    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.scanned, stats.unreferenced, stats.migrated, stats.sources_removed) == (1, 1, 0, 0)
    assert os.path.exists(path)
    assert not get_email_archive_pool().exists(hashlib.sha256(b"no archive row any more").hexdigest())


def test_a_host_directory_with_no_archive_server_is_unreferenced(legacy_dir):
    # nothing was ever archived under this hostname, so no row can name its files
    path = write_legacy(legacy_dir, b"unknown host", hostname="never-registered")
    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.unreferenced, stats.migrated) == (1, 0)
    assert os.path.exists(path)


def test_a_file_the_pool_already_has_is_only_removed(legacy_dir):
    path, sha256 = legacy_email(legacy_dir, b"already there", "<m2@local>")
    get_email_archive_pool().put(b"already there")

    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.already_present, stats.migrated, stats.sources_removed) == (1, 0, 1)
    assert not os.path.exists(path)


def test_dry_run_changes_nothing(legacy_dir):
    path, sha256 = legacy_email(legacy_dir, b"dry run", "<m3@local>")
    stats = migrate_legacy_archive(legacy_dir, dry_run=True)
    assert (stats.dry_run, stats.migrated, stats.sources_removed, stats.rows_backfilled) == (True, 1, 0, 1)
    assert os.path.exists(path)
    assert not get_email_archive_pool().exists(sha256)
    assert archived_messages() == []


def test_keep_source(legacy_dir):
    path, sha256 = legacy_email(legacy_dir, b"keep me", "<m4@local>")
    stats = migrate_legacy_archive(legacy_dir, keep_source=True)
    assert (stats.migrated, stats.sources_removed) == (1, 0)
    assert os.path.exists(path)
    assert get_email_archive_pool().exists(sha256)


def test_limit_stops_and_a_second_run_continues(legacy_dir):
    for n in range(3):
        legacy_email(legacy_dir, f"email {n}".encode(), f"<limit-{n}@local>")

    first = migrate_legacy_archive(legacy_dir, limit=2)
    assert (first.migrated, first.stopped_at_limit) == (2, True)

    second = migrate_legacy_archive(legacy_dir)
    assert (second.migrated, second.stopped_at_limit) == (1, False)
    assert all(find_archived_email(f"<limit-{n}@local>") for n in range(3))


def test_a_file_whose_content_is_not_its_name_is_kept(legacy_dir, caplog):
    # the name says one email, the bytes are another: the pool's digest check refuses it
    claimed = hashlib.sha256(b"what the name says").hexdigest()
    path = write_legacy(legacy_dir, b"what the file holds", name_hash=claimed)
    index_legacy(claimed, "<m5@local>")

    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.failed, stats.migrated, stats.sources_removed) == (1, 0, 0)
    assert os.path.exists(path)
    assert not get_email_archive_pool().exists(claimed)
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR and "does not hold the email" in r.getMessage()]
    assert (record.path, record.sha256) == (path, claimed)


def test_a_file_that_does_not_decrypt_is_kept_and_logged(legacy_dir, caplog):
    path, sha256 = legacy_email(legacy_dir, b"will be corrupted", "<m6@local>")
    with open(path, "r+b") as fp:
        fp.seek(-1, os.SEEK_END)
        last = fp.read(1)
        fp.seek(-1, os.SEEK_END)
        fp.write(bytes([last[0] ^ 0xFF]))

    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.failed, stats.migrated) == (1, 0)
    assert os.path.exists(path)
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR and "unable to migrate" in r.getMessage()]
    assert record.exc_info is not None and record.sha256 == sha256


def test_files_the_old_archive_would_not_write_are_left_alone(legacy_dir):
    stray = os.path.join(legacy_dir, "somehost", "ab", "notes.txt")
    os.makedirs(os.path.dirname(stray))
    open(stray, "w").write("not an email")

    stats = migrate_legacy_archive(legacy_dir)
    assert (stats.unrecognized, stats.scanned) == (1, 0)
    assert os.path.exists(stray)


def test_a_missing_archive_directory_is_nothing_to_do(tmp_path):
    stats = migrate_legacy_archive(str(tmp_path / "nothing here"))
    assert stats.scanned == 0


def test_the_default_directory_is_the_configured_archive_dir():
    assert get_legacy_archive_dir().endswith(os.path.join("archive", "email"))


def _cli_args(legacy_dir, **kwargs):
    return Namespace(archive_dir=legacy_dir, dry_run=False, keep_source=False, limit=None, **kwargs)


def test_cli_migrate(legacy_dir, capsys):
    legacy_email(legacy_dir, b"through the cli", "<cli@local>")
    assert cli_migrate(_cli_args(legacy_dir)) == 0
    out = capsys.readouterr().out
    assert "1 message-id row(s) copied into archived_messages" in out
    assert "scanned 1 file(s), migrated 1" in out and "1 old file(s) removed" in out


def test_cli_migrate_says_when_it_stopped_at_the_limit(legacy_dir, capsys):
    for n in range(2):
        legacy_email(legacy_dir, f"cli {n}".encode(), f"<cli-limit-{n}@local>")

    args = _cli_args(legacy_dir)
    args.limit = 1
    assert cli_migrate(args) == 0
    assert "stopped after 1 file(s) (--limit); run again to continue" in capsys.readouterr().out


def test_cli_migrate_exits_2_when_a_file_failed(legacy_dir, capsys):
    claimed = hashlib.sha256(b"claimed").hexdigest()
    write_legacy(legacy_dir, b"actual", name_hash=claimed)
    index_legacy(claimed, "<bad@local>")
    assert cli_migrate(_cli_args(legacy_dir)) == 2
    assert "1 failed" in capsys.readouterr().out


def test_cli_migrate_needs_the_encryption_key(legacy_dir, monkeypatch, capsys):
    monkeypatch.setattr("saq.crypto.is_encryption_initialized", lambda: False)
    assert cli_migrate(_cli_args(legacy_dir)) == 1
    assert "encryption key is not available" in capsys.readouterr().out
