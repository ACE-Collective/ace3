"""`ace email-archive migrate`: fills archived_messages from the legacy archive rows, then moves the
archive's files from before the CAS into the pool (docs/EMAIL_ARCHIVE.md, "Migrating from the old
archive")."""

import gzip
import logging
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.orm import Session

from saq.cas import DigestMismatch
from saq.configuration.config import get_config
from saq.constants import DB_EMAIL_ARCHIVE
from saq.crypto import decrypt
from saq.database import get_db_connection
from saq.database.model import ArchivedMessage, EmailArchive, EmailArchiveIndex
from saq.database.private_session import private_transaction, run_private_transaction
from saq.email_archive.archive import get_email_archive_pool
from saq.environment import get_data_dir, get_temp_dir

LEGACY_SUFFIX = ".gz.e"
_LEGACY_NAME = re.compile(r"^([0-9a-f]{64})\.gz\.e$")

# a progress line every this many files
_PROGRESS_EVERY = 1000

# legacy archive_ids copied per backfill transaction, and a progress line every this many of them
_BACKFILL_BATCH = 5000
_BACKFILL_PROGRESS_EVERY = 100


@dataclass
class MigrationStats:
    dry_run: bool
    scanned: int = 0
    migrated: int = 0               # stored in the pool by this run
    already_present: int = 0        # the pool already had it (an earlier run, or archived again since)
    unreferenced: int = 0           # no archive row: unreachable, left for the archive cron task
    failed: int = 0                 # could not be decrypted, decompressed or stored; the file is kept
    unrecognized: int = 0           # a file the old archive would not have written; left alone
    bytes_migrated: int = 0         # plaintext bytes stored
    sources_removed: int = 0
    stopped_at_limit: bool = False
    rows_backfilled: int = 0        # archived_messages rows copied from the legacy rows (a dry run: legacy rows there are)


@dataclass(frozen=True)
class LegacyFile:
    path: str
    hostname: str
    sha256: str


def get_legacy_archive_dir() -> str:
    return os.path.join(get_data_dir(), get_config().email_archive.archive_dir)


def iter_legacy_files(archive_dir: str, stats: MigrationStats) -> Iterator[LegacyFile]:
    """Every <hostname>/<xx>/<sha256>.gz.e under archive_dir, in name order. A node normally has only
    its own hostname's directory, but one left by an earlier hostname (a renamed container) is
    migrated as well."""
    if not os.path.isdir(archive_dir):
        return

    for hostname in sorted(os.listdir(archive_dir)):
        host_dir = os.path.join(archive_dir, hostname)
        if not os.path.isdir(host_dir):
            continue

        for prefix in sorted(os.listdir(host_dir)):
            prefix_dir = os.path.join(host_dir, prefix)
            if not os.path.isdir(prefix_dir):
                continue

            for name in sorted(os.listdir(prefix_dir)):
                path = os.path.join(prefix_dir, name)
                match = _LEGACY_NAME.match(name)
                if match is None or not match.group(1).startswith(prefix):
                    logging.warning("email archive migration: skipping %s, which the old archive would not have written", path)
                    stats.unrecognized += 1
                    continue

                yield LegacyFile(path=path, hostname=hostname, sha256=match.group(1))


def _server_ids() -> dict[str, int]:
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT hostname, server_id FROM archive_server")
        return {hostname.lower(): server_id for hostname, server_id in cursor.fetchall()}


def _is_referenced(server_id: Optional[int], sha256: str) -> bool:
    """True when an archive row still names this email (by the server that archived it, which is
    what makes this a lookup on idx_server_id rather than a scan)."""
    if server_id is None:
        return False

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM archive WHERE server_id = %s AND hash = UNHEX(%s) LIMIT 1", (server_id, sha256))
        return cursor.fetchone() is not None


def backfill_archived_messages(stats: MigrationStats, batch_size: int = _BACKFILL_BATCH) -> None:
    """Copies the Message-ID of every legacy archive row into archived_messages, keeping its
    insert_date so it ages out when the legacy row would have. One short transaction per range of
    archive_ids, so it never holds a lock for long, and INSERT IGNORE makes a rerun (on another
    node, or after a stop) copy nothing twice. Nothing writes the legacy tables any more, so the
    shared locks INSERT ... SELECT takes on them block no one."""
    with private_transaction(DB_EMAIL_ARCHIVE) as session:
        if stats.dry_run:
            stats.rows_backfilled = session.execute(
                select(func.count()).select_from(EmailArchiveIndex).where(EmailArchiveIndex.field == "message_id")).scalar()
            return

        # archive_id never resets, and partition maintenance has dropped every row older than the
        # retention, so the ids below the oldest kept row are all empty batches
        first, last = session.execute(select(func.min(EmailArchive.archive_id), func.max(EmailArchive.archive_id))).one()

    # with no legacy rows there is nothing to copy (and min/max are NULL)
    for batch, low in enumerate(range(first - 1, last, batch_size) if first is not None else (), start=1):
        stats.rows_backfilled += run_private_transaction(
            _copy_message_ids, low, low + batch_size, database=DB_EMAIL_ARCHIVE,
            description="email archive migration: copying message-ids", extra={"archive_id": low})
        if batch % _BACKFILL_PROGRESS_EVERY == 0:
            logging.info("email archive migration: %s message-id rows copied, up to archive_id %s of %s",
                         stats.rows_backfilled, min(low + batch_size, last), last,
                         extra={"rows_backfilled": stats.rows_backfilled, "archive_id": min(low + batch_size, last)})

    logging.info("email archive migration: copied %s message-id rows into archived_messages", stats.rows_backfilled,
                 extra={"rows_backfilled": stats.rows_backfilled})


def _copy_message_ids(session: Session, low: int, high: int) -> int:
    """One backfill batch: the legacy rows with low < archive_id <= high."""
    legacy = (select(EmailArchiveIndex.hash, EmailArchive.hash, EmailArchive.insert_date)
              .join(EmailArchiveIndex, EmailArchiveIndex.archive_id == EmailArchive.archive_id)
              .where(EmailArchive.archive_id > low, EmailArchive.archive_id <= high,
                     EmailArchiveIndex.field == "message_id"))
    return session.execute(mysql_insert(ArchivedMessage).prefix_with("IGNORE").from_select(
        ["message_id_hash", "digest", "insert_date"], legacy)).rowcount


def _store(pool, legacy: LegacyFile) -> int:
    """Decrypts and decompresses legacy into the pool. Returns the plaintext size."""
    fd, compressed_path = tempfile.mkstemp(dir=get_temp_dir(), prefix="email-archive-migrate-", suffix=".gz")
    os.close(fd)
    try:
        # decrypt() verifies the tag before it puts anything at compressed_path
        decrypt(legacy.path, compressed_path)
        with gzip.open(compressed_path, "rb") as fp:
            # the digest check is what proves the file holds the email its name says it does
            pool.put(fp, digest=legacy.sha256)

        return pool.stat(legacy.sha256).size
    finally:
        try:
            os.unlink(compressed_path)
        except FileNotFoundError:
            # already gone (the temp-files cron task sweeps the temp directory): nothing left to clean up
            pass


def _remove_source(legacy: LegacyFile, stats: MigrationStats, keep_source: bool) -> None:
    if keep_source or stats.dry_run:
        return

    os.unlink(legacy.path)
    stats.sources_removed += 1


def migrate_legacy_archive(archive_dir: Optional[str] = None, *, dry_run: bool = False, keep_source: bool = False,
                           limit: Optional[int] = None) -> MigrationStats:
    """Fills archived_messages from the legacy rows, then moves every reachable email in the old
    archive directory into the pool (see the module docstring). limit stops after that many files
    have been stored. Safe to run again: a row already copied and a file the pool already has are
    only skipped (the file is removed)."""
    archive_dir = archive_dir or get_legacy_archive_dir()
    stats = MigrationStats(dry_run=dry_run)
    pool = get_email_archive_pool()
    server_ids = _server_ids()
    logging.info("email archive migration: from %s into cas pool %s%s", archive_dir, pool.name, " (dry run)" if dry_run else "",
                 extra={"path": archive_dir, "cas_pool": pool.name, "dry_run": dry_run})

    # first, so a Message-ID resolves as soon as its file is in the pool
    backfill_archived_messages(stats)

    for legacy in iter_legacy_files(archive_dir, stats):
        if limit is not None and stats.migrated >= limit:
            stats.stopped_at_limit = True
            break

        stats.scanned += 1
        if stats.scanned % _PROGRESS_EVERY == 0:
            logging.info("email archive migration: %s files scanned, %s migrated, %s already present, %s unreferenced, "
                         "%s failed", stats.scanned, stats.migrated, stats.already_present, stats.unreferenced,
                         stats.failed)

        extra = {"path": legacy.path, "sha256": legacy.sha256, "cas_pool": pool.name}
        try:
            if not _is_referenced(server_ids.get(legacy.hostname.lower()), legacy.sha256):
                stats.unreferenced += 1
                continue

            if pool.exists(legacy.sha256):
                stats.already_present += 1
                _remove_source(legacy, stats, keep_source)
                continue

            if dry_run:
                stats.migrated += 1
                continue

            stats.bytes_migrated += _store(pool, legacy)
            stats.migrated += 1
            _remove_source(legacy, stats, keep_source)
        except DigestMismatch as e:
            logging.error("email archive migration: %s does not hold the email its name says (%s); kept",
                          legacy.path, e, exc_info=True, extra=extra)
            stats.failed += 1
        except Exception as e:
            logging.exception("email archive migration: unable to migrate %s: %s", legacy.path, e, extra=extra)
            stats.failed += 1

    if not dry_run and not keep_source:
        _remove_empty_directories(archive_dir)

    logging.info("email archive migration finished", extra={
        "path": archive_dir, "cas_pool": pool.name, "dry_run": dry_run, "scanned": stats.scanned,
        "migrated": stats.migrated, "already_present": stats.already_present, "unreferenced": stats.unreferenced,
        "failed": stats.failed, "unrecognized": stats.unrecognized, "bytes_migrated": stats.bytes_migrated,
        "sources_removed": stats.sources_removed, "rows_backfilled": stats.rows_backfilled})
    return stats


def _remove_empty_directories(archive_dir: str) -> None:
    """The <hostname>/<xx> directories the migration emptied. archive_dir itself is kept."""
    if not os.path.isdir(archive_dir):
        return

    # bottom up, so a <hostname> directory is tried after its <xx> directories
    for dirpath, _, _ in os.walk(archive_dir, topdown=False):
        if dirpath == archive_dir:
            continue

        try:
            os.rmdir(dirpath)
        except OSError:
            # not empty: it still holds files the migration kept
            pass
