"""The email archive: the bytes are in the email_archive CAS pool, and archived_messages in the email
archive database maps each Message-ID to them (docs/EMAIL_ARCHIVE.md)."""

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config
from saq.constants import DB_EMAIL_ARCHIVE
from saq.crypto import is_encryption_initialized
from saq.database import execute_with_retry, get_db_connection
from saq.email import normalize_message_id

if TYPE_CHECKING:
    from saq.cas import CASPool


def get_email_archive_pool() -> "CASPool":
    # the CAS loads the ORM models, and every process that reads an alert imports this module
    from saq.cas import get_cas

    return get_cas().pool(get_config().email_archive.pool)


def archive_email(file_path: str, message_id: str, insert_date: datetime) -> str:
    """Stores the email at file_path in the pool under message_id and returns its digest (its
    sha256). Storing an email that is already archived renews its ttl."""
    assert isinstance(file_path, str)
    assert isinstance(message_id, str) and message_id

    # the pool is encrypted: without the key the put would fail later, and less clearly
    if not is_encryption_initialized(): # pragma: nocover
        raise RuntimeError("archive_email was called but encryption is not initialized")

    # before the row, so a row never names an email the pool does not have
    digest = get_email_archive_pool().put(file_path)

    # insert_date is part of the primary key, which de-duplicates: archiving the same email under
    # the same Message-ID at the same insert_date is one row. The column has no fractional seconds
    # and MySQL rounds rather than truncates, so truncate here to write the value that was passed
    insert_date = insert_date.replace(microsecond=0)
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        execute_with_retry(db, db.cursor(),
            "INSERT IGNORE INTO archived_messages ( message_id_hash, digest, insert_date ) "
            "VALUES ( UNHEX(SHA2(%s, 256)), UNHEX(%s), %s )",
            (normalize_message_id(message_id), digest, insert_date), commit=True)

    logging.info("archived email %s as %s", message_id, digest, extra={"message_id": message_id, "sha256": digest})
    return digest


def query_archive_hashes(message_id: str) -> list[str]:
    """The sha256 of every email archived under message_id that still has a row, newest first.
    One Message-ID can name more than one email (journaled copies, a resent message)."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT LOWER(HEX(digest)) FROM archived_messages
            WHERE message_id_hash = UNHEX(SHA2(%s, 256))
            ORDER BY insert_date DESC""", (normalize_message_id(message_id),))
        return list(dict.fromkeys(row[0] for row in cursor.fetchall()))


def find_archived_email(message_id: str) -> Optional[str]:
    """The digest in the pool of the newest email archived under message_id whose bytes the pool
    still has, or None. A row outlives its email by up to a week (rows are dropped a weekly
    partition at a time, emails by their ttl)."""
    hashes = query_archive_hashes(message_id)
    if not hashes:
        return None

    pool = get_email_archive_pool()
    for sha256_hash in hashes:
        if pool.exists(sha256_hash):
            return sha256_hash

    logging.info("email %s has archive rows but its email has expired from the archive", message_id,
                 extra={"message_id": message_id})
    return None
