"""The email archive: the bytes are in the email_archive CAS pool, and archived_messages in the email
archive database maps each Message-ID to them (docs/EMAIL_ARCHIVE.md)."""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config
from saq.constants import DB_EMAIL_ARCHIVE
from saq.crypto import is_encryption_initialized
from saq.email import normalize_message_id

if TYPE_CHECKING:
    from saq.cas import CASPool

# Message-ID hashes per lookup query: 500 BINARY(32) values keep the IN list far below the range
# optimizer's memory limit, past which MySQL quietly scans instead (saq/database/util/index.py)
_LOOKUP_BATCH = 500


def get_email_archive_pool() -> "CASPool":
    # the CAS loads the ORM models, and every process that reads an alert imports this module
    from saq.cas import get_cas

    return get_cas().pool(get_config().email_archive.pool)


def message_id_hash(message_id: str) -> bytes:
    """The key of a Message-ID in archived_messages: the sha256 of the normalized Message-ID (the
    hash the legacy archive_index stored too, so the backfill copies it as it is)."""
    return hashlib.sha256(normalize_message_id(message_id).encode()).digest()


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

    # local, these three: sqlalchemy and the ORM models, which only archiving and lookups need, and
    # every process that reads an alert imports this module (tests/saq/test_imports.py)
    from sqlalchemy.dialects.mysql import insert as mysql_insert
    from saq.database.model import ArchivedMessage  # local: see above
    from saq.database.private_session import run_private_transaction  # local: see above

    # insert_date is part of the primary key, which de-duplicates: archiving the same email under
    # the same Message-ID at the same insert_date is one row. The column has no fractional seconds
    # and MySQL rounds rather than truncates, so truncate here to write the value that was passed
    row = {"message_id_hash": message_id_hash(message_id), "digest": bytes.fromhex(digest),
           "insert_date": insert_date.replace(microsecond=0)}
    run_private_transaction(lambda session: session.execute(mysql_insert(ArchivedMessage).prefix_with("IGNORE").values(**row)),
                            database=DB_EMAIL_ARCHIVE, description=f"archiving email {message_id}",
                            extra={"message_id": message_id, "sha256": digest})

    logging.info("archived email %s as %s", message_id, digest, extra={"message_id": message_id, "sha256": digest})
    return digest


@dataclass(frozen=True)
class ArchivedCopy:
    """One email archived under a Message-ID: its digest in the pool, and the last time it was
    archived under that Message-ID (naive UTC)."""
    digest: str
    archived_at: datetime


def query_archived_copies(message_ids: list[str]) -> dict[str, list[ArchivedCopy]]:
    """Every email archived under each of message_ids that still has a row, keyed by the
    normalized Message-ID, newest first. One Message-ID can name more than one email (journaled
    copies, a resent message). A Message-ID with no rows is left out. Whether the pool still has
    each email is the caller's question."""
    # local, these three: as in archive_email()
    from sqlalchemy import select
    from saq.database.model import ArchivedMessage  # local: see above
    from saq.database.private_session import private_transaction  # local: see above

    by_hash = {message_id_hash(message_id): normalize_message_id(message_id) for message_id in message_ids}
    hashes = list(by_hash)
    copies: dict[str, dict[str, ArchivedCopy]] = {}
    with private_transaction(DB_EMAIL_ARCHIVE) as session:
        for start in range(0, len(hashes), _LOOKUP_BATCH):
            rows = session.execute(
                select(ArchivedMessage.message_id_hash, ArchivedMessage.digest, ArchivedMessage.insert_date)
                .where(ArchivedMessage.message_id_hash.in_(hashes[start:start + _LOOKUP_BATCH]))
                .order_by(ArchivedMessage.insert_date.desc()))
            for hash_, digest, insert_date in rows:
                # newest first, so the first row of a digest is the last time it was archived
                copies.setdefault(by_hash[hash_], {}).setdefault(digest.hex(), ArchivedCopy(digest.hex(), insert_date))

    return {message_id: list(found.values()) for message_id, found in copies.items()}


def query_archive_hashes(message_id: str) -> list[str]:
    """The sha256 of every email archived under message_id that still has a row, newest first."""
    return [copy.digest for copy in query_archived_copies([message_id]).get(normalize_message_id(message_id), [])]


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
