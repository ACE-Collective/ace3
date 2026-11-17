"""The email archive (docs/EMAIL_ARCHIVE.md).

The bytes of every archived email are an object in the email_archive CAS pool (docs/CAS.md), keyed
by the sha256 of the email. The email archive database says which Message-ID (and which URLs)
belong to which email and who received it: archive, archive_index and email_history, all
partitioned by week and dropped by `ace partitions maintain`. The pool is a ttl pool, so an email
lives for its ttl_days after the last time it was archived; a Message-ID whose email has expired is
reported as not archived.
"""

import io
import logging
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Iterator, Optional

from pymysql import IntegrityError

from saq.configuration.config import get_config
from saq.constants import DB_EMAIL_ARCHIVE, EMAIL_ARCHIVE_FIELD_MESSAGE_ID, EMAIL_ARCHIVE_FIELD_URL
from saq.crypto import is_encryption_initialized
from saq.database import execute_with_retry, get_db_connection
from saq.email import normalize_email_address, normalize_message_id
from saq.environment import get_global_runtime_settings

if TYPE_CHECKING:
    from saq.cas import CASPool


@dataclass
class ArchiveEmailResult:
    archive_id: int
    hash: str               # sha256 of the email, which is its digest in the pool
    insert_date: datetime


def get_email_archive_pool() -> "CASPool":
    # the CAS loads the ORM models, and initialize_environment() imports this module in every process
    from saq.cas import get_cas

    return get_cas().pool(get_config().email_archive.pool)


def get_email_archive_server_id() -> Optional[int]:
    """The archive_server id of this host, or None before initialize_email_archive()."""
    return get_global_runtime_settings().email_archive_server_id


def get_email_archive_local_server_name() -> str:
    return socket.gethostname().lower()


def initialize_email_archive():
    """Registers this host in archive_server. Called once at startup by initialize_environment()."""
    get_global_runtime_settings().email_archive_server_id = register_email_archive()


def register_email_archive(hostname: Optional[str] = None) -> int:
    """Returns the archive_server id of hostname (default: this host), creating it if needed."""
    if hostname is None:
        hostname = get_email_archive_local_server_name()

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (hostname,))
        row = cursor.fetchone()
        if row:
            logging.debug(f"loaded email archive server_id {row[0]} for {hostname}")
            return row[0]

        logging.info(f"creating archive server entry for {hostname}")
        execute_with_retry(db, cursor, "INSERT IGNORE INTO archive_server ( hostname ) VALUES ( %s )",
                           (hostname,), commit=True)

        server_id = cursor.lastrowid
        if server_id:
            return server_id

        # another process registered the same hostname between our SELECT and our INSERT, so the
        # INSERT IGNORE was suppressed and lastrowid is 0 -- read back the row that won
        cursor.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (hostname,))
        row = cursor.fetchone()
        if row is None: # pragma: nocover
            raise RuntimeError(f"unable to register email archive server {hostname}")

        return row[0]


def archive_email(file_path: str, message_id: str, recipients: list[str], insert_date: datetime) -> ArchiveEmailResult:
    """Stores the email at file_path in the pool and indexes it under message_id and recipients.
    Storing an email that is already archived renews its ttl."""
    assert isinstance(file_path, str)
    assert isinstance(message_id, str) and message_id
    assert isinstance(recipients, list)

    # the pool is encrypted: without the key the put would fail later, and less clearly
    if not is_encryption_initialized(): # pragma: nocover
        raise RuntimeError("archive_email was called but encryption is not initialized")

    # these insert_date columns are DATETIME with no fractional seconds, and insert_date is part
    # of the unique key used to de-duplicate. truncate here so the value we write is the value we
    # can match on later (MySQL rounds rather than truncates)
    insert_date = insert_date.replace(microsecond=0)

    # before the rows, so a row never names an email the pool does not have
    sha256_hash = get_email_archive_pool().put(file_path)
    logging.info("archived email %s as %s", message_id, sha256_hash,
                 extra={"message_id": message_id, "sha256": sha256_hash})

    def _insert(db, cursor) -> int:
        archive_id = insert_email_archive(db, cursor, sha256_hash, insert_date)
        index_email_archive(db, cursor, archive_id, EMAIL_ARCHIVE_FIELD_MESSAGE_ID, message_id, insert_date)
        index_email_history(db, cursor, message_id, recipients, insert_date)
        return archive_id

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        archive_id = execute_with_retry(db, db.cursor(), _insert, commit=True)

    return ArchiveEmailResult(archive_id=archive_id, hash=sha256_hash, insert_date=insert_date)


def insert_email_archive(db, cursor, email_hash: str, insert_date: datetime) -> int:
    # insert_date must be passed explicitly rather than left to DEFAULT CURRENT_TIMESTAMP. the
    # archive table is partitioned by insert_date, so MySQL requires it in every unique key --
    # which makes it part of idx_server_id (server_id, hash, insert_date), the key this
    # INSERT IGNORE relies on to de-duplicate. taking it from the server clock instead would make
    # de-duplication depend on whether two calls happen to land in the same wall clock second.
    execute_with_retry(db, cursor, "INSERT IGNORE INTO archive ( server_id, hash, insert_date ) VALUES ( %s, UNHEX(%s), %s )",
                       (get_email_archive_server_id(), email_hash, insert_date))

    archive_id = cursor.lastrowid

    # see https://dev.mysql.com/doc/refman/8.0/en/information-functions.html#function_last-insert-id
    # if we did NOT insert a new entry then we get a 0 back

    if archive_id:
        return archive_id

    cursor.execute("SELECT archive_id FROM archive WHERE server_id = %s AND hash = UNHEX(%s) AND insert_date = %s",
                   (get_email_archive_server_id(), email_hash, insert_date))
    row = cursor.fetchone()
    if row is None: # pragma: nocover -- only if the row was dropped between the two statements
        raise RuntimeError(f"unable to find archive entry for {email_hash} at {insert_date}")

    return row[0]


def index_email_archive(db, cursor, archive_id: int, field_name: str, field_value: str, insert_date: datetime):
    # 03/09/2022 - these are the only two fields used from this table
    if field_name in [ EMAIL_ARCHIVE_FIELD_MESSAGE_ID, EMAIL_ARCHIVE_FIELD_URL ]: # TODO make configurable
        if field_name == EMAIL_ARCHIVE_FIELD_MESSAGE_ID:
            field_value = normalize_message_id(field_value)

        execute_with_retry(db, cursor,
            "INSERT IGNORE INTO archive_index ( field, hash, archive_id, insert_date ) VALUES ( %s, UNHEX(SHA2(%s, 256)), %s, %s )",
            (field_name, field_value, archive_id, insert_date))


def index_email_history(db, cursor, message_id: str, recipients: list[str], insert_date: datetime):
    message_id = normalize_message_id(message_id)
    for recipient in recipients:
        recipient = normalize_email_address(recipient)
        try:
            execute_with_retry(db, cursor,
                """
                INSERT INTO email_history (
                    insert_date,
                    message_id,
                    message_id_hash,
                    recipient,
                    recipient_hash
                ) VALUES (
                    %s,
                    %s,
                    UNHEX(SHA2(%s, 256)),
                    %s,
                    UNHEX(SHA2(%s, 256))
                )""",
                (insert_date, message_id, message_id, recipient, recipient))
        except IntegrityError:
            # this recipient was already recorded for this message in this second (a resubmission)
            pass


def query_archive_hashes(message_id: str) -> list[str]:
    """The sha256 of every email archived under message_id that still has an archive row, newest
    first. One Message-ID can name more than one email (journaled copies, a resent message)."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("""
            SELECT LOWER(HEX(archive.hash))
            FROM archive JOIN archive_index ON archive.archive_id = archive_index.archive_id
            WHERE archive_index.field = 'message_id' AND archive_index.hash = UNHEX(SHA2(%s, 256))
            ORDER BY archive.insert_date DESC""", (normalize_message_id(message_id),))
        return list(dict.fromkeys(row[0] for row in cursor.fetchall()))


def find_archived_email(message_id: str) -> Optional[str]:
    """The digest in the pool of the newest email archived under message_id whose bytes the pool
    still has, or None. An archive row outlives its email by up to a week (rows are dropped a
    weekly partition at a time, emails by their ttl)."""
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


def email_is_archived(message_id: str) -> bool:
    return find_archived_email(message_id) is not None


def iter_archived_email(digest: str, chunk_size: Optional[int] = None) -> Iterator[bytes]:
    """The archived email with this digest (from find_archived_email), in chunks. The pool
    verifies it before the first chunk is produced."""
    chunk_size = chunk_size or io.DEFAULT_BUFFER_SIZE
    with get_email_archive_pool().open(digest) as fp:
        while True:
            data = fp.read(chunk_size)
            if not data:
                break

            yield data


def get_recipients_by_message_id(message_id: str) -> list[str]:
    """Returns all recipients who received the email identified by message-id."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT recipient FROM email_history WHERE message_id_hash = UNHEX(SHA2(%s, 256))", (normalize_message_id(message_id), ))
        return [row[0] for row in cursor]
