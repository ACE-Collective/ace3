from dataclasses import dataclass
from datetime import datetime
import gzip
import logging
import os.path
import shutil
import socket
import tempfile
import io

from typing import Optional

from pymysql import IntegrityError

from saq.configuration import get_config_value
from saq.constants import CONFIG_EMAIL_ARCHIVE_MODULE, CONFIG_EMAIL_ARCHIVE_MODULE_DIR, DB_EMAIL_ARCHIVE, G_EMAIL_ARCHIVE_SERVER_ID
from saq.crypto import decrypt, encrypt, is_encryption_initialized
from saq.database import get_db_connection, execute_with_retry
from saq.email import normalize_email_address, normalize_message_id
from saq.environment import g_int, get_data_dir, set_g
from saq.local_locking import LocalLockError, lock_local
from saq.util import fully_qualified
from saq.util.hashing import sha256_file
from saq.util.time import local_time


FIELD_MESSAGE_ID = "message_id"
FIELD_URL = "url"

def get_archive_dir() -> str:
    """Returns the relative path of the email archive directory (relative to get_data_dir())"""
    return get_config_value(CONFIG_EMAIL_ARCHIVE_MODULE, CONFIG_EMAIL_ARCHIVE_MODULE_DIR)

def get_email_archive_dir() -> str:
    """Returns the full path to the email archive directory."""
    return os.path.join(get_data_dir(), get_archive_dir())

def get_email_archive_server_id() -> int:
    """Returns the email archive id for this server, or None if it has not been set yet."""
    return g_int(G_EMAIL_ARCHIVE_SERVER_ID)

def get_email_archive_local_server_name() -> str:
    """Returns the local server name of the email archive server."""
    return socket.gethostname().lower()

@dataclass
class ArchiveEmailResult:
    archive_id: int
    hash: str
    archive_path: str
    insert_date: datetime

def initialize_email_archive():
    """Initializes the email archive subsystem. Must be called once at application startup."""
    set_g(G_EMAIL_ARCHIVE_SERVER_ID, register_email_archive())
    os.makedirs(get_archive_dir(), exist_ok=True)

def archive_email(file_path: str, message_id: str, recipients: list[str], insert_date: datetime) -> ArchiveEmailResult:
    """Archives the given email file with the given message_id and recipient."""
    assert isinstance(file_path, str)
    assert isinstance(message_id, str)
    assert isinstance(recipients, list)

    hash = archive_email_file(file_path, message_id)
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        archive_id = insert_email_archive(db, cursor, hash)
        index_email_archive(db, cursor, archive_id, FIELD_MESSAGE_ID, message_id, insert_date)
        index_email_history(db, cursor, message_id, recipients, insert_date)
        db.commit()

    return ArchiveEmailResult(archive_id=archive_id, hash=hash, archive_path=get_archive_path_by_hash(hash), insert_date=insert_date)

def archive_email_file(file_path: str, message_id: str) -> str:
    """Stores the email in the archive system and returns the md5 hash of the archived email.
    If the email is already stored then nothing changes."""
    assert isinstance(file_path, str)
    assert isinstance(message_id, str) and message_id

    # crypto must be initialized
    if not is_encryption_initialized(): # pragma: nocover
        raise RuntimeError("archive_email was called but encryption is not initialized")

    sha256_hash = sha256_file(file_path) # XXX do we really need to use the hash of the file?
    message_id = normalize_message_id(message_id)

    # figure out where it goes
    target_path = get_archive_path_by_hash(sha256_hash)
    compressed_path = target_path[:-2] # without the .e at the end

    # does it already exist?
    if os.path.exists(target_path):
        # TODO metrics to record this
        return sha256_hash

    logging.info("archiving email %s md5 %s to %s", message_id, sha256_hash, target_path)

    # create required subdirectories
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    try:
        with lock_local(target_path):

            # compress first
            with open(file_path, "rb") as fp_in:
                with gzip.open(compressed_path, "wb") as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

            try:
                # then encrypt
                encrypt(compressed_path, target_path)
            finally:
                # and then get rid of the unencrypted version
                os.remove(compressed_path)

    # if we can't get the lock it means it's already been written
    except LocalLockError as e: # pragma: nocover
        logging.debug("unable to obtain local lock on archive file %s", file_path)

    return sha256_hash

def get_archive_path_by_hash(sha256_hash: str) -> str:
    return os.path.join(
        get_email_archive_dir(), 
        get_email_archive_local_server_name(),
        sha256_hash.lower()[0:2], 
        f'{sha256_hash.lower()}.gz.e')

def query_by_message_id(message_id: str) -> tuple[str, str]:
    """Returns (hostname, hash) or None."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT
    archive_server.hostname, HEX(archive.hash)
FROM
    archive JOIN archive_server ON archive.server_id = archive_server.server_id
    JOIN archive_index ON archive.archive_id = archive_index.archive_id
WHERE 
    archive_index.field = 'message_id' AND archive_index.hash = UNHEX(SHA2(%s, 256))
"""
, (normalize_message_id(message_id),))
        return cursor.fetchone()

def register_email_archive(hostname: Optional[str]=None, reset_server_id: Optional[bool]=False) -> int:
    """Registers this server as an email archiver.
    Returns the server_id if it already exists, or creates a new new."""

    if hostname is None:
        hostname = get_email_archive_local_server_name()

    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT server_id FROM archive_server WHERE hostname = %s", (hostname,))
        row = cursor.fetchone()
        if row:
            server_id = row[0]
            logging.debug("loaded email archive server_id %s for %s", server_id, hostname)
            return server_id

        logging.info("creating archive server entry for %s", hostname)
        execute_with_retry(db, cursor, "INSERT IGNORE INTO archive_server ( hostname ) VALUES ( %s )", 
                        (hostname,), commit=True)

        return cursor.lastrowid

def insert_email_archive(db, cursor, email_hash: str) -> int:
    execute_with_retry(db, cursor, "INSERT IGNORE INTO archive ( server_id, hash ) VALUES ( %s, UNHEX(%s) )",
                      (get_email_archive_server_id(), email_hash))

    archive_id = cursor.lastrowid

    # see https://dev.mysql.com/doc/refman/8.0/en/information-functions.html#function_last-insert-id
    # if we did NOT insert a new entry then we get a 0 back

    if archive_id:
        return archive_id

    cursor.execute("SELECT archive_id FROM archive WHERE server_id = %s AND hash = UNHEX(%s)", (get_email_archive_server_id(), email_hash))
    row = cursor.fetchone()
    return row[0]

def index_email_archive(db, cursor, archive_id: int, field_name: str, field_value: str, insert_date: datetime):
    # 03/09/2022 - these are the only two fields used from this table
    if field_name in [ FIELD_MESSAGE_ID, FIELD_URL ]: # TODO make configurable
        if field_name == FIELD_MESSAGE_ID:
            field_value = normalize_message_id(field_value)

        execute_with_retry(db, cursor, 
            "INSERT IGNORE INTO archive_index ( field, hash, archive_id, insert_date ) VALUES ( %s, UNHEX(SHA2(%s, 256)), %s, %s )",
            (field_name, field_value, archive_id, insert_date))
            
def index_email_history(db, cursor, message_id: str, recipients: list[str], insert_date: datetime):
    message_id = normalize_message_id(message_id)
    # TODO deal with duplicate
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
            # TODO ignore dupes but log or count when this happens for debugging purposes
            pass

def get_archived_email_server(message_id: str) -> str:
    """Returns the hostname of the server that contains the archived email specified by message id.
    Returns None if it cannot be found."""
    result = query_by_message_id(message_id)
    if not result:
        return None

    return fully_qualified(result[0])

def get_archived_email_path(message_id: str) -> str:
    """Returns the local file path to the archive  email specified by message id.
    Returns None if it cannot be found."""
    result = query_by_message_id(message_id)
    if not result:
        return None
    
    return get_archive_path_by_hash(result[1])

def iter_decrypt_email(target_path: str, chunk_size: Optional[int]=None):
    """Decrypt and iterate the contents of the target archived email."""

    chunk_size = chunk_size or io.DEFAULT_BUFFER_SIZE

    with tempfile.NamedTemporaryFile() as temp_file:
        decrypt(target_path, temp_file.name)
        with gzip.open(temp_file.name, 'rb') as fp_in:
            while True:
                data = fp_in.read(chunk_size)
                if not data:
                    break

                yield data

def get_recipients_by_message_id(message_id: str) -> list[str]:
    """Returns all recipients who received the email identified by message-id."""
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT recipient FROM email_history WHERE message_id_hash = UNHEX(SHA2(%s, 256))", (normalize_message_id(message_id), ))
        result = []
        for row in cursor:
            result.append(row[0])

        return result
