from datetime import datetime
from typing import Optional
from saq.email_archive.factory import EmailArchiveFactory
from saq.email_archive.types import ArchiveEmailResult
from saq.email_archive.local import FIELD_MESSAGE_ID, FIELD_URL

def get_archive_dir() -> str:
    """Returns the relative path of the email archive directory (relative to get_data_dir())"""
    return EmailArchiveFactory.get_email_archive_interface().get_archive_dir()

def get_email_archive_dir() -> str:
    """Returns the full path to the email archive directory."""
    return EmailArchiveFactory.get_email_archive_interface().get_email_archive_dir()

def get_email_archive_server_id() -> int:
    """Returns the email archive id for this server, or None if it has not been set yet."""
    return EmailArchiveFactory.get_email_archive_interface().get_email_archive_server_id()

def get_email_archive_local_server_name() -> str:
    """Returns the local server name of the email archive server."""
    return EmailArchiveFactory.get_email_archive_interface().get_email_archive_local_server_name()

def initialize_email_archive():
    """Initializes the email archive subsystem. Must be called once at application startup."""
    EmailArchiveFactory.get_email_archive_interface().initialize_email_archive()

def archive_email(file_path: str, message_id: str, recipients: list[str], insert_date: datetime) -> ArchiveEmailResult:
    """Archives the given email file with the given message_id and recipient."""
    return EmailArchiveFactory.get_email_archive_interface().archive_email(file_path, message_id, recipients, insert_date)

def archive_email_file(file_path: str, message_id: str) -> str:
    """Stores the email in the archive system and returns the md5 hash of the archived email.
    If the email is already stored then nothing changes."""
    return EmailArchiveFactory.get_email_archive_interface().archive_email_file(file_path, message_id)

def get_archive_path_by_hash(sha256_hash: str) -> str:
    return EmailArchiveFactory.get_email_archive_interface().get_archive_path_by_hash(sha256_hash)

def query_by_message_id(message_id: str) -> tuple[str, str]:
    """Returns (hostname, hash) or None."""
    return EmailArchiveFactory.get_email_archive_interface().query_by_message_id(message_id)

def register_email_archive(hostname: Optional[str]=None, reset_server_id: Optional[bool]=False) -> int:
    """Registers this server as an email archiver.
    Returns the server_id if it already exists, or creates a new new."""
    return EmailArchiveFactory.get_email_archive_interface().register_email_archive(hostname, reset_server_id)

def insert_email_archive(db, cursor, email_hash: str) -> int:
    return EmailArchiveFactory.get_email_archive_interface().insert_email_archive(db, cursor, email_hash)

def index_email_archive(db, cursor, archive_id: int, field_name: str, field_value: str, insert_date: datetime):
    return EmailArchiveFactory.get_email_archive_interface().index_email_archive(db, cursor, archive_id, field_name, field_value, insert_date)
            
def index_email_history(db, cursor, message_id: str, recipients: list[str], insert_date: datetime):
    return EmailArchiveFactory.get_email_archive_interface().index_email_history(db, cursor, message_id, recipients, insert_date)

def get_archived_email_server(message_id: str) -> str:
    """Returns the hostname of the server that contains the archived email specified by message id.
    Returns None if it cannot be found."""
    return EmailArchiveFactory.get_email_archive_interface().get_archived_email_server(message_id)

def get_archived_email_path(message_id: str) -> str:
    """Returns the local file path to the archive  email specified by message id.
    Returns None if it cannot be found."""
    return EmailArchiveFactory.get_email_archive_interface().get_archived_email_path(message_id)

def iter_decrypt_email(target_path: str, chunk_size: Optional[int]=None):
    """Decrypt and iterate the contents of the target archived email."""
    return EmailArchiveFactory.get_email_archive_interface().iter_decrypt_email(target_path, chunk_size)

def get_recipients_by_message_id(message_id: str) -> list[str]:
    """Returns all recipients who received the email identified by message-id."""
    return EmailArchiveFactory.get_email_archive_interface().get_recipients_by_message_id(message_id)
