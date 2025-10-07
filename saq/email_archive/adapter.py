from datetime import datetime
from typing import Optional
from saq.email_archive.interface import EmailArchiveInterface
from saq.email_archive.types import ArchiveEmailResult


class EmailArchiveAdapter(EmailArchiveInterface):
    """Adapter that wraps an EmailArchiveInterface implementation.
    
    This adapter allows for dependency injection and abstraction of concrete EmailArchiveInterface
    implementations, making it easier to test and maintain the code.
    """
    
    def __init__(self, email_archive: EmailArchiveInterface):
        self._email_archive = email_archive

    def get_archive_dir(self) -> str:
        """Returns the relative path of the email archive directory (relative to get_data_dir())"""
        return self._email_archive.get_archive_dir()

    def get_email_archive_dir(self) -> str:
        """Returns the full path to the email archive directory."""
        return self._email_archive.get_email_archive_dir()

    def get_email_archive_server_id(self) -> int:
        """Returns the email archive id for this server, or None if it has not been set yet."""
        return self._email_archive.get_email_archive_server_id()

    def get_email_archive_local_server_name(self) -> str:
        """Returns the local server name of the email archive server."""
        return self._email_archive.get_email_archive_local_server_name()

    def initialize_email_archive(self):
        """Initializes the email archive subsystem. Must be called once at application startup."""
        return self._email_archive.initialize_email_archive()

    def archive_email(self, file_path: str, message_id: str, recipients: list[str], insert_date: datetime) -> ArchiveEmailResult:
        """Archives the given email file with the given message_id and recipient."""
        return self._email_archive.archive_email(file_path, message_id, recipients, insert_date)

    def archive_email_file(self, file_path: str, message_id: str) -> str:
        """Stores the email in the archive system and returns the md5 hash of the archived email.
        If the email is already stored then nothing changes."""
        return self._email_archive.archive_email_file(file_path, message_id)

    def get_archive_path_by_hash(self, sha256_hash: str) -> str:
        return self._email_archive.get_archive_path_by_hash(sha256_hash)

    def query_by_message_id(self, message_id: str) -> tuple[str, str]:
        """Returns (hostname, hash) or None."""
        return self._email_archive.query_by_message_id(message_id)

    def register_email_archive(self, hostname: Optional[str]=None, reset_server_id: Optional[bool]=False) -> int:
        """Registers this server as an email archiver.
        Returns the server_id if it already exists, or creates a new new."""
        return self._email_archive.register_email_archive(hostname, reset_server_id)

    def insert_email_archive(self, db, cursor, email_hash: str) -> int:
        return self._email_archive.insert_email_archive(db, cursor, email_hash)

    def index_email_archive(self, db, cursor, archive_id: int, field_name: str, field_value: str, insert_date: datetime):
        return self._email_archive.index_email_archive(db, cursor, archive_id, field_name, field_value, insert_date)
                
    def index_email_history(self, db, cursor, message_id: str, recipients: list[str], insert_date: datetime):
        return self._email_archive.index_email_history(db, cursor, message_id, recipients, insert_date)

    def get_archived_email_server(self, message_id: str) -> str:
        """Returns the hostname of the server that contains the archived email specified by message id.
        Returns None if it cannot be found."""
        return self._email_archive.get_archived_email_server(message_id)

    def get_archived_email_path(self, message_id: str) -> str:
        """Returns the local file path to the archive  email specified by message id.
        Returns None if it cannot be found."""
        return self._email_archive.get_archived_email_path(message_id)

    def iter_decrypt_email(self, target_path: str, chunk_size: Optional[int]=None):
        """Decrypt and iterate the contents of the target archived email."""
        return self._email_archive.iter_decrypt_email(target_path, chunk_size)

    def get_recipients_by_message_id(self, message_id: str) -> list[str]:
        """Returns all recipients who received the email identified by message-id."""
        return self._email_archive.get_recipients_by_message_id(message_id)

