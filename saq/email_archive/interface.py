import datetime
from typing import Optional, Protocol

from saq.email_archive.types import ArchiveEmailResult


class EmailArchiveInterface(Protocol):
    """Interface for email archive operations."""

    def get_archive_dir(self) -> str:
        """Returns the relative path of the email archive directory (relative to get_data_dir())"""
        ...

    def get_email_archive_dir(self) -> str:
        """Returns the full path to the email archive directory."""
        ...

    def get_email_archive_server_id(self) -> int:
        """Returns the email archive id for this server, or None if it has not been set yet."""
        ...

    def get_email_archive_local_server_name(self) -> str:
        """Returns the local server name of the email archive server."""
        ...

    def initialize_email_archive(self):
        """Initializes the email archive subsystem. Must be called once at application startup."""
        ...

    def archive_email(self, file_path: str, message_id: str, recipients: list[str], insert_date: datetime) -> ArchiveEmailResult:
        """Archives the given email file with the given message_id and recipient."""
        ...

    def archive_email_file(self, file_path: str, message_id: str) -> str:
        """Stores the email in the archive system and returns the md5 hash of the archived email.
        If the email is already stored then nothing changes."""
        ...

    def get_archive_path_by_hash(self, sha256_hash: str) -> str:
        ...

    def query_by_message_id(self, message_id: str) -> tuple[str, str]:
        """Returns (hostname, hash) or None."""
        ...

    def register_email_archive(self, hostname: Optional[str]=None, reset_server_id: Optional[bool]=False) -> int:
        """Registers this server as an email archiver.
        Returns the server_id if it already exists, or creates a new new."""
        ...

    def insert_email_archive(self, db, cursor, email_hash: str) -> int:
        ...

    def index_email_archive(self, db, cursor, archive_id: int, field_name: str, field_value: str, insert_date: datetime):
        ...
                
    def index_email_history(self, db, cursor, message_id: str, recipients: list[str], insert_date: datetime):
        ...

    def get_archived_email_server(self, message_id: str) -> str:
        """Returns the hostname of the server that contains the archived email specified by message id.
        Returns None if it cannot be found."""
        ...

    def get_archived_email_path(self, message_id: str) -> str:
        """Returns the local file path to the archive  email specified by message id.
        Returns None if it cannot be found."""
        ...

    def iter_decrypt_email(self, target_path: str, chunk_size: Optional[int]=None):
        """Decrypt and iterate the contents of the target archived email."""
        ...

    def get_recipients_by_message_id(self, message_id: str) -> list[str]:
        """Returns all recipients who received the email identified by message-id."""
        ...
