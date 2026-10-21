from saq.email_archive.adapter import EmailArchiveAdapter
from saq.email_archive.interface import EmailArchiveInterface
from saq.email_archive.local import EmailArchiveLocal


class EmailArchiveFactory:
    """Factory for creating EmailArchiveInterface instances."""

    @staticmethod
    def get_email_archive_interface() -> EmailArchiveInterface:
        """Create an EmailArchiveInterface instance."""
        return EmailArchiveAdapter(EmailArchiveLocal())
