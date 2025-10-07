from saq.constants import CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_TARGET
from saq.configuration.config import get_config_value
from saq.email_archive.adapter import EmailArchiveAdapter
from saq.email_archive.interface import EmailArchiveInterface
from saq.email_archive.local import EmailArchiveLocal
from saq.email_archive.s3 import EmailArchiveS3
from saq.email_archive.types import EmailArchiveTargetType

def get_email_archive_type() -> EmailArchiveTargetType:
    """Get the email archive type from the configuration."""
    return EmailArchiveTargetType(get_config_value(CONFIG_EMAIL_ARCHIVE, CONFIG_EMAIL_ARCHIVE_TARGET))


class EmailArchiveFactory:
    """Factory for creating EmailArchiveInterface instances."""

    @staticmethod
    def get_email_archive_interface() -> EmailArchiveInterface:
        """Create an EmailArchiveInterface instance."""
        if get_email_archive_type() == EmailArchiveTargetType.LOCAL:
            return EmailArchiveAdapter(EmailArchiveLocal())
        elif get_email_archive_type() == EmailArchiveTargetType.S3:
            return EmailArchiveAdapter(EmailArchiveS3())
        else:
            raise ValueError(f"Invalid email archive type: {get_email_archive_type()}")