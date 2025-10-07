from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class EmailArchiveTargetType(Enum):
    LOCAL = "local"
    S3 = "s3"


@dataclass
class ArchiveEmailResult:
    archive_id: int
    hash: str
    archive_path: str
    insert_date: datetime