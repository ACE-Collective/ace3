from dataclasses import dataclass
from datetime import datetime


@dataclass
class ArchiveEmailResult:
    archive_id: int
    hash: str
    archive_path: str
    insert_date: datetime
