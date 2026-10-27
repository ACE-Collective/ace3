from typing import Protocol

from saq.file_collection.types import FileCollectionWorkItem
from saq.queue_service import QueueListener


class FileCollectionListener(QueueListener[FileCollectionWorkItem], Protocol):
    """What FileCollectionCollector needs of the listeners it dispatches to."""

    def pending_collection_ids(self) -> set[int]:
        """Returns the ids of the file collections this listener has accepted but not yet finished
        (queued or in progress). The collector does not hand these out again while they are pending,
        even if their database lock has timed out."""
        return set()
