from typing import Protocol

from saq.file_collection.types import FileCollectionWorkItem


class FileCollectionListener(Protocol):
    """Protocol for classes that want to receive file collection work items."""

    def handle_file_collection_request(self, work_item: FileCollectionWorkItem):
        """Called when a file collection request is ready to be processed."""
        ...

    def pending_collection_ids(self) -> set[int]:
        """Returns the ids of the file collections this listener has accepted but not yet finished
        (queued or in progress). The collector does not hand these out again while they are pending,
        even if their database lock has timed out."""
        return set()
