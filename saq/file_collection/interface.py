from typing import Protocol

from saq.file_collection.types import FileCollectionWorkItem


class FileCollectionListener(Protocol):
    """Protocol for classes that want to receive file collection work items."""

    def handle_file_collection_request(self, work_item: FileCollectionWorkItem):
        """Called when a file collection request is ready to be processed."""
        ...
