from abc import ABC, abstractmethod
import importlib
from typing import TYPE_CHECKING

from saq.file_collection.types import FileCollectionWorkItem, FileCollectorResult

if TYPE_CHECKING:
    from saq.configuration.schema import FileCollectorConfig


class FileCollector(ABC):
    """Abstract base class for file collection implementations.

    Subclasses implement the collect() method to perform the actual file collection
    using whatever system they integrate with (e.g., CrowdStrike Falcon RTR).
    """

    def __init__(self, config: "FileCollectorConfig"):
        self.config = config

    @property
    def observable_type(self) -> str:
        return self.config.observable_type

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def display_name(self) -> str:
        return self.config.display_name

    @property
    def description(self) -> str:
        return self.config.description

    @abstractmethod
    def collect(self, target: FileCollectionWorkItem) -> FileCollectorResult:
        """Attempt to collect the file specified in the target.

        Args:
            target: The work item containing details about the file to collect.

        Returns:
            FileCollectorResult with the status and optional collected file path/hash.
        """
        pass

    def should_retry(self, result: FileCollectorResult, retry_count: int, max_retries: int) -> bool:
        """Determines if a collection should be retried.

        Can be overridden by implementations for custom retry logic.

        Args:
            result: The result of the last collection attempt.
            retry_count: Number of previous retry attempts.
            max_retries: Maximum allowed retry attempts.

        Returns:
            True if the collection should be retried.
        """
        if result.status.is_final:
            return False
        return retry_count < max_retries


def load_file_collector_from_config(config: "FileCollectorConfig") -> FileCollector:
    """Returns a FileCollector instance as defined by a FileCollectorConfig."""
    module = importlib.import_module(config.python_module)
    class_definition = getattr(module, config.python_class)
    return class_definition(config)


def get_file_collector_by_name(name: str) -> FileCollector:
    """Returns the FileCollector with the given name."""
    from saq.configuration import get_config
    for collector_config in get_config().file_collectors:
        if collector_config.name == name:
            return load_file_collector_from_config(collector_config)

    raise ValueError(f"file collector {name} not found")
