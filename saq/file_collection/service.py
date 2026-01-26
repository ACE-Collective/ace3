from typing import Type

from pydantic import Field

from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_FILE_COLLECTION
from saq.file_collection.manager import FileCollectionManager
from saq.service import ACEServiceInterface


class FileCollectionServiceConfig(ServiceConfig):
    """Configuration for the file collection service."""
    lock_timeout_seconds: int = Field(
        default=300, description="The lock timeout in seconds for the file collection service"
    )
    delay_time_seconds: int = Field(
        default=60, description="[DEPRECATED] Use initial_retry_delay_seconds instead. Kept for backwards compatibility."
    )
    initial_retry_delay_seconds: int = Field(
        default=60,
        description="Initial delay between collection retry attempts (uses exponential backoff)."
    )
    max_retry_delay_seconds: int = Field(
        default=3600,
        description="Maximum delay between retry attempts (1 hour default)."
    )
    max_collection_time_seconds: int = Field(
        default=604800,
        description="Maximum total time to keep retrying collection (7 days default)."
    )


class FileCollectionService(ACEServiceInterface):
    """ACE service that manages file collection workers."""

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return FileCollectionServiceConfig

    def start(self):
        config = get_service_config(SERVICE_FILE_COLLECTION)
        self.manager = FileCollectionManager(
            lock_timeout_seconds=config.lock_timeout_seconds,
            initial_retry_delay_seconds=config.initial_retry_delay_seconds,
            max_retry_delay_seconds=config.max_retry_delay_seconds,
            max_collection_time_seconds=config.max_collection_time_seconds,
        )
        self.manager.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.manager.wait_for_start(timeout)

    def start_single_threaded(self):
        self.manager.start_single_threaded()

    def stop(self):
        self.manager.stop()

    def wait(self):
        self.manager.wait()
