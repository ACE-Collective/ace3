from typing import Optional

from pydantic import Field

from saq.configuration.schema import ServiceConfig
from saq.constants import QUEUE_DEFAULT

DEFAULT_DELETE_FILES = False
DEFAULT_COLLECTION_FREQUENCY = 1
DEFAULT_CLEANUP_FREQUENCY = 1
DEFAULT_UPDATE_FREQUENCY = 60
DEFAULT_PERSISTENCE_DIR = "var/collection/persistence"
DEFAULT_INCOMING_DIR = "var/collection/incoming"
DEFAULT_ERROR_DIR = "var/collection/error"
DEFAULT_FORCE_API = False
DEFAULT_TUNING_UPDATE_FREQUENCY = "00:01:00"
DEFAULT_PERSISTENCE_CLEAR_SECONDS = 60
DEFAULT_PERSISTENCE_EXPIRATION_SECONDS = 24*60*60
DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS = 4*60*60

class CollectorServiceConfiguration(ServiceConfig):
    """Configuration for a collector service."""
    workload_type: str = Field(..., description="the type of workload for this collector (e.g., 'email', 'smtp', 'hunter'), used to identify the collector type in the database")
    queue: str = Field(default=QUEUE_DEFAULT, description="the queue name to submit workloads to")
    delete_files: bool = Field(..., description="whether to delete files after processing them, some collectors delete files as they go while others keep them")
    collection_frequency: int = Field(default=DEFAULT_COLLECTION_FREQUENCY, description="the frequency in seconds the collection thread waits between collection passes")
    cleanup_frequency: int = Field(default=DEFAULT_CLEANUP_FREQUENCY, description="the frequency in seconds between passes of the workload cleanup thread, independent of collection_frequency so a slow collector still reclaims completed work promptly")
    update_frequency: int = Field(default=DEFAULT_UPDATE_FREQUENCY, description="the frequency in seconds between calls to Collector.update(), independent of collection_frequency")
    collect_until_empty: Optional[bool] = Field(default=None, description="set to true if a collection pass that scheduled work should immediately run another pass instead of waiting collection_frequency, only meaningful for a collector whose collect() returns a bounded batch. None (the default) defers to the collector class")
    persistence_dir: str = Field(default=DEFAULT_PERSISTENCE_DIR, description="directory for persistence data storage, relative to DATA_DIR, contains various persistent information used by collectors")
    incoming_dir: str = Field(default=DEFAULT_INCOMING_DIR, description="directory where submission files are stored for processing, relative to DATA_DIR")
    error_dir: str = Field(default=DEFAULT_ERROR_DIR, description="directory containing failed submissions, relative to DATA_DIR")
    force_api: bool = Field(default=DEFAULT_FORCE_API, description="set to True to force collection to use the API even if the target node is local")
    tuning_update_frequency: str = Field(default=DEFAULT_TUNING_UPDATE_FREQUENCY, description="how often tuning rules are checked for updates, specified in HH:MM:SS format")
    persistence_clear_seconds: int = Field(default=DEFAULT_PERSISTENCE_CLEAR_SECONDS, description="interval in seconds for clearing expired persistent data from the duplicate filter")
    persistence_expiration_seconds: int = Field(default=DEFAULT_PERSISTENCE_EXPIRATION_SECONDS, description="expiration time in seconds for persistent data, default is 24 hours")
    persistence_unmodified_expiration_seconds: int = Field(default=DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS, description="expiration time in seconds for unmodified persistent data, default is 4 hours")
