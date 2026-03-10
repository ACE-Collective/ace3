from datetime import timedelta
from typing import Optional, Union

from pydantic import BaseModel, Field


class AnalysisModuleConfig(BaseModel):
    name: str = Field(..., description="Unique identifier for the analysis module.")
    python_module: str = Field(..., description="The Python module that contains the analysis module class.")
    python_class: str = Field(..., description="The name of the analysis module class inside the module.")
    enabled: bool = Field(..., description="Controls whether the analysis module is enabled or disabled.")
    description: Optional[str] = Field(default=None, description="A brief description of the analysis module.")
    instance: Optional[str] = Field(default=None, description="The instance name of the analysis module.")
    priority: int = Field(default=10, description="The priority of the analysis module.")
    observation_grouping_time_range: Optional[timedelta] = Field(default=None, description="The time range for grouping observations.")
    automation_limit: Optional[int] = Field(default=None, description="The automation limit for the analysis module.")
    maximum_analysis_time: int = Field(default=300, description="The maximum analysis time in seconds.")
    observable_exclusions: dict = Field(default={}, description="The observable exclusions for the analysis module.")
    expected_observables: dict[str, set] = Field(default={}, description="The expected observables for the analysis module.")
    is_grouped_by_time: bool = Field(default=False, description="Whether the analysis module groups observations by time.")
    cooldown_period: int = Field(default=60, description="The cooldown period in seconds.")
    semaphore_name: Optional[str] = Field(default=None, description="The semaphore name for the analysis module.")
    file_size_limit: int = Field(default=0, description="The file size limit in bytes.")
    valid_observable_types: Union[str, list[str], None] = Field(default=None, description="The list of valid observable types for the analysis module.")
    valid_queues: Optional[list[str]] = Field(default=None, description="The list of valid queues for the analysis module.")
    invalid_queues: Optional[list[str]] = Field(default=None, description="The list of invalid queues for the analysis module.")
    invalid_alert_types: Optional[list[str]] = Field(default=None, description="The list of invalid alert types for the analysis module.")
    required_directives: list[str] = Field(default=[], description="The list of required directives for the analysis module.")
    required_tags: list[str] = Field(default=[], description="The list of required tags for the analysis module.")
    requires_detection_path: bool = Field(default=False, description="Whether the analysis module requires observables to be on a detection path.")
    cache: bool = Field(default=True, description="Whether caching is enabled for the analysis module.")
    version: int = Field(default=1, description="The version of the analysis module.")
    cache_expiration: Optional[int] = Field(default=None, description="Cache expiration time in seconds.")
    cache_dedup_time_range: Optional[timedelta] = Field(default=None, description="Time range for deduplicating observables into the same cache bucket.")
    extended_version: dict[str, str] = Field(default_factory=dict, description="Static custom properties for cache key generation.")
    default_collapsed: bool = Field(default=False, description="Whether this module's analysis is collapsed by default in the GUI tree view.")
