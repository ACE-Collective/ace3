from datetime import timedelta
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalysisModuleConfig(BaseModel):
    # a key the config class does not declare is a typo or a renamed setting, and ignoring it
    # leaves the module running without it; a subclass that takes open-ended keys allows them
    model_config = ConfigDict(extra="forbid")

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
    dependencies: list[str] = Field(default=[], description="config names of analysis modules whose analysis of the same observable must exist before this module runs")
    required_directives: list[str] = Field(default=[], description="The list of required directives for the analysis module.")
    required_tags: list[str] = Field(default=[], description="The list of required tags for the analysis module.")
    requires_detection_path: bool = Field(default=False, description="Whether the analysis module requires observables to be on a detection path.")
    version: int = Field(default=1, description="The version of the analysis module.")
    wide_diff: bool = Field(default=False, description="When True, snapshot all observables before/after module execution for cross-observable mutation tracking.")
    cache_ttl: Optional[timedelta] = Field(default=None, description="When set, successful module deltas are cached for this duration. None disables caching for this module.")
    default_collapsed: bool = Field(default=False, description="Whether this module's analysis is collapsed by default in the GUI tree view.")

    @model_validator(mode='after')
    def _cache_ttl_incompatible_with_wide_diff(self) -> 'AnalysisModuleConfig':
        # Wide-diff modules mutate observables across the tree, violating the
        # cacheability contract (design doc §A6). Caching them would replay
        # stale cross-observable state, so the combination is disallowed.
        if self.cache_ttl is not None and self.wide_diff:
            raise ValueError(
                f"analysis module {self.name!r}: cache_ttl cannot be set when wide_diff is True"
            )
        return self

    @model_validator(mode='after')
    def _cache_ttl_incompatible_with_grouping(self) -> 'AnalysisModuleConfig':
        # A cache hit bypasses analyze() entirely, including the
        # analysis_covered() time-grouping check — so a grouped module
        # would replay an analysis the live path would have skipped (and
        # vice versa). The semantics are incoherent together.
        if self.cache_ttl is not None and self.is_grouped_by_time:
            raise ValueError(
                f"analysis module {self.name!r}: cache_ttl cannot be set when is_grouped_by_time is True"
            )
        return self

    @model_validator(mode='after')
    def _grouping_needs_time_range(self) -> 'AnalysisModuleConfig':
        # analysis_covered() groups observations that fall within
        # observation_grouping_time_range of each other; without one it fails
        # on every observable that has a time
        if self.is_grouped_by_time and self.observation_grouping_time_range is None:
            raise ValueError(
                f"analysis module {self.name!r}: is_grouped_by_time requires observation_grouping_time_range"
            )
        return self
