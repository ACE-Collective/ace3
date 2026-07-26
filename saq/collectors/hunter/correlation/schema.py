from typing import Any, Optional, Union

from pydantic import BaseModel, Field, model_validator

from saq.collectors.hunter.correlation.timespec import parse_timespec


class ExpressionConfig(BaseModel):
    """Configuration for a conditional expression."""
    model_config = {"extra": "forbid"}

    type: str = Field(default="jinja", description="Expression type: and, or, not, equals, glob, regex, jinja")
    value: Any = Field(..., description="Expression value or list of sub-expressions")
    property: Optional[str] = Field(default=None, description="Event property to compare against (required for equals, glob, regex)")
    case_sensitive: bool = Field(default=True, description="Case sensitivity for equals, glob, regex")

    @model_validator(mode="before")
    @classmethod
    def parse_string_shorthand(cls, data):
        """A plain string is shorthand for a jinja expression."""
        if isinstance(data, str):
            return {"type": "jinja", "value": data}
        return data

    @model_validator(mode="after")
    def validate_expression(self):
        if self.type in ("equals", "glob", "regex") and self.property is None:
            raise ValueError(f"'property' is required for expression type '{self.type}'")
        if self.type == "not" and isinstance(self.value, list):
            raise ValueError("'not' expression value must not be a list")
        if self.type in ("and", "or") and not isinstance(self.value, list):
            raise ValueError(f"'{self.type}' expression value must be a list")
        return self


class TimeRangeConfig(BaseModel):
    """Time range configuration for query commands."""
    model_config = {"extra": "forbid"}

    before: Optional[str] = Field(default=None, description="Timespec for duration before reference time")
    after: Optional[str] = Field(default=None, description="Timespec for duration after reference time")
    relative_time_field: Optional[str] = Field(default=None, description="Event field containing the reference time")
    relative_time_format: Optional[str] = Field(default=None, description="Format of the reference time field")


class CommandConfig(BaseModel):
    """Configuration for a transformation command."""
    model_config = {"extra": "forbid"}

    type: str = Field(..., description="Command type: query, executable, defined")
    # This is a runaway backstop, not a routine limiter, so a short default fails a large fraction
    # of legitimate queries -- and a command error makes the event fall through to an alert, so
    # each failure can be a false positive. The correlate block's own `timeout` remains the real
    # governor of how long a correlated hunt may take.
    timeout: str = Field(default="10m", description="Command timeout as timespec")
    cache: Optional[str] = Field(default=None, description="Cache duration as timespec")

    # query-specific fields
    source: Optional[str] = Field(default=None, description="Query source name (e.g. splunk, logscale)")
    query: Optional[str] = Field(default=None, description="Query string (jinja interpolated)")
    time_range: Optional[TimeRangeConfig] = Field(default=None, description="Time range for query")
    source_options: dict[str, Any] = Field(default_factory=dict, description="Per-call options forwarded to the QuerySource (vendor-specific keys, e.g. rapid7's 'log_names')")

    # executable-specific fields
    path: Optional[str] = Field(default=None, description="Path to executable")
    stdin: Optional[bool] = Field(default=None, description="Whether to pass event via stdin")
    args: Optional[list[str]] = Field(default=None, description="Command arguments (jinja interpolated)")
    env: Optional[dict[str, str]] = Field(default=None, description="Environment variables for executable (values are jinja interpolated)")
    files: Optional[list[str]] = Field(default=None, description="Additional supporting files to include with the executable")

    # defined-specific fields
    name: Optional[str] = Field(default=None, description="Name of predefined command")
    arguments: Optional[dict] = Field(default=None, description="Override arguments for defined command")

    @model_validator(mode="after")
    def validate_command_type(self):
        if self.type == "query" and self.source is None:
            raise ValueError("'source' is required for query commands")
        if self.type == "executable" and self.path is None:
            raise ValueError("'path' is required for executable commands")
        if self.type == "defined" and self.name is None:
            raise ValueError("'name' is required for defined commands")
        return self


class MergeTimeSpecConfig(BaseModel):
    """Configuration for merge time specification."""
    model_config = {"extra": "forbid"}

    l_field: str = Field(..., description="Field containing time in existing data")
    l_format: str = Field(..., description="Format of the timestamp in existing data")
    r_field: str = Field(..., description="Field containing time in new data")
    r_format: str = Field(..., description="Format of the timestamp in new data")


class TransformConfig(BaseModel):
    """Configuration for a transform step."""
    model_config = {"extra": "forbid"}

    type: str = Field(default="event", description="Transform type: stream or event")
    method: str = Field(default="property", description="Transform method: property, merge, mutate")
    property_name: Optional[str] = Field(default=None, description="Property name for property method")
    property_type: str = Field(default="str", description="Property type for property method")
    merge_time_spec: Optional[MergeTimeSpecConfig] = Field(default=None, description="Merge time specification")
    command: CommandConfig = Field(..., description="Command to execute")

    @model_validator(mode="after")
    def validate_transform(self):
        if self.method == "property" and self.type != "event":
            raise ValueError("'property' method is only valid for event transforms")
        if self.method in ("merge", "mutate") and self.type != "stream":
            raise ValueError(f"'{self.method}' method is only valid for stream transforms")
        if self.method == "property" and self.property_name is None:
            raise ValueError("'property_name' is required for property method")
        if self.method == "merge" and self.merge_time_spec is None:
            raise ValueError("'merge_time_spec' is required for merge method")
        return self


class ActionConfig(BaseModel):
    """Configuration for an action step."""
    model_config = {"extra": "forbid"}

    type: str = Field(..., description="Action type: filter, stop, discard, alert, log")
    queue: Optional[str] = Field(default=None, description="Queue override for alert action")
    analysis_mode: Optional[str] = Field(default=None, description="Analysis mode override for alert action")
    log_level: str = Field(default="INFO", description="Log level for action logging")
    log_message: Optional[str] = Field(default=None, description="Jinja interpolated log message for action logging")

    @model_validator(mode="before")
    @classmethod
    def parse_string_shorthand(cls, data):
        """A plain string is shorthand for an action type."""
        if isinstance(data, str):
            return {"type": data}
        return data

    @model_validator(mode="after")
    def validate_action(self):
        if self.type not in ("filter", "stop", "discard", "alert", "log"):
            raise ValueError(f"invalid action type: {self.type!r}")
        return self


class ConditionConfig(BaseModel):
    """Configuration for a conditional step."""
    model_config = {"populate_by_name": True, "extra": "forbid"}

    when: Union[ExpressionConfig, str] = Field(..., description="Expression to evaluate")
    execute: list = Field(..., description="Steps to execute if condition is true")
    else_: Optional[list] = Field(default=None, alias="else", description="Steps to execute if condition is false")

    @model_validator(mode="after")
    def parse_when_string(self):
        if isinstance(self.when, str):
            self.when = ExpressionConfig(type="jinja", value=self.when)
        return self


_STEP_ALLOWED_WHEN_KEYS = frozenset({"when", "execute", "else", "description", "debug"})
_STEP_ALLOWED_TRANSFORM_ACTION_KEYS = frozenset({"transform", "action", "description", "debug"})


class StepConfig(BaseModel):
    """A single step in the correlation logic. Discriminated by the presence of when/transform/action keys."""
    model_config = {"extra": "forbid"}

    step: Union[ConditionConfig, TransformConfig, ActionConfig]

    # common optional fields
    description: Optional[str] = Field(default=None, description="Human description")
    debug: Optional[str] = Field(default=None, description="Jinja interpolated debug message")

    @model_validator(mode="before")
    @classmethod
    def dispatch_step_type(cls, data):
        if not isinstance(data, dict):
            return data

        present = [k for k in ("when", "transform", "action") if k in data]
        if len(present) > 1:
            raise ValueError(
                f"step must contain exactly one of 'when', 'transform', or 'action'; got {present}"
            )
        if not present:
            raise ValueError("step must contain 'when', 'transform', or 'action' key")

        allowed = (
            _STEP_ALLOWED_WHEN_KEYS if present[0] == "when"
            else _STEP_ALLOWED_TRANSFORM_ACTION_KEYS
        )
        extras = set(data.keys()) - allowed
        if extras:
            raise ValueError(
                f"step has unexpected keys {sorted(extras)}; allowed: {sorted(allowed)}"
            )

        description = data.get("description")
        debug = data.get("debug")

        if "when" in data:
            # Build condition config
            condition_data = {
                "when": data["when"],
                "execute": [StepConfig.model_validate(s) for s in data.get("execute", [])],
            }
            if "else" in data:
                condition_data["else"] = [StepConfig.model_validate(s) for s in data["else"]]
            step = ConditionConfig.model_validate(condition_data)
        elif "transform" in data:
            step = TransformConfig.model_validate(data["transform"])
        elif "action" in data:
            step = ActionConfig.model_validate(data["action"])

        return {"step": step, "description": description, "debug": debug}


class PredefinedCommandConfig(BaseModel):
    """A predefined command that can be referenced by name."""
    model_config = {"extra": "forbid"}

    name: str = Field(..., description="Name of the command")
    description: Optional[str] = Field(default=None, description="Description of the command")
    type: str = Field(..., description="Command type: query, executable")
    # see CommandConfig.timeout for why this is a backstop rather than a routine limiter
    timeout: str = Field(default="10m", description="Command timeout as timespec")
    cache: Optional[str] = Field(default=None, description="Cache duration as timespec")

    # query-specific fields
    source: Optional[str] = Field(default=None, description="Query source name")
    query: Optional[str] = Field(default=None, description="Query string")
    time_range: Optional[TimeRangeConfig] = Field(default=None, description="Time range for query")
    source_options: dict[str, Any] = Field(default_factory=dict, description="Per-call options forwarded to the QuerySource (vendor-specific keys, e.g. rapid7's 'log_names')")

    # executable-specific fields
    path: Optional[str] = Field(default=None, description="Path to executable")
    stdin: Optional[bool] = Field(default=None, description="Whether to pass event via stdin")
    args: Optional[list[str]] = Field(default=None, description="Command arguments")
    env: Optional[dict[str, str]] = Field(default=None, description="Environment variables for executable (values are jinja interpolated)")
    files: Optional[list[str]] = Field(default=None, description="Additional supporting files to include with the executable")

    def to_command_config(self, overrides: Optional[dict] = None) -> CommandConfig:
        """Convert to a CommandConfig, applying optional overrides."""
        data = self.model_dump(exclude={"name", "description"})
        if overrides:
            data.update(overrides)
        return CommandConfig.model_validate(data)


class CorrelateConfig(BaseModel):
    """Top-level correlate configuration."""
    model_config = {"extra": "forbid"}

    timeout: str = Field(default="15m", description="Maximum time for correlation processing")
    logic: list[StepConfig] = Field(..., description="List of correlation logic steps")

    @model_validator(mode="after")
    def validate_timeout(self):
        parse_timespec(self.timeout)
        return self
