import datetime
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field


def sanitize_value(value: Optional[str], secrets: dict) -> Optional[str]:
    """Replace any secret values found in the string with '***'.

    Iterates all leaf string values in the secrets dict and replaces
    occurrences in the input string.
    """
    if value is None:
        return None

    def _collect_leaf_strings(obj):
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from _collect_leaf_strings(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                yield from _collect_leaf_strings(item)

    for secret in _collect_leaf_strings(secrets):
        if secret and secret in value:
            value = value.replace(secret, "***")

    return value


class ExpressionTrace(BaseModel):
    """Trace of a single expression evaluation."""
    expression_type: str = Field(..., description="Expression type: jinja, equals, glob, regex, and, or, not")
    result: bool = Field(..., description="Boolean result of the expression")
    rendered_value: Optional[str] = Field(default=None, description="For jinja: the rendered string before bool cast")
    property_name: Optional[str] = Field(default=None, description="For equals/glob/regex: the event property name")
    property_value: Optional[str] = Field(default=None, description="For equals/glob/regex: the actual event property value")
    compare_value: Optional[str] = Field(default=None, description="For equals/glob/regex: the value being compared against")
    sub_expressions: Optional[list["ExpressionTrace"]] = Field(default=None, description="For and/or/not: sub-expression traces")
    error: Optional[str] = Field(default=None, description="Error message if evaluation failed")


class ConditionTrace(BaseModel):
    """Trace of a condition step (when/execute/else)."""
    trace_type: Literal["condition"] = "condition"
    expression: ExpressionTrace
    branch_taken: Literal["execute", "else", "none"]
    branch_steps: list["StepTrace"] = Field(default_factory=list)
    error: Optional[str] = Field(default=None, description="Error message if condition evaluation failed")


class TransformTrace(BaseModel):
    """Trace of a transform step."""
    trace_type: Literal["transform"] = "transform"
    transform_type: str = Field(..., description="event or stream")
    method: str = Field(..., description="property, merge, or mutate")
    command_type: str = Field(..., description="query, executable, or defined")
    rendered_command: Optional[str] = Field(default=None, description="Rendered query string or command args (secrets stripped)")
    property_name: Optional[str] = Field(default=None, description="For property transforms: the property name set")
    property_value: Optional[str] = Field(default=None, description="For property transforms: truncated repr of value set")
    result_count: Optional[int] = Field(default=None, description="Number of result rows from command output")
    merge_dropped: Optional[int] = Field(default=None, description="For merge transforms: count of incoming events dropped for a missing/unparseable timestamp")
    query_start_time: Optional[datetime.datetime] = Field(default=None, description="Resolved earliest bound for the executed query. None for non-query commands or when resolution failed before execution.")
    query_end_time: Optional[datetime.datetime] = Field(default=None, description="Resolved latest bound for the executed query. None for non-query commands or when resolution failed before execution.")
    query_time_spec: Optional[str] = Field(default=None, description="Source-native display string for the query's time bounds (e.g. Splunk's `earliest=…/latest=…`). Built by QuerySource.format_timespec_for_display. None for non-query commands.")
    error: Optional[str] = Field(default=None, description="Error message if command failed")


class ActionTrace(BaseModel):
    """Trace of an action step."""
    trace_type: Literal["action"] = "action"
    action_type: str = Field(..., description="filter, stop, discard, alert, or log")
    rendered_log_message: Optional[str] = Field(default=None, description="Rendered log message (secrets stripped)")
    is_interrupt: bool = Field(default=False, description="Whether this action interrupted event processing")
    error: Optional[str] = Field(default=None, description="Error message if action execution failed")


class StepTrace(BaseModel):
    """Trace of one step — wraps the specific trace type."""
    description: Optional[str] = Field(default=None, description="Human description from the step config")
    step: Union[ConditionTrace, TransformTrace, ActionTrace] = Field(..., discriminator="trace_type")
    duration_ms: Optional[float] = Field(
        default=None,
        description="Wall time to execute this step, in milliseconds. For condition steps this is "
                    "inclusive of all nested branch steps.",
    )


class EventTrace(BaseModel):
    """Complete trace for one event's path through correlation logic."""
    event_index: int = Field(..., description="Index of the event in the stream")
    steps: list[StepTrace] = Field(default_factory=list, description="Traces of each step executed for this event")
    outcome: str = Field(default="alert", description="Final outcome: alert, filter, stop, discard, timeout, error, stream_reset")
    duration_ms: Optional[float] = Field(default=None, description="Total wall time to process this event through all its steps, in milliseconds")
    summary: Optional[str] = Field(default=None, description="Short human-readable summary of this event for display in collapsed UI rows")
    events_position: Optional[int] = Field(default=None, description="When set on a per-alert trace, the index into the alert's details['events'] list where the full event dict lives — lets the UI surface the untruncated structured value of any property the trace shows")


class StreamEvent(BaseModel):
    """A stream-level event that doesn't belong to a single event."""
    event_type: str = Field(..., description="stream_reset, timeout, or discard")
    at_event_index: Optional[int] = Field(default=None, description="Event index when this occurred")
    detail: Optional[str] = Field(default=None, description="Additional detail about the event")


class CorrelationTrace(BaseModel):
    """Top-level trace for the entire correlation execution."""
    event_traces: list[EventTrace] = Field(default_factory=list, description="Per-event execution traces")
    stream_events: list[StreamEvent] = Field(default_factory=list, description="Stream-level events")
