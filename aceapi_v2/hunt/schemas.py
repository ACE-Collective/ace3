"""Schemas for the hunt validation API (ACE API v2), for the published schema: the route reads
the body itself and answers in the legacy route's shape (see router.py)."""

from typing import Any, Optional

from pydantic import BaseModel, Field


class HuntValidationRequest(BaseModel):
    compiled_hunt: dict[str, Any] = Field(description="the hunt package the validate-hunt CLI compiles (hunt_compiler.CompiledHunt)")
    execution_arguments: Optional[dict[str, Any]] = Field(
        default=None,
        description="run the hunt: start_time and end_time (MM/DD/YYYY:HH:MM:SS) for a query hunt, timezone, "
                    "analyze_results, create_alerts, queue, query_results, time_range_overrides, correlate_results")


class HuntValidationResult(BaseModel):
    valid: bool
    error: Optional[str] = Field(default=None, description="why the hunt is not valid, or why its run failed")
    remote_status_code: Optional[int] = Field(default=None, description="the data source's status, when it refused the run")
    roots: Optional[list[dict[str, Any]]] = Field(default=None, description="what the run produced, with details")
    logs: Optional[list[str]] = Field(default=None, description="every log line the run wrote")
    correlation_trace: Optional[dict[str, Any]] = None
    original_events: Optional[list[Any]] = Field(default=None, description="the events before correlation")
    correlate_results: Optional[Any] = Field(default=None, description="the correlate queries' results, to replay")
