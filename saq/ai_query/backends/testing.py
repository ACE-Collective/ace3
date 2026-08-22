"""A canned-response backend for engine-free AI API tests.

Registered in etc/saq.unittest.default.yaml as ai_query_backend_fake so the aceapi_ai app can be
built and exercised without any vendor client. The extras knobs drive the failure modes the
endpoint contract must surface.
"""

import time
from typing import Any

from pydantic import BaseModel

from saq.ai_query.interface import (
    AIBackendError,
    AIQueryBackend,
    AIQueryRejected,
    AIQueryRequest,
    AIQueryResult,
)

FAKE_ROWS = [
    {"_time": "2026-01-01T00:00:00Z", "host": "host-a", "value": "1"},
    {"_time": "2026-01-01T00:01:00Z", "host": "host-b", "value": "2"},
]


class FakeQueryExtras(BaseModel):
    simulate: str | None = None      # "truncated" | "rejected" | "backend_error" | "sleep"
    sleep_seconds: float = 0.0
    error_status_code: int = 502


class FakeAIQueryBackend(AIQueryBackend):
    def __init__(self, config):
        super().__init__(config)
        self.last_request: AIQueryRequest | None = None

    @classmethod
    def get_extras_class(cls) -> type[BaseModel]:
        return FakeQueryExtras

    def describe(self) -> dict[str, Any]:
        result = self.base_describe()
        result.update({
            "query_language": "fake",
            "time_semantics": "in-band",
            "notes": "test backend returning canned rows",
        })
        return result

    def validate_request(self, request: AIQueryRequest) -> None:
        if not request.query.strip():
            raise AIQueryRejected("query must not be empty")

        if request.start_time >= request.end_time:
            raise AIQueryRejected("start_time must be before end_time")

        extras = FakeQueryExtras.model_validate(request.extras)
        if extras.simulate == "rejected":
            raise AIQueryRejected("simulated rejection")

    def validate_startup(self) -> list[str]:
        return []

    def execute(self, request: AIQueryRequest) -> AIQueryResult:
        self.last_request = request
        extras = FakeQueryExtras.model_validate(request.extras)

        if extras.simulate == "backend_error":
            raise AIBackendError(extras.error_status_code, "simulated backend failure")

        if extras.simulate == "sleep":
            time.sleep(extras.sleep_seconds)

        rows = list(FAKE_ROWS)
        truncated = extras.simulate == "truncated"
        if truncated:
            rows = rows[:1]

        return AIQueryResult(
            rows=rows,
            row_count=len(rows),
            truncated=truncated,
            truncation_reason="backend_cap" if truncated else None,
            window_start=request.start_time,
            window_end=request.end_time,
            duration_ms=int(extras.sleep_seconds * 1000),
            meta={"fake": True},
        )
