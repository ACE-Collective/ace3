"""The core Splunk backend for the AI investigation API."""

import time
from datetime import timedelta
from typing import Any

import pytz
from pydantic import Field
from splunklib.results import Message

from saq.ai_query.interface import (
    AIBackendError,
    AIQueryBackend,
    AIQueryRejected,
    AIQueryRequest,
    AIQueryResult,
)
from saq.configuration.config import get_config
from saq.configuration.schema import AIQueryBackendConfig
from saq.error.remote import RemoteApiError
from saq.splunk import SplunkClient
from saq.util import create_timedelta


class SplunkAIQueryBackendConfig(AIQueryBackendConfig):
    splunk_config: str = Field(..., description="the splunk_config_<name> section holding this backend's (read-only) credentials")
    auto_append: str = Field(default="| fields *", description="appended to every query so fields survive serialization; queries must not end in a table command")


class SplunkAIQueryBackend(AIQueryBackend):
    config: SplunkAIQueryBackendConfig

    @classmethod
    def get_config_class(cls) -> type[AIQueryBackendConfig]:
        return SplunkAIQueryBackendConfig

    def describe(self) -> dict[str, Any]:
        result = self.base_describe()
        result.update({
            "query_language": "SPL",
            "time_semantics": "start_time/end_time become the search window (earliest/latest); "
                              "in-query time modifiers can only narrow it",
            "notes": f"'{self.config.auto_append}' is appended to every query, so queries must not "
                     "end in a table command; rows carry raw splunk field names",
        })
        return result

    def validate_request(self, request: AIQueryRequest) -> None:
        if not request.query.strip():
            raise AIQueryRejected("query must not be empty")

        if request.start_time >= request.end_time:
            raise AIQueryRejected("start_time must be before end_time")

        max_window = create_timedelta(self.config.limits.max_window)
        if request.end_time - request.start_time > max_window:
            raise AIQueryRejected(f"query window exceeds the maximum of {self.config.limits.max_window} (DD:HH:MM:SS)")

        if request.limit is not None and request.limit > self.config.limits.max_limit:
            raise AIQueryRejected(f"limit exceeds the maximum of {self.config.limits.max_limit}")

    def validate_startup(self) -> list[str]:
        splunk_config = get_config().get_splunk_config(self.config.splunk_config)

        credential_paths = []
        for field_name in ("password", "token"):
            secret_ref = getattr(splunk_config, field_name)
            if secret_ref is None:
                continue

            if secret_ref.key is not None:
                raise RuntimeError(
                    f"ai query backend {self.name}: splunk_config_{self.config.splunk_config}.{field_name} "
                    "is an encrypted: reference, which this process cannot resolve by design; "
                    "provide the read-only credential via a file: or env: marker instead")

            credential_paths.append(f"splunk_config_{self.config.splunk_config}.{field_name}")

        if splunk_config.username is not None:
            if splunk_config.password is None or not splunk_config.password.resolve():
                raise RuntimeError(f"ai query backend {self.name}: splunk password is not set")
        elif splunk_config.token is None or not splunk_config.token.resolve():
            raise RuntimeError(f"ai query backend {self.name}: splunk token is not set")

        return credential_paths

    def execute(self, request: AIQueryRequest) -> AIQueryResult:
        splunk_config = get_config().get_splunk_config(self.config.splunk_config)
        tz = pytz.timezone(splunk_config.timezone)
        start = request.start_time.astimezone(tz)
        end = request.end_time.astimezone(tz)

        limit = request.limit if request.limit is not None else self.config.limits.default_limit
        timeout_seconds = (request.timeout_seconds if request.timeout_seconds is not None
                           else self.config.limits.default_query_timeout)

        query = f"{request.query} {self.config.auto_append}" if self.config.auto_append else request.query

        # per-search mutable state on the client means one client per request
        client = SplunkClient(self.config.splunk_config)

        started = time.monotonic()
        try:
            rows = client.query(query, start=start, end=end, limit=limit, timeout=timedelta(seconds=timeout_seconds))
        except RemoteApiError as e:
            # a backend-side 401 must not surface as an ACE authentication failure
            if e.status_code == 401:
                raise AIBackendError(502, "splunk authentication failure") from e
            if e.status_code == 504:
                raise AIBackendError(504, e.message) from e
            raise AIBackendError(502, e.message) from e

        duration_ms = int((time.monotonic() - started) * 1000)
        rows = [row for row in rows if not isinstance(row, Message)]

        return AIQueryResult(
            rows=rows,
            row_count=len(rows),
            truncated=len(rows) >= limit,
            truncation_reason="limit" if len(rows) >= limit else None,
            window_start=request.start_time,
            window_end=request.end_time,
            duration_ms=duration_ms,
            meta={"search_link": client.encoded_query_link(request.query, start, end)},
        )
