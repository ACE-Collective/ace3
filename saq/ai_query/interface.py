"""The AI investigation query backend contract.

An AI query backend wraps exactly one data source's search API (Splunk, Logscale, Defender, ...)
behind a uniform read-only query interface served by the AI investigation API (aceapi_ai).
Backends are registered through ai_query_backend_<name> configuration sections and resolved by
saq.ai_query.registry -- never imported directly by the API app, so integrations can contribute
backends without any core code change.

The result contract encodes the behaviors an investigation endpoint must preserve:

* Truncation is loud: a capped result carries truncated=True and a reason, never a silently
  short row list.
* Error and empty are distinct: a request the backend refuses raises AIQueryRejected (HTTP 400),
  a backend failure raises AIBackendError (HTTP 5xx), and an empty result is a normal response
  with row_count 0.
* The window actually covered is echoed back, because some backends bound it out-of-band.
* Rows carry the raw backend field names untouched -- client-side tooling keys on them.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from saq.configuration.schema import AIQueryBackendConfig


@dataclass
class AIQueryRequest:
    query: str
    start_time: datetime  # timezone-aware, UTC
    end_time: datetime    # timezone-aware, UTC
    limit: int | None = None            # None -> backend default_limit
    timeout_seconds: int | None = None  # None -> backend default_query_timeout
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class AIQueryResult:
    rows: list[dict]
    row_count: int
    truncated: bool
    truncation_reason: str | None  # "limit" | "backend_cap" | None
    window_start: datetime            # the window the backend actually covered
    window_end: datetime
    duration_ms: int
    meta: dict[str, Any] = field(default_factory=dict)


class AIQueryRejected(Exception):
    """The request was refused before execution (invalid window, bad extras, over-limit...)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class AIBackendError(Exception):
    """The backend failed to execute the query. status_code is the HTTP status the API returns."""

    def __init__(self, status_code: int, reason: str):
        super().__init__(reason)
        self.status_code = status_code
        self.reason = reason


class AIQueryBackend(ABC):
    """One read-only query backend served by the AI investigation API.

    execute() is blocking -- every underlying client is synchronous -- and the API app offloads it
    to a worker thread. Implementations must be safe to construct once at registry build and have
    execute() called concurrently, so per-request state (e.g. a SplunkClient) belongs inside
    execute(), not on self.
    """

    def __init__(self, config: AIQueryBackendConfig):
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    @classmethod
    def get_config_class(cls) -> type[AIQueryBackendConfig]:
        """The config model the raw ai_query_backend_<name> section is re-validated against."""
        return AIQueryBackendConfig

    @classmethod
    def get_extras_class(cls) -> type[BaseModel] | None:
        """Model validating AIQueryRequest.extras, or None if the backend accepts no extras."""
        return None

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Backend metadata for GET /backends: query language, time semantics, limits, caveats."""
        ...

    @abstractmethod
    def validate_request(self, request: AIQueryRequest) -> None:
        """Raise AIQueryRejected for a request this backend refuses to run."""
        ...

    @abstractmethod
    def validate_startup(self) -> list[str]:
        """Assert this backend's credentials are resolvable WITHOUT the encryption subsystem.

        Raises RuntimeError when a credential is missing or reachable only through an
        encrypted: reference -- the AI container cannot read encrypted secrets by design, so
        that must be a boot failure rather than a None at query time.

        Returns the config paths (dotted, e.g. "splunk_config_ai_readonly.token") of every
        SecretRef this backend legitimately holds in plaintext; the startup custody check
        refuses to boot if the process contains any plaintext secret not declared here.
        """
        ...

    @abstractmethod
    def execute(self, request: AIQueryRequest) -> AIQueryResult:
        """Run the query. Blocking. Raises AIQueryRejected / AIBackendError."""
        ...

    def base_describe(self) -> dict[str, Any]:
        """The describe() fields common to every backend; implementations extend this dict."""
        extras_class = self.get_extras_class()
        return {
            "name": self.name,
            "limits": self.config.limits.model_dump(),
            "extras_schema": extras_class.model_json_schema() if extras_class else None,
        }
