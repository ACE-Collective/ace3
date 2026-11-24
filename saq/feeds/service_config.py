"""service_feed_watch's configuration (saq.feeds.service). Kept apart from the service so the API
and the configuration loader can read it without importing the service.

The LLM endpoint lives here rather than in the top-level feeds: section because its api_key is an
env: or file: reference that only this service needs to resolve."""

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from saq.collectors.collector_configuration import CollectorServiceConfiguration


class LLMEndpointConfig(BaseModel):
    """The one OpenAI-compatible chat completions endpoint that answers definitions' questions
    (docs/FEED_WATCHES.md, *LLM*). With a hosted endpoint every question and the text of every entry it
    is asked of leave the network, and a question can reveal which products a team runs."""
    model_config = ConfigDict(extra="forbid")
    base_url: str = Field(..., description="the endpoint; ACE posts to <base_url>/v1/chat/completions")
    model: str = Field(..., min_length=1, max_length=256, description="the model requested")
    api_key: Optional[str] = Field(default=None, description="sent as a bearer token; give it as an env: or file: reference. Never logged or stored")
    proxy: Optional[str] = Field(default=None, description="a named proxy (proxy_<name>); unset for global.default_proxy")
    connect_timeout_seconds: float = Field(default=10, gt=0)
    read_timeout_seconds: float = Field(default=120, gt=0)
    max_tokens: int = Field(default=512, ge=16)
    temperature: float = Field(default=0, ge=0, le=2)
    response_format: Literal["json_schema", "json_object", "none"] = Field(default="json_schema", description="how the reply's JSON is requested; ACE validates the reply whatever the endpoint enforces")
    disable_thinking: bool = Field(default=True, description="send chat_template_kwargs.enable_thinking=false (llama.cpp, vLLM); turn off for an endpoint that refuses unknown fields")
    max_entry_chars: int = Field(default=8000, ge=200, description="the entry text sent is cut to this many characters, and the decision records that it was")
    max_attempts: int = Field(default=3, ge=1, description="invalid replies before a decision fails")
    retry_after_cap_seconds: int = Field(default=300, ge=1, description="the longest a 429's Retry-After pauses classification")
    batch_size: int = Field(default=20, ge=1, description="decisions asked per pass")
    extra_body: dict[str, Any] = Field(default_factory=dict, description="extra request-body fields, such as a router's provider preferences")
    headers: dict[str, str] = Field(default_factory=dict, description="extra request headers; ACE sends none that identify it unless they are listed here (a router's attribution headers, for example)")


class FeedWatchServiceConfig(CollectorServiceConfiguration):
    loop_interval_seconds: float = Field(default=15, gt=0, description="how often the service looks for feeds that are due, entries to evaluate, decisions to ask and replays to run")
    fetch_connect_timeout_seconds: float = Field(default=10, gt=0)
    fetch_read_timeout_seconds: float = Field(default=30, gt=0)
    max_feed_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, description="a larger response is refused")
    fetch_proxy: Optional[str] = Field(default=None, description="a named proxy (proxy_<name>) for fetching feeds; unset for global.default_proxy")
    llm: Optional[LLMEndpointConfig] = Field(default=None, description="the LLM endpoint; without one no question is asked and those decisions stay pending")
