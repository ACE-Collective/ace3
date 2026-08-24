"""Rate limiter behavior: concurrency slots, rate/budget windows, reaper, fail-closed/open."""

import time

import pytest
import redis as redis_module

from aceapi_ai.ratelimit import (
    ACQUIRE_SCRIPT,
    STALE_SLOT_GRACE_SECONDS,
    AIRateLimiter,
    RateLimitExceeded,
    RateLimitUnavailable,
    rate_limiter,
)
from saq.configuration.config import get_config
from saq.configuration.schema import AIQueryBackendLimits
from saq.constants import REDIS_DB_AI_RATE_LIMIT
from saq.redis_client import get_redis_connection

pytestmark = pytest.mark.integration


@pytest.fixture
def limiter() -> AIRateLimiter:
    return AIRateLimiter(key_prefix="ai-test")


def make_limits(**kwargs) -> AIQueryBackendLimits:
    return AIQueryBackendLimits(**kwargs)


class TestConcurrency:
    def test_slots_enforce_cap_and_release(self, limiter):
        limits = make_limits(max_concurrency=1)

        with limiter.concurrency_slot("b", limits):
            with pytest.raises(RateLimitExceeded) as exc_info:
                with limiter.concurrency_slot("b", limits):
                    pass
            assert exc_info.value.kind == "concurrency"

        # released -- acquirable again
        with limiter.concurrency_slot("b", limits):
            pass

    def test_slot_released_when_query_raises(self, limiter):
        limits = make_limits(max_concurrency=1)

        with pytest.raises(ValueError):
            with limiter.concurrency_slot("b", limits):
                raise ValueError("query blew up")

        with limiter.concurrency_slot("b", limits):
            pass

    def test_reaper_reclaims_leaked_slot(self, limiter):
        # a slot registered by a worker that died: present in the zset, never released
        limits = make_limits(max_concurrency=1, max_query_timeout=10)
        connection = get_redis_connection(REDIS_DB_AI_RATE_LIMIT)
        stale_score = time.time() - (10 + STALE_SLOT_GRACE_SECONDS) - 1
        connection.zadd("ai-test:inflight:b", {"leaked-token": stale_score})

        # acquire succeeds because the stale entry is reaped inside the atomic acquire
        with limiter.concurrency_slot("b", limits):
            assert connection.zcard("ai-test:inflight:b") == 1

    def test_fresh_slot_is_not_reaped(self, limiter):
        limits = make_limits(max_concurrency=1, max_query_timeout=10)
        connection = get_redis_connection(REDIS_DB_AI_RATE_LIMIT)
        connection.zadd("ai-test:inflight:b", {"live-token": time.time()})

        with pytest.raises(RateLimitExceeded):
            with limiter.concurrency_slot("b", limits):
                pass


class TestRateAndBudget:
    def test_rate_window(self, limiter):
        limits = make_limits(requests_per_minute=2, hourly_budget=100)
        limiter.check_request("b", limits)
        limiter.check_request("b", limits)
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check_request("b", limits)
        assert exc_info.value.kind == "rate"
        assert 0 < exc_info.value.retry_after_seconds <= 60

    def test_hourly_budget(self, limiter):
        limits = make_limits(requests_per_minute=100, hourly_budget=2)
        limiter.check_request("b", limits)
        limiter.check_request("b", limits)
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check_request("b", limits)
        assert exc_info.value.kind == "budget"

    def test_backends_have_independent_counters(self, limiter):
        limits = make_limits(requests_per_minute=1)
        limiter.check_request("b1", limits)
        limiter.check_request("b2", limits)
        with pytest.raises(RateLimitExceeded):
            limiter.check_request("b1", limits)


@pytest.fixture
def broken_limiter() -> AIRateLimiter:
    limiter = AIRateLimiter(key_prefix="ai-test")
    connection = redis_module.Redis(
        host="localhost", port=1, socket_connect_timeout=0.1, socket_timeout=0.1)
    limiter._connection = connection
    limiter._acquire_script = connection.register_script(ACQUIRE_SCRIPT)
    return limiter


class TestRedisUnavailable:
    def test_fails_closed_by_default(self, broken_limiter):
        assert get_config().ai_api.rate_limit_fail_open is False
        with pytest.raises(RateLimitUnavailable):
            broken_limiter.check_request("b", make_limits())

        with pytest.raises(RateLimitUnavailable):
            with broken_limiter.concurrency_slot("b", make_limits()):
                pass

    def test_fail_open_when_configured(self, broken_limiter, monkeypatch):
        monkeypatch.setattr(get_config().ai_api, "rate_limit_fail_open", True)

        broken_limiter.check_request("b", make_limits())  # no exception

        ran = False
        with broken_limiter.concurrency_slot("b", make_limits()):
            ran = True
        assert ran


@pytest.mark.asyncio
async def test_rate_limited_query_is_429_with_retry_after(client, monkeypatch):
    """End-to-end: the endpoint surfaces a limiter refusal as 429 + Retry-After + audit."""
    import aceapi_ai.query.service as service_module

    def refuse(backend_name, limits):
        raise RateLimitExceeded("rate", "simulated exhaustion", retry_after_seconds=17)

    monkeypatch.setattr(service_module.rate_limiter, "check_request", refuse)

    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    response = await client.post("/query/fake", json={
        "query": "search x",
        "start_time": (end - timedelta(hours=1)).isoformat(),
        "end_time": end.isoformat(),
    })
    assert response.status_code == 429
    assert response.headers["retry-after"] == "17"
    assert "simulated exhaustion" in response.json()["detail"]


@pytest.mark.asyncio
async def test_concurrency_rejection_does_not_consume_rate_token(client, monkeypatch):
    """The concurrency slot is taken before the rate/budget counters are touched, so a request
    refused for concurrency leaves the minute/hour windows untouched."""
    import contextlib
    from unittest.mock import MagicMock

    import aceapi_ai.query.service as service_module

    @contextlib.contextmanager
    def refuse_slot(backend_name, limits):
        raise RateLimitExceeded("concurrency", "simulated slot exhaustion", retry_after_seconds=10)
        yield  # pragma: no cover

    check_request = MagicMock()
    monkeypatch.setattr(service_module.rate_limiter, "concurrency_slot", refuse_slot)
    monkeypatch.setattr(service_module.rate_limiter, "check_request", check_request)

    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    response = await client.post("/query/fake", json={
        "query": "search x",
        "start_time": (end - timedelta(hours=1)).isoformat(),
        "end_time": end.isoformat(),
    })
    assert response.status_code == 429
    assert response.headers["retry-after"] == "10"
    check_request.assert_not_called()
