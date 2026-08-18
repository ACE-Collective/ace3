"""Redis-backed rate limiting for the AI investigation API.

Three per-backend controls, all enforced across every uvicorn worker via shared Redis state
(REDIS_DB_AI_RATE_LIMIT):

* concurrency -- a crash-safe token semaphore on a sorted set: acquire atomically reaps entries
  older than the backend's max query timeout (slots leaked by a killed worker), checks the cap,
  and registers a token. Release removes the token; the reaper is the second net.
* request rate -- fixed one-minute INCR window.
* hourly budget -- fixed one-hour INCR window, the quota-protection control for backends whose
  vendor quota is shared with production analysis.

All calls are synchronous (redis-py) and run inside the query worker thread, never on the event
loop. When redis is unreachable the limiter fails CLOSED by default -- a control that evaporates
when redis blips is not an enforced control -- overridable with ai_api.rate_limit_fail_open.
"""

import contextlib
import logging
import time
import uuid

import redis as redis_module

from saq.configuration.config import get_config
from saq.configuration.schema import AIQueryBackendLimits
from saq.constants import REDIS_DB_AI_RATE_LIMIT
from saq.redis_client import get_redis_connection

# grace added to a slot's lifetime beyond the backend's max query timeout before the reaper may
# reclaim it -- covers result serialization time after the query itself completes
STALE_SLOT_GRACE_SECONDS = 60

# ZREMRANGEBYSCORE stale, ZCARD vs cap, ZADD -- atomically, so two workers cannot both take the
# last slot. KEYS[1]=zset, ARGV: now, stale_after_seconds, cap, token
ACQUIRE_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
    return 0
end
redis.call('ZADD', KEYS[1], tonumber(ARGV[1]), ARGV[4])
redis.call('EXPIRE', KEYS[1], math.ceil(tonumber(ARGV[2]) * 2))
return 1
"""


class RateLimitExceeded(Exception):
    """The request was refused by a limit. kind: "concurrency" | "rate" | "budget"."""

    def __init__(self, kind: str, detail: str, retry_after_seconds: int):
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.retry_after_seconds = retry_after_seconds


class RateLimitUnavailable(Exception):
    """Redis is unreachable and the limiter is configured to fail closed."""


class AIRateLimiter:
    def __init__(self, key_prefix: str = "ai"):
        self.key_prefix = key_prefix
        self._connection = None
        self._acquire_script = None

    @property
    def fail_open(self) -> bool:
        return get_config().ai_api.rate_limit_fail_open

    def _redis(self):
        if self._connection is None:
            self._connection = get_redis_connection(REDIS_DB_AI_RATE_LIMIT)
            self._acquire_script = self._connection.register_script(ACQUIRE_SCRIPT)
        return self._connection

    def _handle_redis_error(self, error: Exception):
        if self.fail_open:
            logging.warning("ai rate limiter redis unavailable, failing open: %s", error)
            return

        raise RateLimitUnavailable("rate limiter unavailable") from error

    def check_request(self, backend_name: str, limits: AIQueryBackendLimits) -> None:
        """Count this request against the minute and hour windows; raise if either is exhausted."""
        now = int(time.time())
        minute_key = f"{self.key_prefix}:rate:{backend_name}:{now // 60}"
        hour_key = f"{self.key_prefix}:budget:{backend_name}:{now // 3600}"

        try:
            connection = self._redis()
            pipeline = connection.pipeline()
            pipeline.incr(minute_key)
            pipeline.expire(minute_key, 120)
            pipeline.incr(hour_key)
            pipeline.expire(hour_key, 7200)
            minute_count, _, hour_count, _ = pipeline.execute()
        except redis_module.RedisError as e:
            self._handle_redis_error(e)
            return

        if int(minute_count) > limits.requests_per_minute:
            raise RateLimitExceeded(
                "rate",
                f"backend {backend_name} allows {limits.requests_per_minute} requests per minute",
                retry_after_seconds=60 - (now % 60))

        if int(hour_count) > limits.hourly_budget:
            raise RateLimitExceeded(
                "budget",
                f"backend {backend_name} allows {limits.hourly_budget} requests per hour",
                retry_after_seconds=3600 - (now % 3600))

    @contextlib.contextmanager
    def concurrency_slot(self, backend_name: str, limits: AIQueryBackendLimits):
        """Hold one of the backend's concurrency slots for the duration of the query."""
        key = f"{self.key_prefix}:inflight:{backend_name}"
        token = str(uuid.uuid4())
        stale_after = limits.max_query_timeout + STALE_SLOT_GRACE_SECONDS

        acquired = False
        try:
            connection = self._redis()
            acquired = bool(self._acquire_script(
                keys=[key],
                args=[time.time(), stale_after, limits.max_concurrency, token]))
        except redis_module.RedisError as e:
            self._handle_redis_error(e)
            yield
            return

        if not acquired:
            raise RateLimitExceeded(
                "concurrency",
                f"backend {backend_name} allows {limits.max_concurrency} concurrent queries",
                retry_after_seconds=10)

        try:
            yield
        finally:
            try:
                connection.zrem(key, token)
            except redis_module.RedisError as e:
                # the reaper reclaims the slot after stale_after seconds
                logging.warning("ai rate limiter failed to release slot for %s: %s", backend_name, e)


# module-level instance shared by the app; per-worker, but the state lives in redis
rate_limiter = AIRateLimiter()
