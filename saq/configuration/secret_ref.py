"""Lazy, TTL-cached resolution of encrypted config secrets.

Most ACE configuration is static and a change to it warrants a release. A handful of values --
vendor API keys/tokens that analysts rotate -- should instead be *dynamic*: settable through the
admin Secrets UI and picked up by running processes without a restart.

Such fields are typed :class:`SecretRef` in the config schema. Instead of the loader eagerly
decrypting an ``encrypted:<name>`` marker into plaintext at startup (baking it into ``CONFIG``), the
marker survives into the validated config as a ``SecretRef(key="<name>")``. The plaintext is fetched
on demand via :func:`SecretRef.resolve`, backed by a small process-local TTL cache so a rotated
secret takes effect within ``secrets.cache_ttl_seconds`` with no restart and without hammering the DB.

A plaintext value (a dev override, or a field not yet migrated) validates into
``SecretRef(literal=...)`` whose ``resolve()`` returns it unchanged -- so migrating a field to this
type is backward compatible.
"""

import threading
import time
from dataclasses import dataclass
from typing import Optional

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from saq.configuration.encryption import decrypt_password

# keep in sync with yaml_parser.ENCRYPTED_PREFIX (importing it would create an import cycle:
# yaml_parser -> encryption, and schema -> secret_ref)
ENCRYPTED_PREFIX = "encrypted:"

# fallback used before the configuration is loaded or if the tunable is unreadable
DEFAULT_SECRET_CACHE_TTL_SECONDS = 60

# name -> (expiration monotonic timestamp, plaintext value) -- process-local, mirrors
# saq.database.util.node.get_node_status_cached
_secret_cache: dict[str, tuple[float, str]] = {}
_secret_cache_lock = threading.Lock()


def _cache_ttl_seconds() -> float:
    """The configured secret cache TTL, falling back to the module default before config load."""
    try:
        # imported lazily to avoid a circular import: config -> schema -> secret_ref -> config
        from saq.configuration.config import get_config
        config = get_config()
        if config is not None and config.secrets is not None:
            return config.secrets.cache_ttl_seconds
    except Exception:
        pass
    return DEFAULT_SECRET_CACHE_TTL_SECONDS


def get_secret(key: str, ttl_seconds: Optional[float] = None) -> Optional[str]:
    """Return the decrypted value for the named secret, cached for ``ttl_seconds``.

    Returns None when the secret is not set or the encryption subsystem is locked. A None result is
    deliberately NOT cached, so a value set moments later (or an encryption unlock) is picked up on
    the next call rather than after the TTL.
    """
    if ttl_seconds is None:
        ttl_seconds = _cache_ttl_seconds()

    now = time.monotonic()
    with _secret_cache_lock:
        cached = _secret_cache.get(key)
        if cached is not None and now < cached[0]:
            return cached[1]

    # decrypt_password hits the encrypted_passwords table + the in-memory master key
    value = decrypt_password(key)

    if value is not None:
        with _secret_cache_lock:
            _secret_cache[key] = (now + ttl_seconds, value)

    return value


def clear_secret_cache() -> None:
    """Drop all cached secret values. Used by tests and available for proactive invalidation."""
    with _secret_cache_lock:
        _secret_cache.clear()


@dataclass(frozen=True, repr=False)
class SecretRef:
    """A deferred reference to an encrypted secret, resolved at point-of-use.

    Exactly one of ``key`` (an ``encrypted:<name>`` reference) or ``literal`` (an inline plaintext
    value) is set. Construct these by validating a string through pydantic, not directly.
    """
    key: Optional[str] = None
    literal: Optional[str] = None

    def resolve(self) -> Optional[str]:
        """Return the current plaintext value (TTL-cached for key refs), or None if unavailable."""
        if self.key is not None:
            return get_secret(self.key)
        return self.literal

    def __repr__(self) -> str:
        # never render a plaintext literal into logs/reprs
        if self.key is not None:
            return f"SecretRef(key={self.key!r})"
        return "SecretRef(literal=***)"

    @staticmethod
    def _validate(value: object) -> "SecretRef":
        if isinstance(value, SecretRef):
            return value
        if isinstance(value, str):
            if value.startswith(ENCRYPTED_PREFIX):
                return SecretRef(key=value[len(ENCRYPTED_PREFIX):])
            return SecretRef(literal=value)
        raise ValueError(f"SecretRef expects a string or SecretRef, got {type(value).__name__}")

    @staticmethod
    def _serialize(value: "SecretRef") -> Optional[str]:
        # round-trippable, and never emits a *resolved* secret; key refs serialize back to the marker
        if value.key is not None:
            return f"{ENCRYPTED_PREFIX}{value.key}"
        return value.literal

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: object, handler: GetCoreSchemaHandler):
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(cls._serialize),
        )


def resolve_secret(value: SecretRef | str | None) -> Optional[str]:
    """Resolve a config value that may be a SecretRef, a plain string, or None.

    Migration shim so a call site works whether or not its field has been retyped to SecretRef yet.
    """
    if isinstance(value, SecretRef):
        return value.resolve()
    return value  # plain str / None
