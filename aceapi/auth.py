from dataclasses import dataclass
from functools import wraps
from typing import Optional

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from saq.database.model import AuthApiKey, AuthApiKeyPermission
from saq.database.pool import get_db
from saq.permissions.logic import (
    key_scope_allows,
    match_config_api_key,
    user_has_permission,
)
from saq.util import sha256_str, is_uuid

@dataclass
class ApiAuthResult:
    auth_type: Optional[str] = None
    auth_name: Optional[str] = None
    auth_user_id: Optional[int] = None
    # None => unrestricted: a user key that inherits its owner's full permissions, or a config key
    # in the deprecated no-scope (legacy bypass) form. A list is a positive ALLOW-only allowlist of
    # (major, minor) patterns the request must also match -- intersected with the owner's
    # permissions for a user key, evaluated alone for a config key.
    key_scope: Optional[list[tuple[str, str]]] = None

KEY_API_AUTH_TYPE = "type"
KEY_API_AUTH_NAME = "name"

API_AUTH_TYPE_CONFIG = "config"
API_AUTH_TYPE_USER = "user"

API_HEADER_NAME = "x-ace-auth"

def _get_config_api_key_match(auth_sha256: str) -> Optional[ApiAuthResult]:
    """Returns an ApiAuthResult if the given auth token matches a configuration [apikeys] entry."""
    match = match_config_api_key(auth_sha256)
    if match is None:
        return None

    name, scope = match
    return ApiAuthResult(auth_type=API_AUTH_TYPE_CONFIG, auth_name=name, key_scope=scope)

def _get_user_api_key_match(auth_sha256: str) -> Optional[ApiAuthResult]:
    """Returns an ApiAuthResult if the given auth token is valid for a user API key, None otherwise."""
    session = get_db()
    api_key = session.execute(
        select(AuthApiKey)
        .options(selectinload(AuthApiKey.scope), selectinload(AuthApiKey.user))
        .where(AuthApiKey.key_hash == auth_sha256.lower())
    ).scalar_one_or_none()

    if api_key is None:
        return None

    # `enabled` is part of the match: disabling a user must revoke API access too, not just
    # browser access. The session path already enforces this.
    if api_key.user is None or not api_key.user.enabled:
        return None

    scope = None if api_key.inherit_user_scope else [
        (row.major, row.minor) for row in api_key.scope if row.effect == "ALLOW"
    ]
    return ApiAuthResult(
        auth_type=API_AUTH_TYPE_USER,
        auth_name=api_key.user.username,
        auth_user_id=api_key.user_id,
        key_scope=scope,
    )

def verify_api_key(auth: str) -> Optional[ApiAuthResult]:
    """Returns an ApiAuthResult object if the given auth token is valid, None otherwise."""
    if not auth:
        return None

    auth_sha256 = sha256_str(auth)
    return _get_config_api_key_match(auth_sha256) or _get_user_api_key_match(auth_sha256)

def create_api_key(
    user_id: int,
    name: str,
    *,
    inherit: bool = False,
    scope: Optional[list[tuple[str, str]]] = None,
    created_by: Optional[int] = None,
    api_key: Optional[str] = None,
) -> str:
    """Create a new API key for the given user and return the plaintext key exactly once.

    Exactly one of `inherit` (the key gets the owner's full permissions) or a non-empty `scope`
    (a list of (major, minor) ALLOW patterns) must be given -- there is no silent full-scope
    default. Only the sha256 is stored; the plaintext is never recoverable after this call.
    """
    if inherit == bool(scope):
        raise ValueError("exactly one of inherit or a non-empty scope must be provided")

    if api_key is None:
        api_key = str(uuid.uuid4())
    elif not is_uuid(api_key):
        raise ValueError("api_key appears to not be a uuid value")

    session = get_db()
    key = AuthApiKey(
        user_id=user_id,
        name=name,
        key_hash=sha256_str(api_key),
        inherit_user_scope=inherit,
        created_by=created_by,
    )
    if not inherit:
        for (major, minor) in scope:
            key.scope.append(AuthApiKeyPermission(major=major, minor=minor, effect="ALLOW"))

    session.add(key)
    session.commit()
    logging.info("created api key '%s' for user %s (inherit=%s)", name, user_id, inherit)
    return api_key

def list_api_keys(user_id: int) -> list[AuthApiKey]:
    """Return a user's API keys (metadata only; no secret is recoverable)."""
    session = get_db()
    return list(session.execute(
        select(AuthApiKey)
        .options(selectinload(AuthApiKey.scope))
        .where(AuthApiKey.user_id == user_id)
        .order_by(AuthApiKey.created_at)
    ).scalars())

def revoke_api_key(key_id: int) -> bool:
    """Delete an API key by id. Returns False if no such key existed. Not reversible."""
    session = get_db()
    key = session.get(AuthApiKey, key_id)
    if key is None:
        return False

    session.delete(key)
    session.commit()
    logging.info("revoked api key id %s", key_id)
    return True

def api_auth_check(major: str, minor: str):
    def decorator(func):
        @wraps(func)
        def _api_auth_check(*args, **kwargs):
            from flask import request, abort
            api_auth_result = verify_api_key(request.headers.get(API_HEADER_NAME, None))
            if not api_auth_result:
                abort(403)

            # Effective permission is the intersection of the user's permissions and the key's
            # scope. user_has_permission is unchanged, so group/user DENY is fully preserved; the
            # scope is a pure AND-narrowing on top. Config keys have no user to intersect with, so
            # their scope decides alone (a None scope is the deprecated legacy bypass).
            if api_auth_result.auth_type == API_AUTH_TYPE_USER:
                if not user_has_permission(api_auth_result.auth_user_id, major, minor):
                    logging.error(
                        "user %s does not have permission %s.%s for URL %s",
                        api_auth_result.auth_user_id, major, minor, request.url
                    )
                    abort(403)

            if api_auth_result.key_scope is not None and not key_scope_allows(api_auth_result.key_scope, major, minor):
                logging.error(
                    "api key %s (type %s) scope does not permit %s.%s for URL %s",
                    api_auth_result.auth_name, api_auth_result.auth_type, major, minor, request.url
                )
                abort(403)

            logging.info("api access granted from %s type %s name %s", request.remote_addr, api_auth_result.auth_type, api_auth_result.auth_name)
            return func(*args, **kwargs)

        return _api_auth_check

    return decorator
