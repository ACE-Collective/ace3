"""Authentication utilities for ACE API v2."""

import hashlib
import logging
from typing import Optional

from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aceapi_v2.auth.schemas import ApiAuthResult
from saq.configuration import get_config
from saq.database.model import AuthApiKey, User
from saq.permissions.logic import match_config_api_key
from saq.util import sha256_str

API_AUTH_TYPE_CONFIG = "config"
API_AUTH_TYPE_USER = "user"
API_HEADER_NAME = "x-ace-auth"


# =============================================================================
# API Key Authentication
# =============================================================================


def _get_config_api_key_match(auth_sha256: str) -> ApiAuthResult:
    """Returns an ApiAuthResult if the auth token matches a config [apikeys] entry."""
    match = match_config_api_key(auth_sha256)
    if match is None:
        return ApiAuthResult()

    name, scope = match
    logging.info(f"valid config API key for {name}")
    return ApiAuthResult(auth_type=API_AUTH_TYPE_CONFIG, auth_name=name, key_scope=scope, key_name=name)


async def _get_user_api_key_match(
    auth_sha256: str, session: AsyncSession
) -> ApiAuthResult:
    """Returns an ApiAuthResult if the auth token matches a user API key."""
    api_key = (
        await session.execute(
            select(AuthApiKey)
            .options(selectinload(AuthApiKey.scope), selectinload(AuthApiKey.user))
            .where(AuthApiKey.key_hash == auth_sha256.lower())
        )
    ).scalar_one_or_none()

    if api_key is None:
        return ApiAuthResult()

    # `enabled` is part of the match: disabling a user must revoke API access too, not just browser
    # access. The Flask-session path already enforces this.
    if api_key.user is None or not api_key.user.enabled:
        return ApiAuthResult()

    scope = None if api_key.inherit_user_scope else [
        (row.major, row.minor) for row in api_key.scope if row.effect == "ALLOW"
    ]
    return ApiAuthResult(
        auth_type=API_AUTH_TYPE_USER,
        auth_name=api_key.user.username,
        auth_user_id=api_key.user_id,
        key_scope=scope,
        key_id=api_key.id,
        key_name=api_key.name,
    )


async def verify_api_key(auth: str, session: AsyncSession) -> ApiAuthResult:
    """Verify API key and return auth result if valid."""
    if not auth:
        return ApiAuthResult()

    auth_sha256 = sha256_str(auth)
    return _get_config_api_key_match(auth_sha256) or await _get_user_api_key_match(
        auth_sha256, session
    )


# =============================================================================
# Flask Session Cookie Authentication
# =============================================================================


async def verify_flask_session(
    cookie: str, session: AsyncSession
) -> Optional[ApiAuthResult]:
    """Decode Flask session cookie and return auth result.

    Temporary: remove when Flask GUI is retired.
    """
    try:
        s = URLSafeTimedSerializer(
            get_config().gui.secret_key,
            salt="cookie-session",
            signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
        )
        data = s.loads(cookie)
    except Exception as e:
        logging.error(f"Error verifying Flask session cookie: {e}")
        return None

    user_id = data.get("_user_id")
    if user_id is None:
        return None

    result = await session.execute(
        select(User.id, User.username).where(
            User.id == int(user_id),
            User.enabled == True,
        )
    )
    row = result.first()
    if not row:
        return None

    return ApiAuthResult(
        auth_type=API_AUTH_TYPE_USER,
        auth_name=row.username,
        auth_user_id=row.id,
    )
