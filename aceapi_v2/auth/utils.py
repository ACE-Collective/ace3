"""Authentication utilities for ACE API v2."""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult, TokenData
from saq.configuration import get_config
from saq.database.model import User
from saq.util import sha256_str

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

API_AUTH_TYPE_CONFIG = "config"
API_AUTH_TYPE_USER = "user"
API_HEADER_NAME = "x-ace-auth"


def _get_secret_key() -> str:
    """Get JWT signing key from config."""
    return get_config().api.secret_key


def create_access_token(
    username: str, user_id: int, expires_delta: timedelta | None = None
) -> str:
    """Create a JWT access token for the given user."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {
        "sub": username,
        "user_id": user_id,
        "type": "access",
        "exp": expire,
    }
    return jwt.encode(to_encode, _get_secret_key(), algorithm=ALGORITHM)


def create_refresh_token(username: str, user_id: int) -> str:
    """Create a JWT refresh token for the given user."""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {
        "sub": username,
        "user_id": user_id,
        "type": "refresh",
        "exp": expire,
    }
    return jwt.encode(to_encode, _get_secret_key(), algorithm=ALGORITHM)


def verify_token(token: str, expected_type: str = "access") -> Optional[TokenData]:
    """Verify JWT token and return token data if valid.

    Args:
        token: The JWT token string to verify
        expected_type: Expected token type ("access" or "refresh")

    Returns:
        TokenData if valid, None if invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            _get_secret_key(),
            algorithms=[ALGORITHM],
            options={"verify_signature": True},
        )
        username = payload.get("sub")
        user_id = payload.get("user_id")
        token_type = payload.get("type")

        if username is None or token_type != expected_type:
            return None

        return TokenData(username=username, user_id=user_id, token_type=token_type)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# =============================================================================
# API Key Authentication
# =============================================================================


def _get_config_api_key_match(auth_sha256: str) -> ApiAuthResult:
    """Returns an ApiAuthResult if the auth token matches a config API key."""
    for valid_key_name, valid_key_value in get_config().apikeys.items():
        if (
            valid_key_value is not None
            and auth_sha256.lower() == valid_key_value.strip().lower()
        ):
            return ApiAuthResult(
                auth_type=API_AUTH_TYPE_CONFIG, auth_name=valid_key_name
            )

    return ApiAuthResult()


async def _get_user_api_key_match(
    auth_sha256: str, session: AsyncSession
) -> ApiAuthResult:
    """Returns an ApiAuthResult if the auth token matches a user API key."""
    result = await session.execute(
        text("SELECT username, id FROM users WHERE apikey_hash = :apikey"),
        {"apikey": auth_sha256.lower()},
    )
    row = result.first()
    if not row:
        return ApiAuthResult()

    return ApiAuthResult(
        auth_type=API_AUTH_TYPE_USER, auth_name=row[0], auth_user_id=row[1]
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
            signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha512},
        )
        data = s.loads(cookie)
    except Exception:
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
