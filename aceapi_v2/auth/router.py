"""Authentication router for ACE API v2."""

from dataclasses import dataclass
import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import RefreshRequest, Token
from aceapi_v2.auth.utils import (
    create_access_token,
    create_refresh_token,
    verify_token,
)
from aceapi_v2.database import get_async_session
from saq.database.model import User

router = APIRouter()


@dataclass
class AuthenticatedUser:
    id: int
    username: str


async def authenticate_user(
    username: str, password: str, session: AsyncSession
) -> Optional[AuthenticatedUser]:
    """Verify username/password against database.

    Args:
        username: The username to authenticate
        password: The password to verify
        session: Async database session

    Returns:
        AuthenticatedUser if authentication succeeds, None otherwise
    """
    logging.info(f"authenticating user {username}")

    try:
        result = await session.execute(
            select(User).where(User.username == username, User.enabled == True)  # noqa: E712
        )
        user = result.scalar_one_or_none()
        if not user:
            return None

        if user.verify_password(password):
            # Note: verify_password may update password_hash for legacy hash migration.
            # The session will commit this change when the request completes.
            logging.info(f"authentication successful for user {username}")
            return AuthenticatedUser(id=user.id, username=user.username)
    except Exception as e:
        logging.error(f"error authenticating user {username}: {e}")

    logging.info(f"authentication failed for user {username}")
    return None


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Token:
    """Authenticate user and return access + refresh tokens.

    Use OAuth2 password flow: POST with form data containing
    'username' and 'password' fields.
    """
    user = await authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(
        access_token=create_access_token(user.username, user.id),
        refresh_token=create_refresh_token(user.username, user.id),
    )


@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    request: RefreshRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Token:
    """Use refresh token to get new access + refresh tokens.

    TODO: Invalidate the old refresh token once new tokens are issued.
    """
    token_data = verify_token(request.refresh_token, expected_type="refresh")
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify user still exists and is enabled
    result = await session.execute(
        select(User.id, User.username).where(
            User.username == token_data.username,
            User.enabled == True,  # noqa: E712
        )
    )
    row = result.first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    return Token(
        access_token=create_access_token(row.username, row.id),
        refresh_token=create_refresh_token(row.username, row.id),
    )
