"""Authentication dependency for the AI investigation API.

API-key only, deliberately: no browser ever talks to this app, and the Flask session path would
require the GUI signing key -- a credential this container neutralizes by design (see
aceapi_ai.startup_checks). Reusing verify_api_key keeps the property that authentication is a pure
sha256 compare: nothing decryptable or forgeable lives in this process.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.auth.utils import verify_api_key
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import api_key_header


async def get_current_auth(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    api_key: Annotated[str | None, Security(api_key_header)] = None,
) -> ApiAuthResult:
    if api_key:
        result = await verify_api_key(api_key, session)
        if result:
            return result

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )
