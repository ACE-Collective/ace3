"""Archived email router for ACE API v2."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security, status

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.email import service
from aceapi_v2.responses import Rfc822StreamResponse

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/archive", response_class=Rfc822StreamResponse)
async def get_archived_email(
    message_id: str,
    _: Annotated[ApiAuthResult, Depends(require_permission("email", "read"))],
) -> Rfc822StreamResponse:
    """Stream the original of an archived email, decrypted, looked up by its Message-ID.

    The Message-ID is a query parameter rather than a path segment because Message-IDs can contain
    a "/".
    """
    try:
        content = await service.open_archived_email(message_id)
    except service.EncryptionKeyMissing:
        logger.critical("archived email %s requested but no encryption key is configured", message_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="archived emails cannot be decrypted: no encryption key is configured",
        )

    if content is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"no archived email has message id {message_id}")

    return Rfc822StreamResponse(content)
