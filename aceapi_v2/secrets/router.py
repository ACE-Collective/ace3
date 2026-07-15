"""Encrypted-secrets management router (ACE API v2)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.secrets import service
from aceapi_v2.secrets.schemas import (
    SecretEntry,
    SecretsPage,
    SecretValue,
    validate_secret_key,
)

router = APIRouter(dependencies=[Security(get_current_auth)])


@router.get("/", response_model=SecretsPage)
async def list_secrets(
    _: Annotated[ApiAuthResult, Depends(require_permission("secret", "read"))],
) -> SecretsPage:
    return await service.get_secrets_page()


@router.put("/{key}", response_model=SecretEntry)
async def set_secret(
    key: str,
    body: SecretValue,
    _: Annotated[ApiAuthResult, Depends(require_permission("secret", "write"))],
) -> SecretEntry:
    try:
        key = validate_secret_key(key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        return await service.set_secret(key, body.value)
    except service.SecretsLockedError:
        raise HTTPException(
            status_code=409,
            detail="Encryption is locked on this node; a secret value cannot be set.",
        )


@router.delete("/{key}")
async def delete_secret(
    key: str,
    _: Annotated[ApiAuthResult, Depends(require_permission("secret", "write"))],
) -> dict:
    deleted = await service.delete_secret(key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"deleted": True}
