"""Encrypted-secrets management service (ACE API v2).

The encrypted-secrets store is reached through the synchronous helpers in
``saq.configuration.encryption`` (raw ``get_db_connection`` + the in-memory master key), so these
async service functions offload that work to a thread with ``asyncio.to_thread`` rather than using
an ``AsyncSession``. Nothing here ever returns a decrypted value -- the API is write-only.
"""

import asyncio

from saq.configuration.encryption import (
    delete_password,
    encrypt_password,
    find_effective_encrypted_config_references,
    find_encrypted_config_references,
    list_encrypted_password_keys,
)
from saq.environment import get_global_runtime_settings
from aceapi_v2.secrets.schemas import SecretEntry, SecretsPage


class SecretsLockedError(Exception):
    """Raised when a write is attempted while the encryption subsystem has no master key loaded."""


def encryption_unlocked() -> bool:
    """True when the process holds the in-memory master key and can encrypt/decrypt secrets."""
    return get_global_runtime_settings().encryption_key is not None


def _collect() -> tuple[list[str], set[str], set[str]]:
    return (
        list_encrypted_password_keys(),
        find_encrypted_config_references(),
        find_effective_encrypted_config_references(),
    )


async def get_secrets_page() -> SecretsPage:
    """List every known secret name -- stored, config-referenced, or both -- with its status."""
    stored_keys, referenced, effective = await asyncio.to_thread(_collect)
    stored_set = set(stored_keys)
    entries = []
    for key in sorted(stored_set | referenced):
        is_set = key in stored_set
        is_referenced = key in referenced
        # declared as encrypted: but its marker is gone from the effective config and no value is
        # stored -> a later-loaded config file masked it with a plaintext literal
        is_overridden = is_referenced and not is_set and key not in effective
        entries.append(SecretEntry(
            key=key, is_set=is_set, is_referenced=is_referenced, is_overridden=is_overridden,
        ))
    return SecretsPage(secrets=entries, encryption_unlocked=encryption_unlocked())


async def set_secret(key: str, value: str) -> SecretEntry:
    """Create or overwrite the encrypted value for ``key``. Requires the master key to be loaded."""
    if not encryption_unlocked():
        raise SecretsLockedError()

    def _store() -> bool:
        encrypt_password(key, value)
        return key in find_encrypted_config_references()

    is_referenced = await asyncio.to_thread(_store)
    return SecretEntry(key=key, is_set=True, is_referenced=is_referenced)


async def delete_secret(key: str) -> bool:
    """Delete the stored secret ``key``. Returns True if a row was removed."""
    return await asyncio.to_thread(delete_password, key)
