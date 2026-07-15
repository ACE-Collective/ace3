"""Schemas for the encrypted-secrets management API (ACE API v2).

Write-only: no schema here ever carries a decrypted secret value. Responses describe a secret by
name and status only.
"""

import re

from pydantic import BaseModel, field_validator

# Secret names become `encrypted:<name>` config references, so keep them config-safe: letters,
# digits, dot, underscore, dash. The 256 cap matches EncryptedPassword.key VARCHAR(256).
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_KEY_LENGTH = 256


def validate_secret_key(key: str) -> str:
    key = key.strip()
    if not key:
        raise ValueError("secret name must not be empty")
    if len(key) > MAX_KEY_LENGTH:
        raise ValueError(f"secret name must be at most {MAX_KEY_LENGTH} characters")
    if not _KEY_PATTERN.match(key):
        raise ValueError("secret name may only contain letters, digits, '.', '_' and '-'")
    return key


class SecretEntry(BaseModel):
    """One named secret and its status. Never includes the value."""
    key: str
    is_set: bool          # a value is stored in the encrypted_passwords table
    is_referenced: bool   # the name is declared as `encrypted:<name>` in some loaded config file
    # the name is declared as encrypted: somewhere, but a later-loaded config file pins that key to a
    # plaintext value, so the effective config ignores the stored secret. A dev-config artifact --
    # setting a value here has no effect until the plaintext override is removed.
    is_overridden: bool = False


class SecretsPage(BaseModel):
    secrets: list[SecretEntry]
    # False when the process has no in-memory master key, so writes cannot encrypt -- drives a
    # "secrets are locked" banner and disables set/delete in the UI.
    encryption_unlocked: bool


class SecretValue(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("secret value must not be empty")
        return v
