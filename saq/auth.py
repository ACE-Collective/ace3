"""Who is acting: the credential a request or a caller authenticated with."""

from dataclasses import dataclass


@dataclass
class ApiAuthResult:
    """Result of API authentication (API key or session cookie)."""

    auth_type: str | None = None
    auth_name: str | None = None
    auth_user_id: int | None = None
    # identity of the specific credential used, for audit attribution; key_id is None for config
    # keys (no table row) and session cookies, key_name is None for session cookies
    key_id: int | None = None
    key_name: str | None = None
    # None => unrestricted: a user key that inherits its owner's full permissions, a config key in
    # the deprecated no-scope form, or a session cookie. A list is a positive ALLOW-only allowlist
    # of (major, minor) patterns the request must also match, intersected with the owner's
    # permissions for a user key and evaluated alone for a config key.
    key_scope: list[tuple[str, str]] | None = None
    # what was presented: API_CREDENTIAL_SESSION, _USER_KEY or _CONFIG_KEY (aceapi_v2.auth.utils).
    # auth_type says whose permissions apply, and a session and a user key share it, so a check
    # that must tell a GUI session from a key tests this rather than inferring it from key_id.
    credential: str | None = None

    def __bool__(self) -> bool:
        # Empty sentinel (returned for unmatched credentials) must be falsy so
        # that `if result:` checks in get_current_auth fall through to the next
        # auth method instead of treating an unverified request as authenticated.
        return self.auth_type is not None
