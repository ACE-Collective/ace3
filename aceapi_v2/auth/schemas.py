"""Authentication schemas for ACE API v2."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ApiAuthResult:
    """Result of API authentication (API key or session cookie)."""

    auth_type: Optional[str] = None
    auth_name: Optional[str] = None
    auth_user_id: Optional[int] = None
    # None => unrestricted: a user key that inherits its owner's full permissions, a config key in
    # the deprecated no-scope form, or a session cookie. A list is a positive ALLOW-only allowlist
    # of (major, minor) patterns the request must also match, intersected with the owner's
    # permissions for a user key and evaluated alone for a config key.
    key_scope: Optional[list[tuple[str, str]]] = None

    def __bool__(self) -> bool:
        # Empty sentinel (returned for unmatched credentials) must be falsy so
        # that `if result:` checks in get_current_auth fall through to the next
        # auth method instead of treating an unverified request as authenticated.
        return self.auth_type is not None
