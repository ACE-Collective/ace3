"""A hold: the explicit reference that keeps a CAS object alive (docs/CAS.md)."""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

LEGAL_HOLD_KIND = "legal_hold"

# column widths in cas_holds
HOLDER_KIND_PATTERN = re.compile(r"^[a-z0-9_]{1,32}$")
HOLDER_ID_MAX_LENGTH = 128


@dataclass(frozen=True)
class Hold:
    """(holder_kind, holder_id), optionally with an expiry.

    holder_kind names what kind of thing holds the object (an SVS capture record, a legal hold);
    holder_id identifies which one. There is no timestamp in the identity, so taking the same hold
    twice is idempotent. expires_at is a naive local datetime compared against the database's
    NOW(); None never expires.
    """

    holder_kind: str
    holder_id: str
    expires_at: Optional[datetime] = None

    def __post_init__(self):
        if not HOLDER_KIND_PATTERN.match(self.holder_kind):
            raise ValueError(f"holder_kind {self.holder_kind!r} must match {HOLDER_KIND_PATTERN.pattern}")
        if not self.holder_id or len(self.holder_id) > HOLDER_ID_MAX_LENGTH:
            raise ValueError(f"holder_id must be 1 to {HOLDER_ID_MAX_LENGTH} characters")
        if self.expires_at is not None and not isinstance(self.expires_at, datetime):
            raise ValueError("expires_at must be a datetime or None")

    @classmethod
    def legal(cls, holder_id: str) -> "Hold":
        """A legal hold: never expires, and purge() refuses while it exists."""
        return cls(LEGAL_HOLD_KIND, holder_id)

    @property
    def is_legal(self) -> bool:
        return self.holder_kind == LEGAL_HOLD_KIND
