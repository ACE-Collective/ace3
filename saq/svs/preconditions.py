"""What a person's write expects of the row it changes (docs/SVS_API.md, *Conflicting writes*).

Two people working from the same page would otherwise overwrite each other without knowing: the
second Keep on a worklist row someone just removed, an expectation decided twice, a test host edited
from a stale form. A write may say what it was made from, as HTTP preconditions on the request:

- If-Match: the row's updated_at as the client last read it. The write applies only while the row is
  unchanged since.
- If-None-Match: *: the client saw no row. The write applies only while there still is none.

A write without either applies whatever the row holds, as before, which is what a script wants. A
precondition that no longer holds raises StaleWrite, which the API answers with 412 and the row as
it is now (re-read by the router), and the write changes nothing. Each writer checks under a lock on
the row, so two writes made from the same read can't both pass.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


class StaleWrite(Exception):
    """The row changed since the client read it."""


class InvalidPrecondition(ValueError):
    pass


@dataclass(frozen=True)
class Precondition:
    # If-Match: the row's updated_at when the client read it
    updated_at: Optional[datetime] = None
    # If-None-Match: *
    absent: bool = False

    @property
    def given(self) -> bool:
        return self.updated_at is not None or self.absent

    def check(self, row: Any, what: str) -> None:
        """Raises StaleWrite unless row (an ORM row with updated_at, or None) is what the client
        read."""
        if self.absent and row is not None:
            raise StaleWrite(f"{what} was decided by someone else since you loaded it")
        if self.updated_at is not None:
            if row is None:
                raise StaleWrite(f"{what} was removed by someone else since you loaded it")
            if _naive(row.updated_at) != self.updated_at:
                raise StaleWrite(f"{what} was changed by someone else since you loaded it")


NONE = Precondition()


def _naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo is not None else value


def parse_precondition(if_match: Optional[str], if_none_match: Optional[str]) -> Precondition:
    """The precondition of a request's If-Match (an updated_at, quoted or not, as an ETag may be) and
    If-None-Match (only * is meaningful for a write). Raises InvalidPrecondition."""
    if if_match is not None and if_none_match is not None:
        raise InvalidPrecondition("send If-Match or If-None-Match, not both")
    if if_none_match is not None:
        if if_none_match.strip() != "*":
            raise InvalidPrecondition("If-None-Match on a write must be *")
        return Precondition(absent=True)
    if if_match is None:
        return NONE

    value = if_match.strip()
    if value.startswith("W/"):
        value = value[2:]
    value = value.strip('"')
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidPrecondition(f"If-Match must be the row's updated_at, not {if_match!r}") from None
    # updated_at is naive in the session time zone, which ACE runs as UTC (saq.svs.samples.to_utc_naive)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return Precondition(updated_at=parsed)
