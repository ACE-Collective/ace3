"""The If-Match / If-None-Match preconditions of SVS writes (saq.svs.preconditions, docs/SVS_API.md,
*Conflicting writes*): parsed from the request, and a write they no longer hold for answered with 412
and the row as it is now."""

from typing import Annotated, Callable, Optional

from fastapi import Depends, Header, HTTPException
from pydantic import BaseModel

from saq.svs.preconditions import InvalidPrecondition, Precondition, StaleWrite, parse_precondition


async def _precondition(
    if_match: Annotated[Optional[str], Header(description="the row's updated_at as last read: the write applies "
                                                          "only while the row is unchanged since")] = None,
    if_none_match: Annotated[Optional[str], Header(description="*: the write applies only while there is no "
                                                               "row yet")] = None,
) -> Precondition:
    try:
        return parse_precondition(if_match, if_none_match)
    except InvalidPrecondition as e:
        raise HTTPException(status_code=400, detail=str(e))


WritePrecondition = Annotated[Precondition, Depends(_precondition)]


def stale_write(e: StaleWrite, current: Callable[[], Optional[BaseModel]]) -> HTTPException:
    """412 for a write whose precondition no longer holds, with the row as it is now (null when it
    is gone), so the client can show what changed."""
    row = current()
    return HTTPException(status_code=412, detail={"message": str(e),
                                                  "current": row.model_dump(mode="json") if row is not None else None})
