"""Keyset listings and their streamed exports, shared by the v2 list endpoints (docs/SVS_API.md,
Conventions).

A listing is prepared once per request (its filters resolved into a statement) and paged by keyset
with an opaque cursor, never by OFFSET. A page function has the shape
`fetch(listing, cursor, limit) -> (rows, next_cursor)`, runs synchronously in a thread, and raises
InvalidCursor for a cursor it can't use. An export streams every page of a listing in one response;
everything that can be a 4xx happens before its first byte, so the first page is fetched up front.

The cursor is base64url (unpadded) JSON with a version and whatever keys the listing needs, such as
`{"v":1,"o":"id","k":[42]}`. Clients treat it as opaque, but a cursor handed out stays valid
across releases, so its encoding never changes for a given listing.
"""

import base64
import csv
import io
import json
import logging
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Optional, TypeVar

import pytz
from fastapi import HTTPException
from pydantic import BaseModel

from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

LISTING_MAX_PAGE_SIZE = 1000
LISTING_EXPORT_PAGE_SIZE = 1000

CURSOR_VERSION = 1

T = TypeVar("T")

PageFetch = Callable[[Any, Optional[str], int], tuple[list, Optional[str]]]


class InvalidListingRequest(ValueError):
    """The filters of a listing request cannot be used; detail is a message or pydantic errors."""

    def __init__(self, detail):
        super().__init__(str(detail))
        self.detail = detail


class InvalidCursor(ValueError):
    """The cursor is malformed, or belongs to a listing in another order."""


#
# cursors
#

def encode_cursor(**fields) -> str:
    """A cursor carrying `fields` (in the order given, after the version)."""
    payload = json.dumps({"v": CURSOR_VERSION, **fields}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_cursor(cursor: str, parse: Callable[[dict], T]) -> T:
    """parse(payload) for a cursor encode_cursor() wrote. Raises InvalidCursor, also for anything
    parse() raises, so parse() can index and convert freely; parse() raises InvalidCursor itself for
    a cursor that is well formed but doesn't fit the request."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload["v"] != CURSOR_VERSION:
            raise InvalidCursor(f"unsupported cursor version {payload['v']!r}")
        return parse(payload)
    except InvalidCursor:
        raise
    except Exception as e:
        raise InvalidCursor(f"malformed cursor: {e}") from None


#
# CSV
#

def rows_to_csv(rows: Sequence[BaseModel], fields: Sequence[str], *, header: bool,
                flatten: Optional[Callable[[dict], None]] = None) -> str:
    """CSV text for rows of an export, with the header line when asked. Each row is dumped as JSON
    values; flatten(values) turns any nested value into a column value in place. None is written
    as an empty cell."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(fields)
    for row in rows:
        values = row.model_dump(mode="json")
        if flatten is not None:
            flatten(values)
        writer.writerow([values[name] if values[name] is not None else "" for name in fields])
    return buffer.getvalue()


#
# routers
#

def parse_timezone(name: str):
    """The timezone relative date filters resolve in; 422 for an unknown name."""
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


def attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


async def run_listing(function: Callable[..., T], *args, **kwargs) -> T:
    """Runs a listing's prepare or page function in a thread: InvalidListingRequest becomes a 422
    and InvalidCursor a 400."""
    try:
        return await run_db_in_thread(function, *args, **kwargs)
    except InvalidListingRequest as e:
        raise HTTPException(status_code=422, detail=e.detail)
    except InvalidCursor as e:
        raise HTTPException(status_code=400, detail=str(e))


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


@dataclass(frozen=True)
class Export:
    """An export whose first page is already fetched."""

    fetch: PageFetch
    listing: Any
    first_page: tuple[list, Optional[str]]
    what: str

    async def pages(self) -> AsyncIterator[list]:
        """Yields the rows of every page in turn. Raises _ExportFailed (after logging) when a later
        page fails, so each format can end its stream the way that format can say so."""
        rows, next_cursor = self.first_page
        yield rows
        while next_cursor is not None:
            try:
                rows, next_cursor = await run_db_in_thread(
                    self.fetch, self.listing, next_cursor, LISTING_EXPORT_PAGE_SIZE)
            except Exception as e:
                logger.error("%s export failed part-way: %s", self.what, e, exc_info=True)
                raise _ExportFailed() from e
            yield rows


async def start_export(fetch: PageFetch, listing, *, what: str) -> Export:
    """Fetches the first page of an export of `listing`, before the response starts: once the first
    byte is sent the status code can't change. `what` names the export in the log."""
    first_page = await run_listing(fetch, listing, None, LISTING_EXPORT_PAGE_SIZE)
    return Export(fetch=fetch, listing=listing, first_page=first_page, what=what)


def ndjson_response(export: Export, filename: str) -> NdjsonStreamResponse:
    """The export as NDJSON, one row per line. A failure part-way can't change the status code that
    was already sent: the stream then ends with an {"error": ...} line."""
    async def _stream():
        try:
            async for rows in export.pages():
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=attachment(filename))


def csv_response(export: Export, to_csv: Callable[..., str], filename: str) -> CsvStreamResponse:
    """The export as CSV, through to_csv(rows, header=...). A failure part-way truncates it."""
    async def _stream():
        header = True
        try:
            async for rows in export.pages():
                yield to_csv(rows, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=attachment(filename))
