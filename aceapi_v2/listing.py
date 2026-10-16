"""The list API of a filter screen over one table, newest first (ACE API v2).

The Remediations and File Collections pages (static/js/filter_list_page.js), and scripts, read a
list the same way:

    GET {list}/?f=...&tz=...&limit=...&cursor=...   -> {data, next_cursor}
    GET {list}/export/ndjson?f=...&tz=...           every matching row, one JSON object per line
    GET {list}/export/csv?f=...&tz=...              every matching row as CSV

The f= values are share-link filters (saq/gui/filter_url.py) with the screen's slugs. Pages are
keyed on the descending id, so a row inserted while a client pages is never shown twice and never
shifts a later page; follow next_cursor, with the same filters, until it is null.

A router builds a Listing from the decoded filters, and hands it to fetch_page() or the exports.
The rows are pydantic models with an id.
"""

import base64
import csv
import io
import json
import logging
from dataclasses import dataclass
from datetime import tzinfo
from typing import Annotated, Any, AsyncIterator, Callable

import pytz
from fastapi import HTTPException, Query
from pydantic import BaseModel, ValidationError
from sqlalchemy import Select

from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.sync import run_db_in_thread
from saq.database.pool import get_db
from saq.gui.filter_screens import FilterScreen
from saq.gui.filter_url import FilterQueryError, decode_filter_query

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 1000
EXPORT_PAGE_SIZE = 1000
_CURSOR_VERSION = 1

TimezoneParam = Annotated[str, Query(description="the timezone relative date filters (`-7d`, `@d`) resolve in")]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]


def filter_param(screen: FilterScreen) -> Any:
    """The f= query parameter of a screen's list."""
    return Annotated[list[str], Query(
        default_factory=list,
        description=f"a filter in the share-link encoding (`[!]slug:v1,v2`) with the {screen.name} screen's "
                    f"slugs: {', '.join(sorted(screen.slugs.values()))}; repeat for more. Filters are ANDed, the "
                    "values of one ORed.")]


@dataclass(frozen=True)
class Listing:
    """What one list request selects."""
    # the rows the filters match, unordered
    statement: Select
    # the table's id column, which orders and pages the list
    id_column: Any
    # one result row of the statement as the API's row model
    to_row: Callable[[Any], BaseModel]


def timezone(name: str) -> tzinfo:
    try:
        return pytz.timezone(name)
    except pytz.UnknownTimeZoneError:
        raise HTTPException(status_code=422, detail=f"unknown timezone {name!r}")


def filter_entries(screen: FilterScreen, f: list[str]) -> list[dict]:
    """The screen's filter entries the f= values encode; an unknown slug or a value the screen
    refuses is a 422."""
    try:
        entries, _ = decode_filter_query(f, screen=screen, strict=True)
    except FilterQueryError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        return [entry.model_dump() for entry in screen.validate_entries(entries)]
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors(include_url=False, include_context=False))


def _encode_cursor(last_id: int) -> str:
    payload = json.dumps({"v": _CURSOR_VERSION, "k": last_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> int:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload["v"] != _CURSOR_VERSION:
            raise ValueError(f"unsupported cursor version {payload['v']!r}")
        return int(payload["k"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"malformed cursor: {e}") from None


def fetch_page(listing: Listing, cursor: str | None, limit: int) -> tuple[list[BaseModel], str | None]:
    """One page after cursor, and the next page's cursor (None on the last). Uses get_db(), so
    run it through run_db_in_thread."""
    statement = listing.statement
    if cursor is not None:
        statement = statement.where(listing.id_column < _decode_cursor(cursor))

    rows = [listing.to_row(row) for row in
            get_db().execute(statement.order_by(listing.id_column.desc()).limit(limit + 1)).all()]
    if len(rows) <= limit:
        return rows, None

    rows = rows[:limit]
    return rows, _encode_cursor(rows[-1].id)


def rows_to_csv(rows: list[BaseModel], fields: tuple[str, ...], *, header: bool) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(fields)
    for row in rows:
        values = row.model_dump(mode="json")
        writer.writerow([values[name] if values[name] is not None else "" for name in fields])
    return buffer.getvalue()


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


class _ExportFailed(Exception):
    """A page after the first could not be fetched, after the response started."""


async def _export_pages(listing: Listing) -> AsyncIterator[list[BaseModel]]:
    # the first page is fetched before the response starts, so that a failure there is an error
    # response rather than an empty file
    rows, next_cursor = await run_db_in_thread(fetch_page, listing, None, EXPORT_PAGE_SIZE)

    async def _pages():
        nonlocal rows, next_cursor
        yield rows
        while next_cursor is not None:
            try:
                rows, next_cursor = await run_db_in_thread(fetch_page, listing, next_cursor, EXPORT_PAGE_SIZE)
            except Exception as e:
                logger.error("export of %s failed part-way: %s", listing.id_column, e, exc_info=True)
                raise _ExportFailed() from e
            yield rows

    return _pages()


async def export_ndjson(listing: Listing, filename: str) -> NdjsonStreamResponse:
    """Every row the listing matches, one per line; a failure part-way ends the stream with an
    {"error": ...} line."""
    pages = await _export_pages(listing)

    async def _stream():
        try:
            async for rows in pages:
                yield "".join(row.model_dump_json() + "\n" for row in rows)
        except _ExportFailed:
            yield json.dumps({"error": "the export failed part-way; the lines above are incomplete"}) + "\n"

    return NdjsonStreamResponse(_stream(), headers=_attachment(filename))


async def export_csv(listing: Listing, fields: tuple[str, ...], filename: str) -> CsvStreamResponse:
    """Every row the listing matches as CSV with these columns; a failure part-way truncates it."""
    pages = await _export_pages(listing)

    async def _stream():
        header = True
        try:
            async for rows in pages:
                yield rows_to_csv(rows, fields, header=header)
                header = False
        except _ExportFailed:
            # CSV has no way to say so in-band; the truncation and the log are the signal
            return

    return CsvStreamResponse(_stream(), headers=_attachment(filename))
