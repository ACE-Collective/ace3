"""Filter screen router for ACE API v2.

The screens that filter with {name, inverted, values} entries (saq/gui/filter_screens.py) and
their share-link encoding (saq/gui/filter_url.py). A screen built as a shell over the API reads
its filter descriptor here and encodes and decodes its share links here, so the encoding exists
once, in Python. Each route requires the permission that reads the screen's data.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from pydantic import ValidationError

from aceapi_v2.dependencies import get_current_auth, require_screen_permission, screen_from_path
from aceapi_v2.filter_screens.schemas import (
    DecodedFilters,
    EncodedFilters,
    FilterDescriptor,
    FilterList,
    FilterScreenRead,
)
from saq.gui.filter_screens import FilterScreen, UnknownFilterScreen, get_filter_screen
from saq.gui.filter_url import FilterQueryError, decode_filter_query, encode_filter_query

# every route needs the permission of the screen in its path (aceapi_v2/dependencies.py)
router = APIRouter(dependencies=[Security(get_current_auth), Depends(require_screen_permission(screen_from_path))])


async def _screen(name: Annotated[str, Depends(screen_from_path)]) -> FilterScreen:
    try:
        return get_filter_screen(name)
    except UnknownFilterScreen as e:
        raise HTTPException(status_code=404, detail=str(e))


ScreenDep = Annotated[FilterScreen, Depends(_screen)]


def _invalid_filters(e: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=e.errors(include_url=False, include_context=False))


@router.get("/{screen}", response_model=FilterScreenRead)
async def get_filter_screen_descriptor(screen: ScreenDep) -> FilterScreenRead:
    fields = {field.name: field for field in screen.fields}
    return FilterScreenRead(
        name=screen.name,
        filters=[
            FilterDescriptor(
                name=name,
                slug=slug,
                kind=fields[name].kind if name in fields else None,
                options=list(fields[name].options) if name in fields else [])
            for name, slug in sorted(screen.slugs.items())
        ])


@router.post("/{screen}/encode", response_model=EncodedFilters)
async def encode_filters(body: FilterList, screen: ScreenDep) -> EncodedFilters:
    """The share-link form of a filter list. The filters are validated for the screen first, so
    a link is never made from a filter the screen would refuse."""
    try:
        entries = screen.validate_entries(body.filters)
    except ValidationError as e:
        raise _invalid_filters(e)

    try:
        return EncodedFilters(f=encode_filter_query([entry.model_dump() for entry in entries], screen=screen))
    except FilterQueryError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/{screen}/decode", response_model=DecodedFilters)
async def decode_filters(
    screen: ScreenDep,
    f: Annotated[list[str], Query(default_factory=list, description="the f= values of a share link")],
) -> DecodedFilters:
    """The filter list a share link names. A filter that no longer exists is skipped and
    reported in warnings, so an old link still opens; a malformed one is a 422."""
    try:
        filters, warnings = decode_filter_query(f, screen=screen, strict=False)
        entries = screen.validate_entries(filters)
    except FilterQueryError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ValidationError as e:
        raise _invalid_filters(e)

    return DecodedFilters(filters=entries, warnings=warnings)
