"""Feeds router for ACE API v2, at /feeds (docs/FEED_WATCHES.md). Reading needs feed:read; adding,
changing and deleting a feed need feed:write. A feed's credentials are accepted and never returned."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import run_listing
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.feeds import service
from aceapi_v2.feeds.schemas import Feed, FeedEntryPage, FeedPage, FeedRequest, FeedUpdate
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("feed", "read"))]
WriteAuth = Annotated[ApiAuthResult, Depends(require_permission("feed", "write"))]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=500)]


@router.get("/", response_model=FeedPage)
async def list_feeds(auth: ReadAuth, cursor: CursorParam = None, limit: LimitParam = 100) -> FeedPage:
    """The feeds, oldest first. Follow next_cursor until it is null."""
    return await run_listing(service.list_feeds, cursor, limit)


@router.post("/", response_model=Feed, status_code=201)
async def create_feed(body: FeedRequest, auth: WriteAuth) -> Feed:
    """Subscribe to a feed. Its first poll is for preview: delivery starts with the entries after it."""
    return await run_db_in_thread(service.create_feed, body, auth)


@router.get("/{feed_id}", response_model=Feed)
async def get_feed(feed_id: int, auth: ReadAuth) -> Feed:
    return await run_db_in_thread(service.get_feed, feed_id)


@router.patch("/{feed_id}", response_model=Feed)
async def update_feed(feed_id: int, body: FeedUpdate, auth: WriteAuth) -> Feed:
    return await run_db_in_thread(service.update_feed, feed_id, body, auth)


@router.delete("/{feed_id}", status_code=204)
async def delete_feed(feed_id: int, auth: WriteAuth) -> Response:
    """Stop polling the feed; its entries are deleted in the background."""
    await run_db_in_thread(service.delete_feed, feed_id, auth)
    return Response(status_code=204)


@router.get("/{feed_id}/entries", response_model=FeedEntryPage)
async def list_entries(feed_id: int, auth: ReadAuth, cursor: CursorParam = None, limit: LimitParam = 50) -> FeedEntryPage:
    """The entry versions the feed carried, newest first: the titles and text ACE receives."""
    return await run_listing(service.list_entries, feed_id, cursor, limit)
