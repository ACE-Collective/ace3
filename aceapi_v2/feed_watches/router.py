"""Feed watches router for ACE API v2, at /feed-watches (docs/FEED_WATCHES.md).

Every watch is visible with feed_watch:read, which also reads the definitions, decisions, replays and
evaluations. feed_watch:write creates and edits watches (including switching delivery on or off),
queues replays and labels entries."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import run_listing
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.feed_watches import service
from aceapi_v2.feed_watches.schemas import (
    DecisionPage,
    DefinitionPage,
    Evaluation,
    LabelRequest,
    Replay,
    ReplayRequest,
    ReplayResultPage,
    Watch,
    WatchPage,
    WatchRequest,
    WatchUpdate,
)
from aceapi_v2.sync import run_db_in_thread

router = APIRouter(dependencies=[Security(get_current_auth)])

ReadAuth = Annotated[ApiAuthResult, Depends(require_permission("feed_watch", "read"))]
WriteAuth = Annotated[ApiAuthResult, Depends(require_permission("feed_watch", "write"))]
CursorParam = Annotated[str | None, Query(description="the next_cursor of the previous page")]
LimitParam = Annotated[int, Query(ge=1, le=500)]


@router.get("/", response_model=WatchPage)
async def list_watches(auth: ReadAuth, cursor: CursorParam = None, limit: LimitParam = 100) -> WatchPage:
    """Every watch, oldest first, each flagged when its definition is missing or unusable."""
    return await run_listing(service.list_watches, cursor, limit)


@router.post("/", response_model=Watch, status_code=201)
async def create_watch(body: WatchRequest, auth: WriteAuth) -> Watch:
    """A watch delivers only entries first seen after it exists; warning says when every entry will go
    to the LLM (a definition with a question and no rule)."""
    return await run_db_in_thread(service.create_watch, body, auth)


@router.get("/definitions", response_model=DefinitionPage)
async def list_definitions(auth: ReadAuth, cursor: CursorParam = None, limit: LimitParam = 500) -> DefinitionPage:
    """The definitions as service_feed_watch last read them from the repositories."""
    return await run_listing(service.list_definitions, cursor, limit)


@router.get("/decisions", response_model=DecisionPage)
async def list_decisions(auth: ReadAuth,
                         status: Annotated[str | None, Query(description="pending, decided or failed")] = None,
                         watch_id: Annotated[int | None, Query()] = None,
                         cursor: CursorParam = None, limit: LimitParam = 100) -> DecisionPage:
    """Decisions, newest first. The failed ones gave up after llm.max_attempts invalid replies."""
    return await run_listing(service.list_decisions, status, watch_id, cursor, limit)


@router.post("/replays", response_model=Replay, status_code=202)
async def create_replay(body: ReplayRequest, auth: WriteAuth) -> Replay:
    """Queue a replay of a draft rule and question against the chosen feeds' recent entries. Nothing is
    saved where a watch reads it; poll the replay until its state is done."""
    return await run_db_in_thread(service.create_replay, body, auth)


@router.get("/replays/{replay_id}", response_model=Replay)
async def get_replay(replay_id: int, auth: ReadAuth) -> Replay:
    return await run_db_in_thread(service.get_replay, replay_id)


@router.get("/replays/{replay_id}/results", response_model=ReplayResultPage)
async def list_replay_results(replay_id: int, auth: ReadAuth,
                              outcome: Annotated[Literal["match", "miss"] | None, Query()] = None,
                              cursor: CursorParam = None, limit: LimitParam = 100) -> ReplayResultPage:
    """What the draft made of each entry, newest first, with the label for the replay's watch."""
    return await run_listing(service.list_replay_results, replay_id, outcome, cursor, limit)


@router.get("/{watch_id}", response_model=Watch)
async def get_watch(watch_id: int, auth: ReadAuth) -> Watch:
    return await run_db_in_thread(service.get_watch, watch_id)


@router.patch("/{watch_id}", response_model=Watch)
async def update_watch(watch_id: int, body: WatchUpdate, auth: WriteAuth) -> Watch:
    """Every edit is a new version. Switch delivery with mode (shadow or delivering)."""
    return await run_db_in_thread(service.update_watch, watch_id, body, auth)


@router.get("/{watch_id}/evaluation", response_model=Evaluation)
async def get_evaluation(watch_id: int, auth: ReadAuth) -> Evaluation:
    """Missed relevant posts, false alerts, latency and token usage of each configuration of the
    watch, against the labeled entries."""
    return await run_db_in_thread(service.get_evaluation, watch_id)


@router.put("/{watch_id}/labels/{entry_id}", status_code=204)
async def set_label(watch_id: int, entry_id: int, body: LabelRequest, auth: WriteAuth) -> Response:
    await run_db_in_thread(service.set_label, watch_id, entry_id, body.label, auth)
    return Response(status_code=204)


@router.delete("/{watch_id}/labels/{entry_id}", status_code=204)
async def remove_label(watch_id: int, entry_id: int, auth: WriteAuth) -> Response:
    await run_db_in_thread(service.remove_label, watch_id, entry_id, auth)
    return Response(status_code=204)
