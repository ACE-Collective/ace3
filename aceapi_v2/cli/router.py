"""CLI execution router for ACE API v2 (docs/GUI_CLI.md).

Runs ACE CLI commands on one or more nodes for the Admin -> CLI page. A POST records one run per
node and asks each node to start its own; the runs then proceed in the background on those nodes,
and GET /cli/executions/{id} follows one to the end.
"""

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.cli import service
from aceapi_v2.cli.schemas import CliExecutionCreate, CliExecutionListPage, CliExecutionRead
from aceapi_v2.common.listing import run_listing
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.schemas import ListResponse
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

CliPermission = Annotated[ApiAuthResult, Depends(require_permission("cli", "execute"))]


@router.post("/executions", response_model=ListResponse[CliExecutionRead], status_code=202)
async def create_execution(body: CliExecutionCreate, auth: CliPermission) -> ListResponse[CliExecutionRead]:
    """Run `ace <command>` on each of node_ids (the primary node by default), once per node.

    Answers once every node has been asked to start, with one execution per node: a node that could
    not be asked is already failed. Follow the others with GET /cli/executions/{id}."""
    try:
        argv = service.parse_command(body.command)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    if auth.auth_user_id is None:
        # a config key has no user to record the run against
        raise HTTPException(status_code=403, detail="cli executions need a user's credentials")

    execution_ids = await run_db_in_thread(
        service.create_executions, auth.auth_user_id, auth.auth_name, argv, body.node_ids, body.timeout_seconds)
    await asyncio.gather(*(run_db_in_thread(service.dispatch_execution, i) for i in execution_ids))
    return ListResponse(data=await run_db_in_thread(service.get_executions, execution_ids))


@router.get("/executions", response_model=CliExecutionListPage)
async def list_executions(
    auth: CliPermission,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CliExecutionListPage:
    """Every recorded run, newest first, without its output."""
    rows, next_cursor = await run_listing(service.fetch_execution_page, cursor, limit)
    return CliExecutionListPage(data=rows, next_cursor=next_cursor)


@router.get("/executions/{execution_id}", response_model=CliExecutionRead)
async def get_execution(execution_id: int, auth: CliPermission) -> CliExecutionRead:
    """One run, with its output so far."""
    execution = await run_db_in_thread(service.get_execution, execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="cli execution not found")
    return execution
