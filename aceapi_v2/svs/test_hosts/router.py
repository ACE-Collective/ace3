"""SVS test hosts router for ACE API v2 (docs/SVS_RUNS.md, *Test hosts*; docs/SVS_API.md).

The hosts SVS test runs may target. Reading them needs svs:run_read; adding, changing and removing
them needs svs:admin, and each change is an AUDIT line.
"""

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, Security

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.common.listing import LISTING_MAX_PAGE_SIZE, csv_response, ndjson_response, run_listing, start_export
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.responses import CsvStreamResponse, NdjsonStreamResponse
from aceapi_v2.svs.preconditions import WritePrecondition
from aceapi_v2.svs.test_hosts import service
from aceapi_v2.svs.test_hosts.schemas import TestHost, TestHostPage, TestHostRequest
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])

ChangedSinceParam = Annotated[datetime | None, Query(
    description="only test hosts added or changed at or after this time (UTC if no offset is given)")]


@router.get("/", response_model=TestHostPage)
async def list_test_hosts(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    changed_since: ChangedSinceParam = None,
    cursor: Annotated[str | None, Query(description="the next_cursor of the previous page")] = None,
    limit: Annotated[int, Query(ge=1, le=LISTING_MAX_PAGE_SIZE)] = 100,
) -> TestHostPage:
    """The test hosts, by host name. Follow next_cursor until it is null."""
    rows, next_cursor = await run_listing(service.fetch_page, changed_since, cursor, limit)
    return TestHostPage(data=rows, next_cursor=next_cursor)


@router.get("/export/ndjson", response_class=NdjsonStreamResponse)
async def export_test_hosts_ndjson(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    changed_since: ChangedSinceParam = None,
) -> NdjsonStreamResponse:
    """Stream every test host as NDJSON, one TestHost per line."""
    export = await start_export(service.fetch_page, changed_since, what="svs test host")
    return ndjson_response(export, "svs-test-hosts.ndjson")


@router.get("/export/csv", response_class=CsvStreamResponse)
async def export_test_hosts_csv(
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
    changed_since: ChangedSinceParam = None,
) -> CsvStreamResponse:
    """Stream every test host as CSV (usernames and ips joined with ",")."""
    export = await start_export(service.fetch_page, changed_since, what="svs test host")
    return csv_response(export, service.hosts_to_csv, "svs-test-hosts.csv")


@router.post("/", response_model=TestHost, status_code=201)
async def create_test_host(
    body: TestHostRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
) -> TestHost:
    """Add a test host: 409 when its short name is already one, 422 for a field that can't be used."""
    return await run_db_in_thread(service.create_test_host, body, auth.auth_user_id, auth.auth_name)


@router.get("/{host_id}", response_model=TestHost)
async def get_test_host(
    host_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "run_read"))],
) -> TestHost:
    return await run_db_in_thread(service.get_test_host, host_id)


@router.put("/{host_id}", response_model=TestHost)
async def update_test_host(
    host_id: int,
    body: TestHostRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
    precondition: WritePrecondition,
) -> TestHost:
    """Replace a test host's fields. 412 when an If-Match or If-None-Match precondition no longer holds (docs/SVS_API.md, *Conflicting writes*)."""
    return await run_db_in_thread(service.update_test_host, host_id, body, auth.auth_name, precondition)


@router.delete("/{host_id}", status_code=204)
async def delete_test_host(
    host_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("svs", "admin"))],
) -> Response:
    """Remove a test host. Runs already registered keep their targets."""
    await run_db_in_thread(service.delete_test_host, host_id, auth.auth_name)
    return Response(status_code=204)
