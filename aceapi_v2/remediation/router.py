"""Remediation router (ACE API v2).

The alert pages' remediation dialog: the remediation targets of the selected alerts, queueing a
removal or a restore of them, and stopping or clearing a target's latest remediation.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security, status

from aceapi_v2.auth import ApiAuthResult
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.remediation import service
from aceapi_v2.remediation.schemas import (
    QueueRemediationsRequest,
    RemediationSummary,
    RemediationTargetRead,
    TargetLookupRequest,
)
from aceapi_v2.schemas.base import ListResponse
from aceapi_v2.sync import run_db_in_thread

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Security(get_current_auth)])


def _user_id(auth: ApiAuthResult) -> int:
    # a remediation is attributed to the analyst who asked for it
    if auth.auth_user_id is None:
        raise HTTPException(status_code=400, detail="remediating needs a caller that is a user")
    return auth.auth_user_id


@router.post("/targets/lookup", response_model=ListResponse[RemediationTargetRead])
async def lookup_targets(
    body: TargetLookupRequest,
    _: Annotated[ApiAuthResult, Depends(require_permission("remediation", "read"))],
) -> ListResponse[RemediationTargetRead]:
    """The remediation targets of the observables in these alerts, each with its latest remediation.

    A POST so that a long selection of alerts fits in the body. Each alert's analysis is loaded
    from disk."""
    return ListResponse(data=await run_db_in_thread(service.lookup_targets, body.alert_uuids))


@router.post("/remediations", response_model=ListResponse[RemediationSummary], status_code=status.HTTP_201_CREATED)
async def queue_remediations(
    body: QueueRemediationsRequest,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> ListResponse[RemediationSummary]:
    """Queues a removal or a restore of each target for the remediation service. Every target is
    checked before any is queued."""
    queued = await run_db_in_thread(service.queue_remediations, body.action, body.targets, _user_id(auth))
    logger.info("AUDIT: user %s queued %s remediations %s for %s", auth.auth_name, body.action.value,
                ",".join(str(remediation.id) for remediation in queued),
                ", ".join(f"{t.remediator} {t.observable_type} {t.observable_value!r}" for t in body.targets))
    return ListResponse(data=queued)


@router.post("/remediations/{remediation_id}/cancel", response_model=RemediationSummary)
async def cancel_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> RemediationSummary:
    """Stops a remediation that is queued or in progress. One that has completed is a 409: its
    result stands."""
    cancelled = await run_db_in_thread(service.cancel, remediation_id, _user_id(auth))
    logger.info("AUDIT: user %s cancelled remediation %s", auth.auth_name, remediation_id)
    return cancelled


@router.delete("/remediations/{remediation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_remediation(
    remediation_id: int,
    auth: Annotated[ApiAuthResult, Depends(require_permission("remediation", "write"))],
) -> None:
    """Deletes a remediation's record."""
    removed = await run_db_in_thread(service.delete, remediation_id)
    logger.info("AUDIT: user %s deleted remediation %s (%s, %s)", auth.auth_name, remediation_id,
                removed.action, removed.result or removed.status)
