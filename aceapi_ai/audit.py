"""Audit trail for the AI investigation API.

One JSON line per operation on the ace.ai_audit logger. The container's log pipeline
(FLUENT_BIT_TAG ace-api-ai) ships these off-box; nothing reachable with an ai:* key can disable
them. Full query text is recorded deliberately -- reconstructing what an agent asked for (and how
much it was shown) is the point of the trail.
"""

import json
import logging
from typing import Any

from fastapi import Request

from aceapi_v2.auth.schemas import ApiAuthResult

audit_logger = logging.getLogger("ace.ai_audit")


def client_ip(request: Request) -> str | None:
    # nginx sets both; X-Real-IP is the direct client, X-Forwarded-For may carry a chain
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else None


def audit_event(event: str, auth: ApiAuthResult, request: Request, **fields: Any) -> None:
    record = {
        "event": event,
        "user": auth.auth_name,
        "user_id": auth.auth_user_id,
        "key_id": auth.key_id,
        "key_name": auth.key_name,
        "src_ip": client_ip(request),
    }
    record.update(fields)
    audit_logger.info("AI_AUDIT %s", json.dumps(record, default=str))
