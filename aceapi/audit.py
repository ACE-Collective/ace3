"""Audit trail for the legacy API's hunt validation endpoint.

One JSON line per request on the ace.hunt_audit logger, in the shape the AI investigation API
uses for its own trail (aceapi_ai/audit.py). POST /api/hunt/validate runs data-source queries,
sandboxed scripts and alert creation for anyone holding a hunt:write key, which includes an
analyst's AI-scoped key, so the point of the trail is reconstructing what each key asked for. The
container's log pipeline ships it off-box like any other log line; the caller writes it outside
suppress_external_logging(), which would otherwise drop it.
"""

import json
import logging
from typing import Any, Optional

from flask import g, request

audit_logger = logging.getLogger("ace.hunt_audit")


def client_ip() -> Optional[str]:
    # nginx sets both; X-Real-IP is the direct client, X-Forwarded-For may carry a chain
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr


def audit_event(event: str, **fields: Any) -> None:
    auth = g.get("api_auth")
    record = {
        "event": event,
        "user": auth.auth_name if auth else None,
        "user_id": auth.auth_user_id if auth else None,
        "key_id": auth.key_id if auth else None,
        "key_name": auth.key_name if auth else None,
        "src_ip": client_ip(),
    }
    record.update(fields)
    audit_logger.info("HUNT_AUDIT %s", json.dumps(record, default=str))
