"""Audit trail for the legacy API's hunt validation endpoint: the HUNT_AUDIT record of
aceapi_v2/hunt/audit.py, with the caller taken from the Flask request.
"""

from typing import Any, Optional

from flask import g, request

from aceapi_v2.hunt.audit import write_audit_record


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
    write_audit_record(
        event,
        user=auth.auth_name if auth else None,
        user_id=auth.auth_user_id if auth else None,
        key_id=auth.key_id if auth else None,
        key_name=auth.key_name if auth else None,
        src_ip=client_ip(),
        **fields,
    )
