"""POST /api/hunt/validate, the legacy route of hunt validation.

Kept until every validate-hunt CLI calls POST /api/v2/hunt/validate; both routes run
aceapi_v2/hunt/service.py and answer with the same body and status.
"""

from typing import Optional

from flask import g, request

from aceapi.audit import audit_event
from aceapi.auth import API_AUTH_TYPE_USER, api_auth_check
from aceapi.blueprints import hunt_bp
from aceapi.json import json_result
from aceapi_v2.hunt.audit import ValidationOutcome, audit_fields, failure_audit_fields
from aceapi_v2.hunt.service import validate_hunt as run_validation


def _requesting_user_id() -> Optional[int]:
    """The ACE user behind this request, or None when it was made with a config API key."""
    api_auth = g.get("api_auth")
    if api_auth is not None and api_auth.auth_type == API_AUTH_TYPE_USER:
        return api_auth.auth_user_id

    return None


@hunt_bp.route('/validate', methods=['POST'])
@api_auth_check("hunt", "write")
def validate_hunt():
    outcome = ValidationOutcome()
    try:
        # request.json raises for a body that is not JSON (415 or 400)
        run_validation(outcome, request.json, _requesting_user_id())
    except Exception as e:
        event, fields = failure_audit_fields(outcome, e)
        audit_event(event, **fields)
        raise

    event, fields = audit_fields(outcome)
    audit_event(event, **fields)
    return json_result(outcome.body), outcome.status
