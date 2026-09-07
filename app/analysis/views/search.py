"""The manage-page search box and the "similar alerts" action.

The active search lives in the session as a small spec, either
    {"mode": "query", "query": "<text>"}
or  {"mode": "similar", "alert_uuid": "<uuid>", "description": "<alert description>"}
and build_manage_list_context() (manage.py) runs it. An empty query clears the search.
"""

from flask import flash, redirect, request, session, url_for

from app.auth.permissions import require_permission
from app.blueprints import analysis
from app.analysis.views.session.filters import reset_pagination
from saq.database.model import Alert
from saq.database.pool import get_db

SEARCH_MODE_QUERY = "query"
SEARCH_MODE_SIMILAR = "similar"


def get_search_spec():
    """The active search spec, or None. Tolerates the pre-dict session value (a bare string)."""
    spec = session.get("search")
    if not spec:
        return None

    if isinstance(spec, str):
        return {"mode": SEARCH_MODE_QUERY, "query": spec}

    if isinstance(spec, dict) and spec.get("mode") in (SEARCH_MODE_QUERY, SEARCH_MODE_SIMILAR):
        return spec

    return None


def set_search_spec(spec) -> None:
    session["search"] = spec
    reset_pagination()


@analysis.route('/search', methods=['POST'])
@require_permission('alert', 'read')
def search():
    # POST-only: this endpoint mutates session state.
    query = (request.form.get("search") or "").strip()
    set_search_spec({"mode": SEARCH_MODE_QUERY, "query": query} if query else None)
    # return empty page
    return ('', 204)


@analysis.route('/search/similar/<alert_uuid>', methods=['GET'])
@require_permission('alert', 'read')
def search_similar(alert_uuid):
    """Shows the alerts most similar to alert_uuid on the manage page."""
    row = get_db().query(Alert.uuid, Alert.description).filter(Alert.uuid == alert_uuid).one_or_none()
    if row is None:
        flash("alert not found")
        return redirect(url_for('analysis.manage'))

    set_search_spec({"mode": SEARCH_MODE_SIMILAR, "alert_uuid": row.uuid, "description": row.description or row.uuid})
    return redirect(url_for('analysis.manage'))
