from flask import jsonify, render_template, request, session
from app.auth.permissions import require_permission
from app.blueprints import remediation
from app.remediation.constants import R_PAGE_OFFSET_BACKWARD, R_PAGE_OFFSET_END, R_PAGE_OFFSET_FORWARD, R_PAGE_OFFSET_START, RH_PAGE_OFFSET, RH_PAGE_SIZE, RH_PAGE_SIZE_DEFAULT
from saq.database.model import RemediationHistory
from saq.database.pool import get_db


def get_current_pagination_offset() -> int:
    if RH_PAGE_OFFSET not in session:
        return 0

    return session[RH_PAGE_OFFSET]


def get_current_pagination_size() -> int:
    if RH_PAGE_SIZE not in session:
        return RH_PAGE_SIZE_DEFAULT

    return session[RH_PAGE_SIZE]


def get_total_remediation_history_count(remediation_id: int) -> int:
    return (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .count()
    )


@remediation.route("/remediation/history/<int:remediation_id>", methods=["GET"])
@require_permission("remediation", "read")
def history(remediation_id: int):
    history = (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .order_by(RemediationHistory.insert_date.desc())
        .offset(get_current_pagination_offset())
        .limit(get_current_pagination_size())
        .all()
    )
    return render_template("remediation/history.html", history=history)

@remediation.route("/remediation/history/<int:remediation_id>/page", methods=["GET", "POST"])
@require_permission("remediation", "read")
def history_page(remediation_id: int):
    if request.method == "GET":
        return jsonify({"offset": get_current_pagination_offset(), "size": get_current_pagination_size(), "total": get_total_remediation_history_count(remediation_id)})
    elif request.method == "POST":
        if "size" in request.json:
            # sanitize page size
            session[RH_PAGE_SIZE] = max(1, min(1000, int(request.json["size"])))

        if "direction" in request.json:
            if request.json["direction"] == R_PAGE_OFFSET_START:
                session[RH_PAGE_OFFSET] = 0
            elif request.json["direction"] == R_PAGE_OFFSET_BACKWARD:
                session[RH_PAGE_OFFSET] = max(0, session[RH_PAGE_OFFSET] - get_current_pagination_size())
            elif request.json["direction"] == R_PAGE_OFFSET_FORWARD:
                session[RH_PAGE_OFFSET] = max(0, min(get_total_remediation_history_count(remediation_id) - get_current_pagination_size(), session[RH_PAGE_OFFSET] + get_current_pagination_size()))
            elif request.json["direction"] == R_PAGE_OFFSET_END:
                session[RH_PAGE_OFFSET] = max(0, get_total_remediation_history_count(remediation_id) - get_current_pagination_size())

        return jsonify({"offset": get_current_pagination_offset(), "size": get_current_pagination_size(), "total": get_total_remediation_history_count(remediation_id)})