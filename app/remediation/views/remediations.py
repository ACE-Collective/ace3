import logging
import re
from flask import abort, jsonify, render_template, request, session
from flask_login import current_user
from sqlalchemy import Column
from app.auth.permissions import require_permission
from app.blueprints import remediation
from app.remediation.constants import (
    R_DEFAULT_SORT_FILTER,
    R_DEFAULT_SORT_FILTER_DIRECTION,
    R_FILTER_ACTION,
    R_FILTER_ALL,
    R_FILTER_ANALYST,
    R_FILTER_ID,
    R_FILTER_REMEDIATOR,
    R_FILTER_RESULT,
    R_FILTER_STATUS,
    R_FILTER_TYPE,
    R_FILTER_VALUE,
    R_PAGE_OFFSET,
    R_PAGE_OFFSET_BACKWARD,
    R_PAGE_OFFSET_END,
    R_PAGE_OFFSET_FORWARD,
    R_PAGE_OFFSET_START,
    R_PAGE_SIZE,
    R_PAGE_SIZE_DEFAULT,
    R_SORT_FILTER,
    R_SORT_FILTER_DESC,
    RemediationSortFilter,
    SortFilterDirection,
)
from saq.database.model import Remediation, User
from saq.database.pool import get_db
from saq.observables.generator import create_observable
from saq.remediation.util import (
    cancel_remediations,
    delete_remediations,
    get_distinct_analyst_names,
    get_distinct_remediation_actions,
    get_distinct_remediation_statuses,
    get_distinct_remediation_types,
    get_distinct_remediator_names,
    get_distinct_remediator_statuses,
    mass_remediate_targets,
    restore_remediations,
    retry_remediations,
)
from saq.remediation.target import get_observable_remediation_interfaces
from saq.remediation.types import RemediationAction


def get_current_pagination_offset() -> int:
    if R_PAGE_OFFSET not in session:
        return 0

    return session[R_PAGE_OFFSET]


def get_current_pagination_size() -> int:
    if R_PAGE_SIZE not in session:
        return R_PAGE_SIZE_DEFAULT

    return session[R_PAGE_SIZE]


def get_total_remediations_count() -> int:
    return get_db().query(Remediation).count()


def get_current_sort_filter() -> RemediationSortFilter:
    if R_SORT_FILTER not in session:
        return R_DEFAULT_SORT_FILTER

    try:
        return RemediationSortFilter(session[R_SORT_FILTER])
    except ValueError:
        logging.warning(
            f"Invalid sort filter: {session[R_SORT_FILTER]}, using default: {R_DEFAULT_SORT_FILTER}"
        )
        session[R_SORT_FILTER] = R_DEFAULT_SORT_FILTER.value
        return R_DEFAULT_SORT_FILTER


def get_current_sort_filter_direction() -> SortFilterDirection:
    if R_SORT_FILTER_DESC not in session:
        return R_DEFAULT_SORT_FILTER_DIRECTION

    try:
        return SortFilterDirection(session[R_SORT_FILTER_DESC])
    except ValueError:
        logging.warning(
            f"Invalid sort filter direction: {session[R_SORT_FILTER_DESC]}, using default: {R_DEFAULT_SORT_FILTER_DIRECTION}"
        )
        session[R_SORT_FILTER_DESC] = R_DEFAULT_SORT_FILTER_DIRECTION.value
        return R_DEFAULT_SORT_FILTER_DIRECTION


def get_sort_filter_column_by_name(sort_filter: RemediationSortFilter) -> Column:
    """Translate sort name to the column to actually sort by."""
    return {
        RemediationSortFilter.ID: Remediation.id,
        RemediationSortFilter.REMEDIATOR: Remediation.name,
        RemediationSortFilter.TYPE: Remediation.type,
        RemediationSortFilter: Remediation.key,
        RemediationSortFilter.ANALYST: Remediation.user_id,
        RemediationSortFilter.ACTION: Remediation.action,
        RemediationSortFilter.STATUS: Remediation.status,
        RemediationSortFilter.RESULT: Remediation.result,
    }.get(
        sort_filter, Remediation.id
    )  # default to id


def remediate_target(observable_type: str, observable_value: str) -> int:
    """Submits the given observable type and value for remediation. Returns the number of remediations queued."""
    total = 0
    target_observable = create_observable(observable_type, observable_value)
    if not target_observable:
        logging.error(
            f"failed to create observable for remediation: {observable_type} {observable_value}"
        )
        return total

    for interface in get_observable_remediation_interfaces(observable_type):
        targets = interface.get_remediation_targets(target_observable)
        for target in targets:
            target.queue_remediation(RemediationAction.REMOVE, current_user.id)
            total += 1

    return total


@remediation.route(
    "/remediation/remediations", methods=["POST", "PUT", "DELETE", "PATCH"]
)
@require_permission("remediation", "read")
def remediations():
    if request.method == "POST":
        sort_filter = get_current_sort_filter()
        sort_column = get_sort_filter_column_by_name(sort_filter)
        sort_direction = get_current_sort_filter_direction()

        filter_values = request.json.get("filter_values")

        # ensure all filter values are set and defalt to empty strings
        for filter_name in R_FILTER_ALL:
            filter_values[filter_name] = filter_values.get(filter_name, "") or ""

        remediator_names = get_distinct_remediator_names()
        remediation_types = get_distinct_remediation_types()
        remediation_actions = get_distinct_remediation_actions()
        remediation_statuses = get_distinct_remediation_statuses()
        analyst_names = get_distinct_analyst_names()
        remediator_statuses = get_distinct_remediator_statuses()

        if sort_direction == SortFilterDirection.DESC:
            sort_column = sort_column.desc()
        else:
            sort_column = sort_column.asc()

        query = get_db().query(Remediation)
        if filter_values.get(R_FILTER_ID):
            query = query.filter(Remediation.id.ilike(f"%{filter_values.get(R_FILTER_ID)}%"))
        if filter_values.get(R_FILTER_REMEDIATOR):
            query = query.filter(Remediation.name.ilike(f"%{filter_values.get(R_FILTER_REMEDIATOR)}%"))
        if filter_values.get(R_FILTER_TYPE):
            query = query.filter(Remediation.type.ilike(f"%{filter_values.get(R_FILTER_TYPE)}%"))
        if filter_values.get(R_FILTER_VALUE):
            query = query.filter(Remediation.key.ilike(f"%{filter_values.get(R_FILTER_VALUE)}%"))
        if filter_values.get(R_FILTER_ANALYST):
            subquery = get_db().query(User.id).filter(User.display_name.ilike(f"%{filter_values.get(R_FILTER_ANALYST)}%"))
            query = query.filter(Remediation.user_id.in_(subquery))
        if filter_values.get(R_FILTER_ACTION):
            query = query.filter(Remediation.action.ilike(f"%{filter_values.get(R_FILTER_ACTION)}%"))
        if filter_values.get(R_FILTER_STATUS):
            query = query.filter(Remediation.status.ilike(f"%{filter_values.get(R_FILTER_STATUS)}%"))
        if filter_values.get(R_FILTER_RESULT):
            query = query.filter(Remediation.result.ilike(f"%{filter_values.get(R_FILTER_RESULT)}%"))

        remediations = (
            query
            .order_by(sort_column)
            .offset(get_current_pagination_offset())
            .limit(get_current_pagination_size())
            .all()
        )
        return render_template(
            "remediation/remediations.html",
            remediations=remediations,
            sort_filter=sort_filter.value,
            sort_filter_direction=sort_direction.value,
            remediator_names=remediator_names,
            remediation_types=remediation_types,
            remediation_actions=remediation_actions,
            remediation_statuses=remediation_statuses,
            analyst_names=analyst_names,
            remediator_statuses=remediator_statuses,
            filter_values=filter_values,
        )
    elif request.method == "PUT":
        observable_type = request.json["observable_type"]
        observable_value = request.json["observable_value"]
        count = remediate_target(observable_type, observable_value)
        return jsonify({"count": count}), 200
    elif request.method == "PATCH":
        remediation_ids = request.json["remediation_ids"]
        action = request.json["action"]
        if action not in ["cancel", "retry", "restore"]:
            abort(
                400,
                f"Invalid action: {action}, possible values: cancel, retry, restore",
            )

        if action == "cancel":
            update_count = cancel_remediations(
                remediation_ids,
                comment=request.json.get("comment"),
                user_id=current_user.id,
            )
        elif action == "retry":
            update_count = retry_remediations(remediation_ids)
        elif action == "restore":
            update_count = restore_remediations(remediation_ids)

        return jsonify({"count": update_count}), 200

    elif request.method == "DELETE":
        remediation_ids = request.json["remediation_ids"]
        delete_count = delete_remediations(remediation_ids)
        return jsonify({"count": delete_count}), 200
    else:
        raise ValueError(f"Invalid request method: {request.method}")


@remediation.route("/remediation/remediations/page", methods=["GET", "POST"])
@require_permission("remediation", "read")
def remediations_page():
    if request.method == "GET":
        return jsonify(
            {
                "offset": get_current_pagination_offset(),
                "size": get_current_pagination_size(),
                "total": get_total_remediations_count(),
            }
        )
    elif request.method == "POST":
        if "size" in request.json:
            # sanitize page size
            session[R_PAGE_SIZE] = max(1, min(1000, int(request.json["size"])))

        if "direction" in request.json:
            if request.json["direction"] == R_PAGE_OFFSET_START:
                session[R_PAGE_OFFSET] = 0
            elif request.json["direction"] == R_PAGE_OFFSET_BACKWARD:
                session[R_PAGE_OFFSET] = max(
                    0, session[R_PAGE_OFFSET] - get_current_pagination_size()
                )
            elif request.json["direction"] == R_PAGE_OFFSET_FORWARD:
                session[R_PAGE_OFFSET] = max(
                    0,
                    min(
                        get_total_remediations_count() - get_current_pagination_size(),
                        session[R_PAGE_OFFSET] + get_current_pagination_size(),
                    ),
                )
            elif request.json["direction"] == R_PAGE_OFFSET_END:
                session[R_PAGE_OFFSET] = max(
                    0, get_total_remediations_count() - get_current_pagination_size()
                )

        return jsonify(
            {
                "offset": get_current_pagination_offset(),
                "size": get_current_pagination_size(),
                "total": get_total_remediations_count(),
            }
        )


@remediation.route("/remediation/remediations/sort", methods=["POST"])
@require_permission("remediation", "read")
def remediations_sort():
    if request.method == "POST":
        sort_direction_str = request.json.get("sort_direction")
        if sort_direction_str:
            try:
                sort_direction = SortFilterDirection(sort_direction_str)
            except ValueError:
                abort(
                    400,
                    f"Invalid sort direction: {sort_direction_str}, possible values: {', '.join([sort_direction.value for sort_direction in SortFilterDirection])}",
                )

            session[R_SORT_FILTER_DESC] = sort_direction.value

        sort_filter_str = request.json.get("sort_filter")
        if sort_filter_str:
            try:
                sort_filter = RemediationSortFilter(sort_filter_str)
            except ValueError:
                abort(
                    400,
                    f"Invalid sort filter: {sort_filter_str}, possible values: {', '.join([sort_filter.value for sort_filter in RemediationSortFilter])}",
                )

            session[R_SORT_FILTER] = sort_filter.value

        return jsonify({"success": True}), 200
    else:
        raise ValueError(f"Invalid request method: {request.method}")


@remediation.route("/remediation/mass_remediate", methods=["POST"])
@require_permission("remediation", "read")
def mass_remediate():
    observable_type = request.json["observable_type"]
    observable_values_raw = request.json["observable_values"]
    observable_values = [
        line for line in re.split(r"\r\n|\r|\n", observable_values_raw) if line.strip()
    ]
    count = mass_remediate_targets(observable_type, observable_values, current_user.id)
    return jsonify({"count": count}), 200
