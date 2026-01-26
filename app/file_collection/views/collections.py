# vim: sw=4:ts=4:et:cc=120

import logging
from flask import abort, jsonify, render_template, request, session
from flask_login import current_user
from sqlalchemy import Column
from app.auth.permissions import require_permission
from app.blueprints import file_collection
from app.file_collection.constants import (
    FC_DEFAULT_SORT_FILTER,
    FC_DEFAULT_SORT_FILTER_DIRECTION,
    FC_FILTER_COLLECTOR,
    FC_FILTER_ALL,
    FC_FILTER_ID,
    FC_FILTER_RESULT,
    FC_FILTER_STATUS,
    FC_FILTER_TYPE,
    FC_FILTER_VALUE,
    FC_PAGE_OFFSET,
    FC_PAGE_OFFSET_BACKWARD,
    FC_PAGE_OFFSET_END,
    FC_PAGE_OFFSET_FORWARD,
    FC_PAGE_OFFSET_START,
    FC_PAGE_SIZE,
    FC_PAGE_SIZE_DEFAULT,
    FC_SORT_FILTER,
    FC_SORT_FILTER_DESC,
    FileCollectionSortFilter,
    SortFilterDirection,
)
from saq.configuration import get_config
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.file_collection.database import (
    cancel_file_collection,
    delete_file_collection,
    retry_file_collection,
)
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus


def get_current_pagination_offset() -> int:
    if FC_PAGE_OFFSET not in session:
        return 0

    return session[FC_PAGE_OFFSET]


def get_current_pagination_size() -> int:
    if FC_PAGE_SIZE not in session:
        return FC_PAGE_SIZE_DEFAULT

    return session[FC_PAGE_SIZE]


def get_total_collections_count() -> int:
    return get_db().query(FileCollection).count()


def get_current_sort_filter() -> FileCollectionSortFilter:
    if FC_SORT_FILTER not in session:
        return FC_DEFAULT_SORT_FILTER

    try:
        return FileCollectionSortFilter(session[FC_SORT_FILTER])
    except ValueError:
        logging.warning(
            f"Invalid sort filter: {session[FC_SORT_FILTER]}, using default: {FC_DEFAULT_SORT_FILTER}"
        )
        session[FC_SORT_FILTER] = FC_DEFAULT_SORT_FILTER.value
        return FC_DEFAULT_SORT_FILTER


def get_current_sort_filter_direction() -> SortFilterDirection:
    if FC_SORT_FILTER_DESC not in session:
        return FC_DEFAULT_SORT_FILTER_DIRECTION

    try:
        return SortFilterDirection(session[FC_SORT_FILTER_DESC])
    except ValueError:
        logging.warning(
            f"Invalid sort filter direction: {session[FC_SORT_FILTER_DESC]}, using default: {FC_DEFAULT_SORT_FILTER_DIRECTION}"
        )
        session[FC_SORT_FILTER_DESC] = FC_DEFAULT_SORT_FILTER_DIRECTION.value
        return FC_DEFAULT_SORT_FILTER_DIRECTION


def get_sort_filter_column_by_name(sort_filter: FileCollectionSortFilter) -> Column:
    """Translate sort name to the column to actually sort by."""
    return {
        FileCollectionSortFilter.ID: FileCollection.id,
        FileCollectionSortFilter.COLLECTOR: FileCollection.name,
        FileCollectionSortFilter.TYPE: FileCollection.type,
        FileCollectionSortFilter.VALUE: FileCollection.key,
        FileCollectionSortFilter.STATUS: FileCollection.status,
        FileCollectionSortFilter.RESULT: FileCollection.result,
    }.get(
        sort_filter, FileCollection.id
    )  # default to id


@file_collection.route(
    "/file_collection/collections", methods=["POST", "PATCH", "DELETE"]
)
@require_permission("file_collection", "read")
def collections():
    if request.method == "POST":
        sort_filter = get_current_sort_filter()
        sort_column = get_sort_filter_column_by_name(sort_filter)
        sort_direction = get_current_sort_filter_direction()

        filter_values = request.json.get("filter_values")

        # ensure all filter values are set and default to empty strings
        for filter_name in FC_FILTER_ALL:
            filter_values[filter_name] = filter_values.get(filter_name, "") or ""

        # Use enums/config for filter dropdowns instead of DISTINCT queries (performance optimization)
        collector_names = [c.name for c in get_config().file_collectors]
        collection_types = list(set(c.observable_type for c in get_config().file_collectors))
        collection_statuses = [s.value for s in FileCollectionStatus]
        collection_results = [r.value for r in FileCollectorStatus]

        if sort_direction == SortFilterDirection.DESC:
            sort_column = sort_column.desc()
        else:
            sort_column = sort_column.asc()

        query = get_db().query(FileCollection)

        # ID filter - use exact match for integer
        if filter_values.get(FC_FILTER_ID):
            try:
                query = query.filter(FileCollection.id == int(filter_values.get(FC_FILTER_ID)))
            except ValueError:
                pass  # Invalid ID, filter will return no results naturally

        # Collector name - use exact match (selecting from dropdown)
        if filter_values.get(FC_FILTER_COLLECTOR):
            query = query.filter(FileCollection.name == filter_values.get(FC_FILTER_COLLECTOR))

        # Type - use exact match (selecting from dropdown)
        if filter_values.get(FC_FILTER_TYPE):
            query = query.filter(FileCollection.type == filter_values.get(FC_FILTER_TYPE))

        # Value - keep ILIKE for substring search (this is a user-typed free text field)
        if filter_values.get(FC_FILTER_VALUE):
            query = query.filter(FileCollection.key.ilike(f"%{filter_values.get(FC_FILTER_VALUE)}%"))

        # Status - use exact match (enum field)
        if filter_values.get(FC_FILTER_STATUS):
            query = query.filter(FileCollection.status == filter_values.get(FC_FILTER_STATUS))

        # Result - use exact match (enum field)
        if filter_values.get(FC_FILTER_RESULT):
            query = query.filter(FileCollection.result == filter_values.get(FC_FILTER_RESULT))

        # Get count with filters applied, before pagination (eliminates separate API call)
        total_count = query.count()

        file_collections = (
            query
            .order_by(sort_column)
            .offset(get_current_pagination_offset())
            .limit(get_current_pagination_size())
            .all()
        )
        return render_template(
            "file_collection/collections.html",
            collections=file_collections,
            sort_filter=sort_filter.value,
            sort_filter_direction=sort_direction.value,
            collector_names=collector_names,
            collection_types=collection_types,
            collection_statuses=collection_statuses,
            collection_results=collection_results,
            filter_values=filter_values,
            total_count=total_count,
            page_offset=get_current_pagination_offset(),
            page_size=get_current_pagination_size(),
        )
    elif request.method == "PATCH":
        collection_ids = request.json["collection_ids"]
        action = request.json["action"]
        if action not in ["cancel", "retry"]:
            abort(
                400,
                f"Invalid action: {action}, possible values: cancel, retry",
            )

        update_count = 0
        if action == "cancel":
            for collection_id in collection_ids:
                if cancel_file_collection(int(collection_id)):
                    update_count += 1
        elif action == "retry":
            for collection_id in collection_ids:
                if retry_file_collection(int(collection_id)):
                    update_count += 1

        return jsonify({"count": update_count}), 200

    elif request.method == "DELETE":
        collection_ids = request.json["collection_ids"]
        delete_count = 0
        for collection_id in collection_ids:
            if delete_file_collection(int(collection_id)):
                delete_count += 1
        return jsonify({"count": delete_count}), 200
    else:
        raise ValueError(f"Invalid request method: {request.method}")


@file_collection.route("/file_collection/collections/page", methods=["GET", "POST"])
@require_permission("file_collection", "read")
def collections_page():
    if request.method == "GET":
        return jsonify(
            {
                "offset": get_current_pagination_offset(),
                "size": get_current_pagination_size(),
                "total": get_total_collections_count(),
            }
        )
    elif request.method == "POST":
        if "size" in request.json:
            # sanitize page size
            session[FC_PAGE_SIZE] = max(1, min(1000, int(request.json["size"])))

        if "direction" in request.json:
            if request.json["direction"] == FC_PAGE_OFFSET_START:
                session[FC_PAGE_OFFSET] = 0
            elif request.json["direction"] == FC_PAGE_OFFSET_BACKWARD:
                session[FC_PAGE_OFFSET] = max(
                    0, session[FC_PAGE_OFFSET] - get_current_pagination_size()
                )
            elif request.json["direction"] == FC_PAGE_OFFSET_FORWARD:
                session[FC_PAGE_OFFSET] = max(
                    0,
                    min(
                        get_total_collections_count() - get_current_pagination_size(),
                        session[FC_PAGE_OFFSET] + get_current_pagination_size(),
                    ),
                )
            elif request.json["direction"] == FC_PAGE_OFFSET_END:
                session[FC_PAGE_OFFSET] = max(
                    0, get_total_collections_count() - get_current_pagination_size()
                )

        return jsonify(
            {
                "offset": get_current_pagination_offset(),
                "size": get_current_pagination_size(),
                "total": get_total_collections_count(),
            }
        )


@file_collection.route("/file_collection/collections/sort", methods=["POST"])
@require_permission("file_collection", "read")
def collections_sort():
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

            session[FC_SORT_FILTER_DESC] = sort_direction.value

        sort_filter_str = request.json.get("sort_filter")
        if sort_filter_str:
            try:
                sort_filter = FileCollectionSortFilter(sort_filter_str)
            except ValueError:
                abort(
                    400,
                    f"Invalid sort filter: {sort_filter_str}, possible values: {', '.join([sort_filter.value for sort_filter in FileCollectionSortFilter])}",
                )

            session[FC_SORT_FILTER] = sort_filter.value

        return jsonify({"success": True}), 200
    else:
        raise ValueError(f"Invalid request method: {request.method}")
