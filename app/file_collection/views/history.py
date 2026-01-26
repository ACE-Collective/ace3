# vim: sw=4:ts=4:et:cc=120

from flask import jsonify, render_template, request, session
from app.auth.permissions import require_permission
from app.blueprints import file_collection
from app.file_collection.constants import (
    FC_PAGE_OFFSET_BACKWARD,
    FC_PAGE_OFFSET_END,
    FC_PAGE_OFFSET_FORWARD,
    FC_PAGE_OFFSET_START,
    FCH_PAGE_OFFSET,
    FCH_PAGE_SIZE,
    FCH_PAGE_SIZE_DEFAULT,
)
from saq.database.model import FileCollectionHistory
from saq.database.pool import get_db


def get_current_pagination_offset() -> int:
    if FCH_PAGE_OFFSET not in session:
        return 0

    return session[FCH_PAGE_OFFSET]


def get_current_pagination_size() -> int:
    if FCH_PAGE_SIZE not in session:
        return FCH_PAGE_SIZE_DEFAULT

    return session[FCH_PAGE_SIZE]


def get_total_collection_history_count(file_collection_id: int) -> int:
    return (
        get_db()
        .query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == file_collection_id)
        .count()
    )


@file_collection.route("/file_collection/history/<int:file_collection_id>", methods=["GET"])
@require_permission("file_collection", "read")
def history(file_collection_id: int):
    history = (
        get_db()
        .query(FileCollectionHistory)
        .filter(FileCollectionHistory.file_collection_id == file_collection_id)
        .order_by(FileCollectionHistory.insert_date.desc())
        .offset(get_current_pagination_offset())
        .limit(get_current_pagination_size())
        .all()
    )
    return render_template("file_collection/history.html", history=history)


@file_collection.route("/file_collection/history/<int:file_collection_id>/page", methods=["GET", "POST"])
@require_permission("file_collection", "read")
def history_page(file_collection_id: int):
    # Cache the count within the request to avoid redundant queries
    total = get_total_collection_history_count(file_collection_id)
    page_size = get_current_pagination_size()

    if request.method == "GET":
        return jsonify({
            "offset": get_current_pagination_offset(),
            "size": page_size,
            "total": total
        })
    elif request.method == "POST":
        if "size" in request.json:
            # sanitize page size
            session[FCH_PAGE_SIZE] = max(1, min(1000, int(request.json["size"])))
            page_size = session[FCH_PAGE_SIZE]

        if "direction" in request.json:
            if request.json["direction"] == FC_PAGE_OFFSET_START:
                session[FCH_PAGE_OFFSET] = 0
            elif request.json["direction"] == FC_PAGE_OFFSET_BACKWARD:
                session[FCH_PAGE_OFFSET] = max(0, session[FCH_PAGE_OFFSET] - page_size)
            elif request.json["direction"] == FC_PAGE_OFFSET_FORWARD:
                session[FCH_PAGE_OFFSET] = max(
                    0,
                    min(
                        total - page_size,
                        session[FCH_PAGE_OFFSET] + page_size
                    )
                )
            elif request.json["direction"] == FC_PAGE_OFFSET_END:
                session[FCH_PAGE_OFFSET] = max(0, total - page_size)

        return jsonify({
            "offset": get_current_pagination_offset(),
            "size": page_size,
            "total": total
        })
