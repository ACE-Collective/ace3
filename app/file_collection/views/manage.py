# vim: sw=4:ts=4:et:cc=120

from flask import render_template, session
from app.auth.permissions import require_permission
from app.blueprints import file_collection
from app.file_collection.constants import (
    FC_DEFAULT_SORT_FILTER,
    FC_DEFAULT_SORT_FILTER_DIRECTION,
    FC_PAGE_OFFSET,
    FC_PAGE_SIZE,
    FC_PAGE_SIZE_DEFAULT,
    FC_SORT_FILTER,
    FC_SORT_FILTER_DESC,
    FCH_PAGE_OFFSET,
    FCH_PAGE_SIZE,
    FCH_PAGE_SIZE_DEFAULT,
)
from app.file_collection.views.collections import get_current_pagination_size
from app.file_collection.views.history import get_current_pagination_size as get_current_history_pagination_size


def initialize_file_collection_session():
    """Initializes default session variables for file collection management if not already set."""
    if FC_PAGE_OFFSET not in session or FC_PAGE_SIZE not in session:
        reset_file_collection_pagination()
    if FCH_PAGE_OFFSET not in session or FCH_PAGE_SIZE not in session:
        reset_file_collection_history_pagination()
    if FC_SORT_FILTER not in session or FC_SORT_FILTER_DESC not in session:
        reset_file_collection_sort_filter()


def reset_file_collection_pagination():
    session[FC_PAGE_OFFSET] = 0
    if FC_PAGE_SIZE not in session:
        session[FC_PAGE_SIZE] = FC_PAGE_SIZE_DEFAULT


def reset_file_collection_history_pagination():
    session[FCH_PAGE_OFFSET] = 0
    if FCH_PAGE_SIZE not in session:
        session[FCH_PAGE_SIZE] = FCH_PAGE_SIZE_DEFAULT


def reset_file_collection_sort_filter():
    session[FC_SORT_FILTER] = FC_DEFAULT_SORT_FILTER.value
    session[FC_SORT_FILTER_DESC] = FC_DEFAULT_SORT_FILTER_DIRECTION.value


@file_collection.route('/file_collection/manage', methods=['GET'])
@require_permission('file_collection', 'read')
def manage():
    initialize_file_collection_session()

    return render_template(
        "file_collection/manage.html",
        page_size=get_current_pagination_size(),
        fch_page_size=get_current_history_pagination_size(),
    )
