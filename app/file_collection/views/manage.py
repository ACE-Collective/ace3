# vim: sw=4:ts=4:et:cc=120

from flask import render_template
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.auth.permissions import require_permission
from app.blueprints import file_collection
from saq.gui.filter_screens import FILE_COLLECTIONS_SCREEN


@file_collection.route('/file_collection/manage', methods=['GET'])
@require_permission('file_collection', 'read')
def manage():
    # the page is a shell: its script loads everything from /api/v2/file-collections, and its
    # filters and saved filters from /api/v2/filter-screens and /api/v2/saved-filters (screen
    # file_collections). The write controls follow has_permission('file_collection', 'write') in
    # the template, and the API enforces it regardless.
    #
    # A user new to the screen gets its default saved filters. This writes, which is why only
    # this real page render calls it.
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=FILE_COLLECTIONS_SCREEN.name)
    return render_template("file_collection/manage.html", file_collections_screen=FILE_COLLECTIONS_SCREEN.name)
