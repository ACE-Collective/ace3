import json
import logging

from flask import jsonify, redirect, render_template, request, session, url_for
from flask_login import login_required
from pydantic import ValidationError

from app.analysis.views.session.filters import (
    _reset_filters,
    apply_temporary_filter,
    get_effective_filters,
    get_existing_filter,
    getFilters,
    is_temporary_filter_active,
    reset_checked_alerts,
    reset_pagination,
    reset_sort_filter,
    revert_temporary_filter,
    select_saved_filter,
    write_working_filters,
)
from app.auth.permissions import require_permission
from app.blueprints import analysis
from aceapi_v2.saved_filters import service as saved_filters_service
from aceapi_v2.saved_filters.schemas import (
    FilterEntry,
    QuickFilterOrder,
    SavedFilterCreate,
    SavedFilterUpdate,
)
from aceapi_v2.saved_filters.service import SavedFilterNameConflict
from aceapi_v2.sync import run_async_with_session
from saq.gui.filter_url import FilterQueryError, decode_legacy_filter_json, encode_filter_query
from saq.util.relative_time import is_relative_time, resolve_date_range_for_display


def _validate(filters: list) -> list:
    """Hold every door to the same standard: a modal apply, an API call, and a hand-edited
    wiki link all validate through FilterEntry.

    Returning 400 on a bad value is the load-bearing part. Without it an unparseable date
    reaches storage and then raises on EVERY subsequent /manage load, leaving the analyst's
    alert queue broken until someone resets their filters by hand."""
    return [FilterEntry.model_validate(entry).model_dump() for entry in filters]


def _posted_filters_or_effective() -> list:
    """Returns the filter list a save should persist."""

    # The editor posts what is on screen, so Save and Save as are WYSIWYG -- they used to read
    # the session instead, which meant building a filter and saving it without pressing Apply
    # first silently saved the PREVIOUS filter.

    # An ABSENT field still means "whatever is currently in effect". That is the "Save a copy"
    # path on the temporary-filter banner, which must never read the editor's DOM, and it is
    # also what a browser holding pre-upgrade JS posts during a rolling deploy -- so the
    # fallback is not dead code.

    # An empty list is NOT the same as an absent field: clearing every row and saving is a
    # mistake, not a request to save "match everything".

    raw = request.form.get('filters')
    if raw is None:
        return _validate(get_effective_filters())

    filters = _validate(json.loads(raw))
    if not filters:
        raise ValueError("a saved filter needs at least one filter row")

    return filters


@analysis.route('/set_sort_filter', methods=['POST'])
@login_required
def set_sort_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # flip direction if same as current, otherwise start asc
    name = request.form['name']
    if 'sort_filter' in session and 'sort_filter_desc' in session and session['sort_filter'] == name:
        session['sort_filter_desc'] = not session['sort_filter_desc']
    else:
        session['sort_filter'] = name
        session['sort_filter_desc'] = False

    # return empy page
    return ('', 204)


@analysis.route('/reset_filters', methods=['POST'])
@login_required
def reset_filters():
    # reset page options
    _reset_filters()
    reset_pagination()
    reset_sort_filter()
    reset_checked_alerts()

    # return empy page
    return ('', 204)


@analysis.route('/set_filters', methods=['GET', 'POST'])
@login_required
def set_filters():
    """POST applies an explicit filter edit.

    DO NOT DELETE THE GET HANDLER. It looks like legacy cruft; removing it silently breaks
    every filter link anyone ever shared. It must also never regain a side effect: as a
    mutating GET it let any prefetch or link scanner rewrite an analyst's filters."""
    if request.method == 'GET':
        raw = request.args.get('filters')
        if not raw:
            return redirect(url_for('analysis.manage'))

        try:
            filters = decode_legacy_filter_json(raw)
        except FilterQueryError as e:
            logging.warning("could not translate legacy filter link: %s", e)
            return (f"That filter link could not be read: {e}", 400)

        # 302 rather than 301: browsers cache a permanent redirect per-URL, and an escaping
        # bug in the new codec would be baked into every analyst's browser with no
        # server-side way to correct it.
        return redirect(url_for('analysis.manage', f=encode_filter_query(filters)))

    reset_pagination()
    reset_checked_alerts()

    try:
        filters = _validate(json.loads(request.form['filters']))
    except (ValidationError, ValueError) as e:
        return (f"That filter is not valid: {e}", 400)

    write_working_filters(filters)
    return ('', 204)


@analysis.route('/select_filter/<filter_uuid>', methods=['POST'])
@require_permission('alert', 'read')
def select_filter(filter_uuid):
    """Apply one of the analyst's own saved filters as their persistent selection."""
    if not select_saved_filter(filter_uuid):
        return ('', 404)

    reset_pagination()
    reset_checked_alerts()
    return ('', 204)


@analysis.route('/apply_temp_filter', methods=['POST'])
@require_permission('alert', 'read')
def apply_temp_filter():
    """Apply a filter WITHOUT touching the analyst's persistent selection."""

    reset_pagination()
    reset_checked_alerts()

    try:
        filters = _validate(json.loads(request.form['filters']))
    except (ValidationError, ValueError) as e:
        return (f"That filter is not valid: {e}", 400)

    apply_temporary_filter(filters, request.form.get('label') or "Modified filter")
    return ('', 204)


@analysis.route('/revert_temp_filter', methods=['POST'])
@require_permission('alert', 'read')
def revert_temp_filter():
    """Discard the temporary filter and restore what the analyst was using before."""
    if not revert_temporary_filter():
        return ('', 404)

    reset_pagination()
    reset_checked_alerts()
    return ('', 204)


@analysis.route('/remove_filter', methods=['POST'])
@login_required
def remove_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    name = request.form['name']
    index = int(request.form['index'])
    target = []
    for _filter in get_effective_filters():
        if _filter["name"] == name:
            del _filter["values"][index]

        if _filter["values"]:
            target.append(_filter)

    write_working_filters(target)
    return ('', 204)


@analysis.route('/remove_filter_category', methods=['POST'])
@login_required
def remove_filter_category():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    name = request.form['name']
    write_working_filters([f for f in get_effective_filters() if f["name"] != name])
    return ('', 204)


@analysis.route('/new_filter_option', methods=['GET'])
@login_required
def new_filter_option():
    return render_template('analysis/alert_filter_input.html', filters=getFilters(),
                           session_filters=[{"name": "Description", "inverted": False, "values": [""]}])


#
# saved filter management
#
# Thin wrappers over the aceapi_v2 service (no HTTP hop -- run_async_with_session calls it
# directly). Flask enforces the permission; the service enforces row ownership.
#

@analysis.route('/saved_filters', methods=['POST'])
@require_permission('alert', 'read')
def create_saved_filter():
    """Save the current filter under a name. Also serves "Save a copy" from the temporary
    filter banner."""
    try:
        body = SavedFilterCreate(
            name=request.form['name'],
            description=request.form.get('description') or None,
            filters=_posted_filters_or_effective(),
            quick_filter=request.form.get('quick_filter') == 'on',
            quick_filter_indicator=request.form.get('quick_filter_indicator') == 'on',
        )
    except (ValidationError, KeyError, ValueError) as e:
        return (f"That filter could not be saved: {e}", 400)

    try:
        saved = run_async_with_session(
            saved_filters_service.create_saved_filter, current_user_id(), body)
    except SavedFilterNameConflict as e:
        return (str(e), 409)

    select_saved_filter(saved.uuid)
    return jsonify({"uuid": saved.uuid, "name": saved.name})


@analysis.route('/saved_filters/<filter_uuid>', methods=['POST'])
@require_permission('alert', 'read')
def update_saved_filter(filter_uuid):
    """Overwrite a saved filter, either its metadata or (on Save) its contents."""
    fields = {}
    if 'name' in request.form:
        fields['name'] = request.form['name']
    if 'description' in request.form:
        fields['description'] = request.form.get('description') or None
    if 'quick_filter_indicator' in request.form:
        fields['quick_filter_indicator'] = request.form.get('quick_filter_indicator') == 'on'

    # save_current, not the presence of `filters`, is what means "overwrite the contents" --
    # a rename or a badge toggle has to be able to run without touching them.
    try:
        if request.form.get('save_current') == 'on':
            fields['filters'] = _posted_filters_or_effective()
        body = SavedFilterUpdate(**fields)
    except (ValidationError, ValueError) as e:
        return (f"That filter could not be saved: {e}", 400)

    try:
        saved = run_async_with_session(
            saved_filters_service.update_saved_filter, filter_uuid, current_user_id(), body)
    except PermissionError:
        return ('', 403)
    except SavedFilterNameConflict as e:
        return (str(e), 409)

    if saved is None:
        return ('', 404)

    # re-select so the page cannot show stale contents for the filter it says is active
    if session.get('filter_base_uuid') == filter_uuid:
        select_saved_filter(filter_uuid)

    return ('', 204)


@analysis.route('/saved_filters/<filter_uuid>/delete', methods=['POST'])
@require_permission('alert', 'read')
def delete_saved_filter(filter_uuid):
    try:
        deleted = run_async_with_session(
            saved_filters_service.delete_saved_filter, filter_uuid, current_user_id())
    except PermissionError:
        return ('', 403)

    if not deleted:
        return ('', 404)

    # the session points at uuids; leaving a dangling one would resolve to the default set
    # on the next load without explanation, so clear it deliberately here
    if session.get('filter_base_uuid') == filter_uuid:
        session['filter_base_uuid'] = None
    if session.get('filter_uuid') == filter_uuid:
        _reset_filters()

    return ('', 204)


@analysis.route('/saved_filters/quick', methods=['POST'])
@require_permission('alert', 'read')
def set_quick_filters():
    """Set which saved filters appear as badges, and in what order, in one call."""
    try:
        order = QuickFilterOrder(filter_uuids=request.form.getlist('filter_uuids'))
        run_async_with_session(saved_filters_service.set_quick_filters, current_user_id(), order)
    except (ValidationError, ValueError) as e:
        return (f"Could not update quick filters: {e}", 400)

    return ('', 204)


@analysis.route('/resolve_date_range', methods=['GET'])
@require_permission('alert', 'read')
def resolve_date_range():
    """What a relative token currently resolves to, for the live hint under the date input.

    Resolved server-side so the hint uses the same parser the query does -- a hint computed
    in JavaScript could disagree with what the filter actually matches."""
    return jsonify({"text": resolve_date_range_for_display(request.args.get('value', ''))})


@analysis.route('/saved_filter_link/<filter_uuid>', methods=['GET'])
@require_permission('alert', 'read')
def saved_filter_link(filter_uuid):
    """A durable share link for one of the analyst's saved filters.

    The URL carries the filter itself, so it keeps working after this row is renamed,
    edited, or deleted -- which is exactly why links are not row ids."""
    saved = run_async_with_session(
        saved_filters_service.get_saved_filter, filter_uuid, current_user_id())
    if saved is None:
        return ('', 404)

    return jsonify({"url": url_for(
        'analysis.manage',
        f=encode_filter_query([entry.model_dump() for entry in saved.filters]),
        _external=True)})


@analysis.route('/saved_filters_modal_body', methods=['GET'])
@require_permission('alert', 'read')
def saved_filters_modal_body():
    """The Manage Filters modal body, refetched after each change so the modal updates
    without a page reload."""
    saved = run_async_with_session(
        saved_filters_service.get_saved_filters_for_user, current_user_id())
    return render_template('analysis/_saved_filters_table.html', saved_filters=saved)


def current_user_id() -> int:
    from flask_login import current_user
    return current_user.id
