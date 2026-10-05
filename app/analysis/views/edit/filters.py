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
    overlay_temporary_filter,
    reset_checked_alerts,
    reset_pagination,
    reset_sort_filter,
    revert_temporary_filter,
    select_saved_filter,
    write_working_filters,
)
from app.auth.permissions import require_permission
from app.blueprints import analysis
from aceapi_v2.saved_filters.schemas import FilterEntry
from saq.gui.filter_url import FilterQueryError, decode_legacy_filter_json, encode_filter_query
from saq.util.relative_time import is_relative_time, resolve_date_range_for_display


def _validate(filters: list) -> list:
    """Hold every door to the same standard: a modal apply, an API call, and a hand-edited
    wiki link all validate through FilterEntry.

    Returning 400 on a bad value is the load-bearing part. Without it an unparseable date
    reaches storage and then raises on EVERY subsequent /manage load, leaving the analyst's
    alert queue broken until someone resets their filters by hand."""
    return [FilterEntry.model_validate(entry).model_dump() for entry in filters]


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
    """Apply one of the analyst's own saved filters as their persistent selection.

    Saved filters are saved, deleted and ordered through /api/v2/saved-filters
    (static/js/saved_filters.js); selecting one is session state, so it stays here, and the page
    calls it after a Save as or a Save."""
    if not select_saved_filter(filter_uuid):
        return ('', 404)

    reset_pagination()
    reset_checked_alerts()
    return ('', 204)


@analysis.route('/apply_temp_filter', methods=['POST'])
@require_permission('alert', 'read')
def apply_temp_filter():
    """Apply a filter WITHOUT touching the analyst's persistent selection. With overlay=on
    it is laid over the filter in effect instead of replacing it."""

    reset_pagination()
    reset_checked_alerts()

    try:
        filters = _validate(json.loads(request.form['filters']))
    except (ValidationError, ValueError) as e:
        return (f"That filter is not valid: {e}", 400)

    label = request.form.get('label') or "Modified filter"
    if request.form.get('overlay') == 'on':
        overlay_temporary_filter(filters, label)
    else:
        apply_temporary_filter(filters, label)

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


@analysis.route('/resolve_date_range', methods=['GET'])
@require_permission('alert', 'read')
def resolve_date_range():
    """What a relative token currently resolves to, for the live hint under the date input.

    Resolved server-side so the hint uses the same parser the query does -- a hint computed
    in JavaScript could disagree with what the filter actually matches."""
    return jsonify({"text": resolve_date_range_for_display(request.args.get('value', ''))})
