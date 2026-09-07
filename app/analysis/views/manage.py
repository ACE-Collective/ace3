import logging
from datetime import datetime

import pytz
from flask import flash, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user
from sqlalchemy import distinct, func
from sqlalchemy.orm import selectinload

from aceapi_v2.observable_types.service import get_observable_types
from aceapi_v2.sync import run_async
from app.analysis.views.search import SEARCH_MODE_SIMILAR, get_search_spec
from app.analysis.views.session.search_filters import effective_filters_to_search_filters
from app.analysis.views.session.filters import (
    _reset_filters,
    apply_temporary_filter,
    build_alert_query,
    get_current_filter,
    get_effective_filters,
    get_quick_filter_display_data,
    get_reset_filter_alert_count,
    get_saved_filter_list,
    seed_default_saved_filters,
    get_temp_filter,
    getFilters,
    migrate_legacy_session_filters,
    reset_checked_alerts,
    reset_pagination,
    reset_sort_filter,
)
from saq.gui.filter_names import DATE_RANGE_FILTER_NAMES
from saq.gui.filter_url import (
    FilterQueryError,
    decode_filter_query,
    decode_legacy_filter_json,
    encode_filter_query,
)
from app.auth.permissions import reject_unauthenticated_datastar, require_permission
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT, DIRECTIVE_DESCRIPTIONS, GUI_DIRECTIVES
from saq.database.model import (
    Campaign,
    Comment,
    Event,
    ObservableMapping,
    Owner,
    Tag,
    TagMapping,
    User,
)
from saq.database.pool import get_db
from saq.disposition import get_dispositions
from saq.gui.alert import GUIAlert
from saq.remediation.coverage import get_remediation_coverage
from saq.search.query import search_alerts, similar_alerts
from saq.search.types import AlertSearchResult, SearchRequest


def _is_single_disposition_filter(filters: list) -> bool:
    """True when the analyst has narrowed to exactly one disposition, so showing the
    disposition column would repeat the same value on every row."""
    for entry in filters or []:
        if entry["name"] == "Disposition" and not entry.get("inverted") and len(entry["values"]) == 1:
            return True

    return False


def _ensure_manage_session_defaults(seed_saved_filters: bool = False):
    """Seeds the session with the default alert management view settings on first visit.

    `seed_saved_filters` WRITES to the database, so only manage() passes it. manage_refresh()
    calls this same function every 30 seconds and a polled endpoint must not write."""
    # carry a pre-upgrade cookie's filter list over to a scratch row before anything reads
    # the new UUID-shaped state
    migrate_legacy_session_filters()
    # Must come BEFORE the working row is created below: the seed guard is "this user has
    # no filter rows at all", which is what stops deleted defaults from being resurrected.
    if seed_saved_filters:
        seed_default_saved_filters()
    if 'filter_uuid' not in session:
        _reset_filters()
    if 'checked' not in session:
        reset_checked_alerts()
    if 'page_offset' not in session or 'page_size' not in session:
        reset_pagination()
    if 'sort_filter' not in session or 'sort_filter_desc' not in session:
        reset_sort_filter()

def build_manage_list_context() -> dict:
    """Builds the template context for the alert list and filter bar of the alert
    management page: the filtered/sorted/paginated alerts with their comments and tags,
    the total count, and the filter display data. Shared by manage() and
    manage_refresh(). Never writes to the session -- the clamped page offset is returned
    in the context as page_offset."""
    # create alert view by joining required tables, applying the session filters and
    # scoping to the alerts visible from this node
    effective_filters = get_effective_filters()
    query = build_alert_query(effective_filters)

    #query = query.options(selectinload('workload'))
    query = query.options(selectinload(GUIAlert.workload))
    #query = query.options(selectinload('delayed_analysis'))
    query = query.options(selectinload(GUIAlert.delayed_analysis))
    #query = query.options(selectinload('lock'))
    query = query.options(selectinload(GUIAlert.lock))
    #query = query.options(selectinload('observable_mappings'))
    query = query.options(selectinload(GUIAlert.observable_mappings))
    #query = query.options(selectinload('observable_mappings.observable'))
    query = query.options(selectinload(GUIAlert.observable_mappings).selectinload(ObservableMapping.observable))
    #query = query.options(selectinload('event_mapping'))
    query = query.options(selectinload(GUIAlert.event_mapping))
    #query = query.options(selectinload('tag_mapping'))
    query = query.options(selectinload(GUIAlert.tag_mapping))
    # eager-load detection points so the detection_count hybrid property does not
    # issue a separate query per alert when the template renders the count
    query = query.options(selectinload(GUIAlert.detection_points))

    saved_filters = get_saved_filter_list()

    # an active search decides which alerts are listed and in what order; the analyst's
    # filters still apply (pushed into the search as pre-filters and re-applied in SQL)
    search_spec = get_search_spec()
    search_query = None
    search_mode = None
    search_result_mapping: dict[str, AlertSearchResult] = {}

    if search_spec:
        search_mode = search_spec["mode"]
        page_offset = max(session['page_offset'], 0)

        def post_filter(uuids: list[str]) -> list[str]:
            # the filter list is authoritative: keep only fused matches it lets through
            visible = {row[0] for row in build_alert_query(effective_filters).with_entities(GUIAlert.uuid).filter(GUIAlert.uuid.in_(uuids)).distinct()}
            return [alert_uuid for alert_uuid in uuids if alert_uuid in visible]

        search_filters = effective_filters_to_search_filters(effective_filters)
        if search_mode == SEARCH_MODE_SIMILAR:
            search_query = f"Similar to: {search_spec.get('description') or search_spec['alert_uuid']}"
        else:
            search_query = search_spec["query"]

        def run_search(offset: int):
            if search_mode == SEARCH_MODE_SIMILAR:
                return similar_alerts(search_spec["alert_uuid"], search_filters, limit=session['page_size'], offset=offset, post_filter=post_filter)

            return search_alerts(
                SearchRequest(query=search_query, filters=search_filters, limit=session['page_size'], offset=offset),
                post_filter=post_filter,
            )

        response = run_search(page_offset)
        total_alerts = response.total
        if page_offset >= total_alerts:
            # the page the session remembers is past the end of this result set (the search
            # changed, or a filter narrowed it): clamp like the unsearched path and re-page
            clamped = max((total_alerts // session['page_size']) * session['page_size'], 0)
            if clamped != page_offset:
                page_offset = clamped
                response = run_search(page_offset)

        page_uuids = response.alert_uuids
        search_result_mapping = {result.alert_uuid: result for result in response.results}
        if page_uuids:
            query = query.filter(GUIAlert.uuid.in_(page_uuids)).group_by(GUIAlert.id)
        else:
            query = query.filter(GUIAlert.id == None) # noqa: E711  (an empty page)
    else:
        # get total number of alerts
        count_query = query.statement.with_only_columns(func.count(distinct(GUIAlert.id)))
        total_alerts = get_db().execute(count_query).scalar()

        # group by id to prevent duplicates
        query = query.group_by(GUIAlert.id)

        # apply sort filter
        sort_filters = {
            'Alert Date': GUIAlert.insert_date,
            'Description': GUIAlert.description,
            'Disposition': GUIAlert.disposition,
            'Owner': Owner.display_name,
            'Queue': GUIAlert.queue,
        }
        if session['sort_filter_desc']:
            query = query.order_by(sort_filters[session['sort_filter']].desc(), GUIAlert.id.desc())
        else:
            query = query.order_by(sort_filters[session['sort_filter']].asc(), GUIAlert.id.asc())

        # apply pagination
        # the offset is clamped into a local rather than back into the session: this also
        # runs from the polled refresh endpoint, where a Set-Cookie could race a pagination
        # click in another request
        query = query.limit(session['page_size'])
        page_offset = session['page_offset']
        if page_offset >= total_alerts:
            page_offset = (total_alerts // session['page_size']) * session['page_size']
        page_offset = max(page_offset, 0)
        query = query.offset(page_offset)

    # execute query to get all alerts
    alerts = query.all()

    # we do not want load() called on alerts from the alert management screen
    for alert in alerts:
        alert.set_log_error_on_load(True)

    # load alert comments
    # NOTE: We should have the alert class do this automatically
    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    # load alert tags
    # NOTE: We should have the alert class do this automatically
    alert_tags = {}
    if alerts:
        tag_query = get_db().query(Tag, GUIAlert.uuid).join(TagMapping, Tag.id == TagMapping.tag_id).join(GUIAlert, GUIAlert.id == TagMapping.alert_id)
        tag_query = tag_query.filter(GUIAlert.id.in_([a.id for a in alerts]))
        ignore_tags = [tag for tag in get_config().tags if get_config().tags[tag] in ['special', 'hidden' ]]
        tag_query = tag_query.filter(Tag.name.notin_(ignore_tags))
        tag_query = tag_query.order_by(Tag.name.asc())
        for tag, alert_uuid in tag_query:
            if alert_uuid not in alert_tags:
                alert_tags[alert_uuid] = []
            alert_tags[alert_uuid].append(tag)

    # per-alert email remediation coverage for the badge next to the description
    remediation_coverage = get_remediation_coverage(alerts)

    # alert display timezone
    display_timezone = pytz.utc
    if current_user.timezone and pytz.timezone(current_user.timezone) != pytz.utc:
        display_timezone = pytz.timezone(current_user.timezone)
        for alert in alerts:
            alert.display_timezone = display_timezone
    # the Date column header names the timezone so the cells can drop the offset suffix
    display_timezone_label = datetime.now(display_timezone).strftime('%Z')

    # a search page is shown in relevance order (the fused ranking), not the sort filter's
    if search_result_mapping:
        alerts = sorted(alerts, key=lambda alert: search_result_mapping[alert.uuid].rank if alert.uuid in search_result_mapping else 0)

    return {
        # settings
        'ace_config': get_config(),
        'session': session,
        'dispositions': get_dispositions(),

        # filter
        'filters': getFilters(),
        'effective_filters': effective_filters,
        # lets the filter bar show what a relative token like -24h currently resolves to
        'date_range_filter_names': DATE_RANGE_FILTER_NAMES,
        'search_query': search_query,
        'search_mode': search_mode,
        'saved_filters': saved_filters,
        'quick_filters': get_quick_filter_display_data(saved_filters),
        'current_filter': get_current_filter(),
        'temp_filter': get_temp_filter(),
        # the share link is a pure string build -- no DB write, no round trip
        'share_url': url_for('analysis.manage', f=encode_filter_query(effective_filters), _external=True),

        # alert data
        'alerts': alerts,
        'comments': comments,
        'remediation_coverage': remediation_coverage,
        'display_timezone_label': display_timezone_label,
        'alert_tags': alert_tags,
        # hide the disposition column when the analyst has narrowed to a single disposition
        # (it would be the same value on every row). The old form indexed the filter LIST
        # as if it were a dict, so this was always True.
        'display_disposition': not _is_single_disposition_filter(effective_filters),
        'total_alerts': total_alerts,
        'page_offset': page_offset,

        # search data
        'search_result_mapping': search_result_mapping,
    }

@analysis.route('/manage', methods=['GET', 'POST'])
@require_permission('alert', 'read')
def manage():
    # A share link carries the filter itself, so it keeps working after the filter it was
    # copied from is edited or deleted. Applied as a TEMPORARY filter: opening someone
    # else's link must never clobber the filter you were already using.
    if 'filters' in request.args:
        # legacy ?filters=<json>, permanently supported -- translate and bounce to the
        # canonical URL so what the analyst copies onward is the new format
        try:
            return redirect(url_for(
                'analysis.manage',
                f=encode_filter_query(decode_legacy_filter_json(request.args['filters']))))
        except FilterQueryError as e:
            flash(f"That filter link could not be read: {e}", "error")
            return redirect(url_for('analysis.manage'))

    if 'f' in request.args:
        # seed here too: this is a real page render, and seeding must happen before any
        # working row exists for this user (see _ensure_manage_session_defaults)
        _ensure_manage_session_defaults(seed_saved_filters=True)
        try:
            filters, warnings = decode_filter_query(request.args.getlist('f'))
        except FilterQueryError as e:
            flash(f"That filter link could not be read: {e}", "error")
            return redirect(url_for('analysis.manage'))

        apply_temporary_filter(filters, "Shared link")
        reset_pagination()
        reset_checked_alerts()
        for warning in warnings:
            flash(warning, "warning")

        # NOTE: deliberately no redirect. The canonical URL stays in the address bar so it
        # can be copied, bookmarked, and reached with the back button -- that is the whole
        # point of a durable link. Revert navigates to a bare /manage instead, which is
        # where the "don't re-apply on F5" concern actually belongs.

    _ensure_manage_session_defaults(seed_saved_filters=True)

    ctx = build_manage_list_context()

    # persist the clamped page offset (the polled refresh endpoint intentionally does not)
    session['page_offset'] = ctx['page_offset']

    open_events = []
    event_query_results = get_db().query(Event).filter(Event.status.has(value='OPEN')).order_by(Event.creation_date.desc()).all()
    if event_query_results:
        open_events = event_query_results

    closed_events = []
    end_of_closed_events_list = True
    event_query_results = get_db().query(Event).filter(Event.status.has(value='CLOSED')).order_by(Event.creation_date.desc())\
        .limit(CLOSED_EVENT_LIMIT).all()
    if event_query_results:
        if len(event_query_results) == CLOSED_EVENT_LIMIT:
            end_of_closed_events_list = False
        closed_events = event_query_results

    return render_template(
        'analysis/manage.html',
        **ctx,

        # event data
        open_events=open_events,
        closed_events=closed_events,
        end_of_list=end_of_closed_events_list,
        campaigns=get_db().query(Campaign).order_by(Campaign.name.asc()).all(),

        # user data
        all_users=get_db().query(User).all(),

        # observable modal data
        observable_types=run_async(get_observable_types()),
        directives={directive: DIRECTIVE_DESCRIPTIONS[directive] for directive in sorted(GUI_DIRECTIVES)},
    )

@analysis.route('/manage/refresh')
@reject_unauthenticated_datastar
@require_permission('alert', 'read')
def manage_refresh():
    """Returns the morphable fragments of the alert management page (filter bar + alert
    table) as plain HTML. Polled by Datastar to keep the page current -- see
    analysis/manage.html and docs/GUI_DATASTAR.md."""
    _ensure_manage_session_defaults()
    response = make_response(render_template('analysis/_manage_refresh.html', **build_manage_list_context()))
    # per-user data -- must not be handed out by the blueprint's default public cache policy
    response.headers['Cache-Control'] = 'private, no-store'
    return response

@analysis.route('/reset_filter_alert_count')
@require_permission('alert', 'read')
def reset_filter_alert_count():
    """Returns the number of alerts matching the "Reset" filter for the current user, as
    JSON. Polled by the browser tab to drive the favicon notification dot -- see
    static/js/ace.js."""
    response = jsonify({"count": get_reset_filter_alert_count()})
    # per-user data -- must not be handed out by the blueprint's default public cache policy
    response.headers['Cache-Control'] = 'private, no-store'
    return response
