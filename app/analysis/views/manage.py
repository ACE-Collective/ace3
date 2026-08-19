import logging
from flask import jsonify, render_template, session
from flask_login import current_user
import pytz
from qdrant_client.models import ScoredPoint
from sqlalchemy import distinct, func
from app.analysis.views.session.filters import _reset_filters, build_alert_query, get_quick_filter_display_data, get_reset_filter_alert_count, getFilters, reset_checked_alerts, reset_pagination, reset_sort_filter
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.configuration.config import get_config
from aceapi_v2.observable_types.service import get_observable_types
from aceapi_v2.sync import run_async
from saq.constants import CLOSED_EVENT_LIMIT, DIRECTIVE_DESCRIPTIONS, GUI_DIRECTIVES
from saq.database.model import Campaign, Observable, ObservableMapping, ObservableRemediationMapping, Owner, Tag, TagMapping, Comment, Event, User
from saq.database.pool import get_db
from saq.disposition import get_dispositions
from saq.gui.alert import GUIAlert
from sqlalchemy.orm import selectinload

@analysis.route('/manage', methods=['GET', 'POST'])
@require_permission('alert', 'read')
def manage():
    # use default page settings if first visit
    if 'filters' not in session:
        _reset_filters()
    if 'checked' not in session:
        reset_checked_alerts()
    if 'page_offset' not in session or 'page_size' not in session:
        reset_pagination()
    if 'sort_filter' not in session or 'sort_filter_desc' not in session:
        reset_sort_filter()

    # create alert view by joining required tables, applying the session filters and
    # scoping to the alerts visible from this node
    query = build_alert_query(session["filters"])

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
    #query = query.options(selectinload('observable_mappings.observable.observable_remediation_mappings'))
    query = query.options(selectinload(GUIAlert.observable_mappings).selectinload(ObservableMapping.observable).selectinload(Observable.observable_remediation_mappings))
    #query = query.options(selectinload('observable_mappings.observable.observable_remediation_mappings.remediation'))
    query = query.options(selectinload(GUIAlert.observable_mappings).selectinload(ObservableMapping.observable).selectinload(Observable.observable_remediation_mappings).selectinload(ObservableRemediationMapping.remediation))
    #query = query.options(selectinload('event_mapping'))
    query = query.options(selectinload(GUIAlert.event_mapping))
    #query = query.options(selectinload('tag_mapping'))
    query = query.options(selectinload(GUIAlert.tag_mapping))
    # eager-load detection points so the detection_count hybrid property does not
    # issue a separate query per alert when the template renders the count
    query = query.options(selectinload(GUIAlert.detection_points))

    # if we have a search query then apply it
    search_query = session.get("search", None)
    search_result_uuids = []
    search_result_mapping: dict[str, list[ScoredPoint]] = {}

    if search_query:
        from saq.llm.embedding.search import search
        logging.info(f"search query: {search_query}")
        search_results = search(search_query)
        logging.info(f"got {len(search_results)} search results")
        for result in search_results:
            alert_uuid = result.payload.get("root_uuid", None)
            logging.info(f"search result alert uuid: {alert_uuid}")
            if alert_uuid:
                search_result_uuids.append(alert_uuid)
                if alert_uuid not in search_result_mapping:
                    search_result_mapping[alert_uuid] = []

                # for now we'll limit these to 5 max
                if len(search_result_mapping[alert_uuid]) < 5:
                    search_result_mapping[alert_uuid].append(result)

    if search_result_uuids:
        query = query.filter(GUIAlert.uuid.in_(list(set(search_result_uuids))))

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
    }
    if session['sort_filter_desc']:
        query = query.order_by(sort_filters[session['sort_filter']].desc(), GUIAlert.id.desc())
    else:
        query = query.order_by(sort_filters[session['sort_filter']].asc(), GUIAlert.id.asc())

    # apply pagination
    query = query.limit(session['page_size'])
    if session['page_offset'] >= total_alerts:
        session['page_offset'] = (total_alerts // session['page_size']) * session['page_size']
    if session['page_offset'] < 0:
        session['page_offset'] = 0
    query = query.offset(session['page_offset'])

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
        ignore_tags = [tag for tag in get_config().tags.keys() if get_config().tags[tag] in ['special', 'hidden' ]]
        tag_query = tag_query.filter(Tag.name.notin_(ignore_tags))
        tag_query = tag_query.order_by(Tag.name.asc())
        for tag, alert_uuid in tag_query:
            if alert_uuid not in alert_tags:
                alert_tags[alert_uuid] = []
            alert_tags[alert_uuid].append(tag)

    # alert display timezone
    if current_user.timezone and pytz.timezone(current_user.timezone) != pytz.utc:
        for alert in alerts:
            alert.display_timezone = pytz.timezone(current_user.timezone)

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

    # if we did a vector search then we need to order by the scores
    if search_result_uuids:
        alerts = sorted(alerts, key=lambda x: max([_.score for _ in search_result_mapping[x.uuid]]), reverse=True)

    return render_template(
        'analysis/manage.html',
        # settings
        ace_config=get_config(),
        session=session,
        dispositions=get_dispositions(),

        # filter
        filters=getFilters(),
        search_query=search_query,
        quick_filters=get_quick_filter_display_data(),

        # alert data
        alerts=alerts,
        comments=comments,
        alert_tags=alert_tags,
        display_disposition=not ('Disposition' in session['filters'] and len(session['filters']['Disposition']) == 1 and session['filters']['Disposition'][0] is None),
        total_alerts=total_alerts,

        # event data
        open_events=open_events,
        closed_events=closed_events,
        end_of_list=end_of_closed_events_list,
        campaigns=get_db().query(Campaign).order_by(Campaign.name.asc()).all(),

        # user data
        all_users=get_db().query(User).all(),

        # search data
        search_result_mapping=search_result_mapping,

        # observable modal data
        observable_types=run_async(get_observable_types()),
        directives={directive: DIRECTIVE_DESCRIPTIONS[directive] for directive in sorted(GUI_DIRECTIVES)},
    )

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