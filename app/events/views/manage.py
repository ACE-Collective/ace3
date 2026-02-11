from datetime import datetime, timedelta
import hashlib
from flask import flash, redirect, render_template, request, session, url_for
from sqlalchemy import and_, func, or_
from app.auth.permissions import require_permission
from app.blueprints import events
from app.filters import FILTER_TYPE_CHECKBOX, FILTER_TYPE_MULTISELECT, FILTER_TYPE_SELECT, FILTER_TYPE_TEXT, SearchFilter
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT
from saq.database.model import Alert, Campaign, Company, CompanyMapping, Event, EventMapping, EventPreventionTool, EventRemediation, EventRiskLevel, EventStatus, EventTagMapping, EventType, EventVector, Malware, MalwareMapping, Observable, ObservableMapping, Tag, User, Comment
from saq.database.pool import get_db
from saq.disposition import get_dispositions
from aceapi_v2.observable_types.service import get_observable_types_sync

@events.route('/manage', methods=['GET', 'POST'])
@require_permission('event', 'read')
def manage():
    if not get_config().gui.display_events:
        # redirect to index
        return redirect(url_for('analysis.index'))

    all_users = get_db().query(User).order_by(User.display_name.asc()).all()
    valid_tags = [tag.name for tag in get_db().query(Tag).join(EventTagMapping, Tag.id == EventTagMapping.tag_id).order_by(Tag.name).all()]
    default_owners = [str(user.id) for user in all_users]
    default_owners.append('None')
    filters = {
            'event_daterange': SearchFilter('event_daterange', FILTER_TYPE_TEXT, ''),
            'filter_event_disposition': SearchFilter('filter_event_disposition', FILTER_TYPE_MULTISELECT, list(get_dispositions().keys())),
            'filter_event_status': SearchFilter('filter_event_status', FILTER_TYPE_MULTISELECT, ['OPEN']),
            'filter_event_owner': SearchFilter('filter_event_owner', FILTER_TYPE_MULTISELECT, default_owners),
            'filter_event_type': SearchFilter('filter_event_type', FILTER_TYPE_SELECT, 'ANY'),
            'filter_event_vector': SearchFilter('filter_event_vector', FILTER_TYPE_SELECT, 'ANY'),
            'filter_event_prevention_tool': SearchFilter('filter_event_prevention_tool', FILTER_TYPE_SELECT, 'ANY'),
            'filter_event_risk_level': SearchFilter('filter_event_risk_level', FILTER_TYPE_SELECT, 'ANY'),
            'filter_observable_type': SearchFilter('filter_observable_type', FILTER_TYPE_SELECT, 'ANY'),
            'filter_observable_value': SearchFilter('filter_observable_value', FILTER_TYPE_TEXT, ''),
            'filter_event_tag': SearchFilter('filter_event_tag', FILTER_TYPE_MULTISELECT, '')
    }

    malware = get_db().query(Malware).order_by(Malware.name.asc()).all()
    for mal in malware:
        key = 'malz_{}'.format(mal.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    companies = get_db().query(Company).order_by(Company.name.asc()).all()
    for company in companies:
        key = 'company_{}'.format(company.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    campaigns = get_db().query(Campaign).order_by(Campaign.name.asc()).all()
    for campaign in campaigns:
        key = 'campaign_{}'.format(campaign.id)
        filters[key] = SearchFilter(key, FILTER_TYPE_CHECKBOX, False)

    reset_filter = ('reset-filters' in request.form) or ('reset-filters' in request.args)
    if reset_filter:
        for filter_item in filters.values():
            filter_item.reset()

    filter_state = {filters[f].name: filters[f].state for f in filters}

    for filter_name in filters.keys():
        form_value = filters[filter_name].form_value
        if form_value is not None:
            session[filter_name] = form_value
        elif filter_name in session:
            del session[filter_name]

    query = get_db().query(Event)

    if filters['event_daterange'].value != '':
        try:
            daterange_start, daterange_end = filters['event_daterange'].value.split(' - ')
            daterange_start = datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.now()
            daterange_start = daterange_end - timedelta(days=7)
        query = query.filter(and_(Event.creation_date >= daterange_start, Event.creation_date <= daterange_end))
    if filters['filter_event_status'].value:
        query = query.filter(Event.status.has(EventStatus.value.in_(filters['filter_event_status'].value)))


    owners = [o for o in filters['filter_event_owner'].value if o != 'None']
    if 'None' in filters['filter_event_owner'].value:
        query = query.filter(or_(Event.owner_id.in_(owners), Event.owner_id == None))
    else:
        if owners:
            query = query.filter(Event.owner_id.in_(owners))
    if filters['filter_event_type'].value != 'ANY':
        query = query.filter(Event.type.has(value=filters['filter_event_type'].value))
    if filters['filter_event_vector'].value != 'ANY':
        query = query.filter(Event.vector.has(value=filters['filter_event_vector'].value))
    if filters['filter_event_prevention_tool'].value != 'ANY':
        query = query.filter(Event.prevention_tool.has(value=filters['filter_event_prevention_tool'].value))
    if filters['filter_event_risk_level'].value != 'ANY':
        query = query.filter(Event.risk_level.has(value=filters['filter_event_risk_level'].value))

    # If an observable type and value filter was supplied, create the query so that it uses the type+md5 index
    if filters['filter_observable_type'].value != 'ANY' and filters['filter_observable_value'].value:
        o_md5 = hashlib.md5(filters['filter_observable_value'].value.encode('utf-8', errors='ignore')).hexdigest()

        query = query.join(EventMapping, Event.id == EventMapping.event_id) \
            .join(Alert, EventMapping.alert_id == Alert.id) \
            .join(ObservableMapping, Alert.id == ObservableMapping.alert_id) \
            .join(Observable, ObservableMapping.observable_id == Observable.id) \
            .filter(Observable.type == filters['filter_observable_type'].value, Observable.md5 == func.UNHEX(o_md5))

    # Otherwise, check to see if either of the individual filters were given. This prevents trying to join on the same
    # tables more than once, which causes an error.
    else:
        if filters['filter_observable_type'].value != 'ANY':
            query = query.join(EventMapping, Event.id == EventMapping.event_id) \
                .join(Alert, EventMapping.alert_id == Alert.id) \
                .join(ObservableMapping, Alert.id == ObservableMapping.alert_id) \
                .join(Observable, ObservableMapping.observable_id == Observable.id) \
                .filter(Observable.type == filters['filter_observable_type'].value)

        elif filters['filter_observable_value'].value:
            o_md5 = hashlib.md5(filters['filter_observable_value'].value.encode('utf-8', errors='ignore')).hexdigest()

            query = query.join(EventMapping, Event.id == EventMapping.event_id) \
                .join(Alert, EventMapping.alert_id == Alert.id) \
                .join(ObservableMapping, Alert.id == ObservableMapping.alert_id) \
                .join(Observable, ObservableMapping.observable_id == Observable.id) \
                .filter(Observable.md5 == func.UNHEX(o_md5))

    mal_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('malz_') and filters[filter_name].value:
            mal_id = int(filter_name[len('malz_'):])
            mal_filters.append(MalwareMapping.malware_id == mal_id)
    if len(mal_filters) > 0:
        query = query.filter(Event.malware.any(or_(*mal_filters)))

    company_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('company_') and filters[filter_name].value:
            company_id = int(filter_name[len('company_'):])
            company_filters.append(CompanyMapping.company_id == company_id)
    if len(company_filters) > 0:
        query = query.filter(Event.companies.any(or_(*company_filters)))

    campaign_filters = []
    for filter_name in filters.keys():
        if filter_name.startswith('campaign_') and filters[filter_name].value:
            campaign_id = int(filter_name[len('campaign_'):])
            campaign_filters.append(Event.campaign_id == campaign_id)
    if len(campaign_filters) > 0:
        query = query.filter(or_(*campaign_filters))

    if 'event_sort_by' not in session:
        session['event_sort_by'] = 'date'
        session['event_sort_dir'] = True

    sort_field = request.form.get('sort_field', None)
    if sort_field is not None:
        if session['event_sort_by'] == sort_field:
            session['event_sort_dir'] = not session['event_sort_dir']
        else:
            session['event_sort_by'] = sort_field
            session['event_sort_dir'] = True

    if session['event_sort_by'] == 'date':
        if session['event_sort_dir']:
            query = query.order_by(Event.creation_date.desc())
        else:
            query = query.order_by(Event.creation_date.asc())
    elif session['event_sort_by'] == 'event':
        query = query.join(EventType).join(EventVector)
        if session['event_sort_dir']:
            query = query.order_by(EventType.value.desc(), EventVector.value.desc(), Event.name.desc())
        else:
            query = query.order_by(EventType.value.asc(), EventVector.value.asc(), Event.name.asc())
    elif session['event_sort_by'] == 'campaign':
        query = query.outerjoin(Campaign)
        if session['event_sort_dir']:
            query = query.order_by(Campaign.name.desc())
        else:
            query = query.order_by(Campaign.name.asc())
    elif session['event_sort_by'] == 'prevention':
        query = query.join(EventPreventionTool)
        if session['event_sort_dir']:
            query = query.order_by(EventPreventionTool.value.desc())
        else:
            query = query.order_by(EventPreventionTool.value.asc())
    elif session['event_sort_by'] == 'remediation':
        query = query.join(EventRemediation)
        if session['event_sort_dir']:
            query = query.order_by(EventRemediation.value.desc())
        else:
            query = query.order_by(EventRemediation.value.asc())
    elif session['event_sort_by'] == 'status':
        query = query.join(EventStatus)
        if session['event_sort_dir']:
            query = query.order_by(EventStatus.value.desc())
        else:
            query = query.order_by(EventStatus.value.asc())
    elif session['event_sort_by'] == 'risk_level':
        query = query.join(EventRiskLevel)
        if session['event_sort_dir']:
            query = query.order_by(EventRiskLevel.value.desc())
        else:
            query = query.order_by(EventRiskLevel.value.asc())
    elif session['event_sort_by'] == 'owner':
        query = query.join(User)
        if session['event_sort_dir']:
            query = query.order_by(User.display_name.desc())
        else:
            query = query.order_by(User.display_name.asc())

    events = query.all()

    # filter by disposition here since it isn't a DB column
    if filters['filter_event_disposition'].value:
        events = [event for event in events if event.disposition in filters['filter_event_disposition'].value]

    if session['event_sort_by'] == 'disposition':
        events = sorted(events, key=lambda event: event.disposition_rank, reverse=session['event_sort_dir'])

    # Filter by tag
    # do this in a loop instead of list comprehension so you can compile the event_tags for display at the same time
    # (avoids doubling DB calls)
    all_event_tags = {}
    if events and filters['filter_event_tag'].value:
        for event in events.copy():
            event_tags = event.tags
            event_tag_values = set([tag.name for tag in event_tags])
            filter_tags = set(filters['filter_event_tag'].value)

            if not event_tag_values.isdisjoint(filter_tags):
                all_event_tags[event.id] = event_tags
            else:
                events.remove(event)

    # Skip any filtering by tag if there are no event tags / no tag filter selected
    else:
        for event in events:
            all_event_tags[event.id] = event.tags

    prevention_tools = get_db().query(EventPreventionTool).order_by(EventPreventionTool.value.asc()).all()
    risk_levels = get_db().query(EventRiskLevel).order_by(EventRiskLevel.value.asc()).all()
    statuses = get_db().query(EventStatus).order_by(EventStatus.value.asc()).all()
    types = get_db().query(EventType).order_by(EventType.value.asc()).all()
    vectors = get_db().query(EventVector).order_by(EventVector.value.asc()).all()

    # Query events for the event modal
    open_events = get_db().query(Event).filter(Event.status.has(value='OPEN')).order_by(Event.creation_date.desc()).all()
    closed_events_query = get_db().query(Event).filter(Event.status.has(value='CLOSED')).order_by(Event.creation_date.desc()).limit(CLOSED_EVENT_LIMIT).all()
    end_of_list = len(closed_events_query) < CLOSED_EVENT_LIMIT
    closed_events = closed_events_query

    return render_template('events/manage.html',
                           all_users=all_users,
                           campaigns=campaigns,
                           companies=companies,
                           events=events,
                           event_tags=all_event_tags,
                           filter_state=filter_state,
                           malware=malware,
                           prevention_tools=prevention_tools,
                           risk_levels=risk_levels,
                           sort_by=session['event_sort_by'],
                           sort_dir=session['event_sort_dir'],
                           tip=None,
                           statuses=statuses,
                           dispositions=get_dispositions(),
                           tags=valid_tags,
                           types=types,
                           vectors=vectors,
                           open_events=open_events,
                           closed_events=closed_events,
                           end_of_list=end_of_list,
                           observable_types=get_observable_types_sync())

@events.route('/manage_event_details', methods=['GET'])
@require_permission('event', 'read')
def manage_event_details():
    event_id = request.args['event_id']
    event = get_db().query(Event).filter(Event.id == event_id).one()

    alerts = event.alert_objects
    alert_tags = event.showable_tags

    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    return render_template(
        'events/manage_event_summary.html',
        alert_tags = alert_tags,
        alerts = alerts,
        event = event,
        comments = comments,
    )