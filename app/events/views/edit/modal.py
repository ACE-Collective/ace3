from datetime import datetime
from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required
from app.auth.permissions import require_permission
from app.blueprints import events
from saq.configuration.config import get_config
from saq.database.model import Campaign, Event, EventPreventionTool, EventRemediation, EventRiskLevel, EventStatus, EventType, EventVector, Malware, MalwareMapping, Threat, User
from saq.database.pool import get_db

@events.route('/edit_event_modal', methods=['GET'])
@login_required
def edit_event_modal():
    event_id = request.args['event_id']
    event = get_db().query(Event).filter(Event.id == event_id).one()
    malware = get_db().query(Malware).order_by(Malware.name.asc()).all()
    campaigns = get_db().query(Campaign).order_by(Campaign.name.asc()).all()
    prevention_tools = get_db().query(EventPreventionTool).order_by(EventPreventionTool.value.asc()).all()
    remediations = get_db().query(EventRemediation).order_by(EventRemediation.value.asc()).all()
    risk_levels = get_db().query(EventRiskLevel).order_by(EventRiskLevel.value.asc()).all()

    # If the event is NOT closed, the closed status should not appear in the Edit Event window. This means to close
    # an event, you have to go to the event page and use the "Close Event" button. This ensures that all of the tasks
    # related to closing an event are performed instead of simply updating the status in the database.
    #
    # If the event status is already set to closed, then the closed status will appear in the Edit Event window so that
    # you can edit things about the event after the fact without needing to re-open and re-close it.
    closed_status = get_config().events.closed_status
    if event.status.value == closed_status:
        statuses = get_db().query(EventStatus).order_by(EventStatus.value.asc()).all()
    else:
        statuses = get_db().query(EventStatus).filter(EventStatus.value != closed_status).order_by(EventStatus.value.asc()).all()

    types = get_db().query(EventType).order_by(EventType.value.asc()).all()
    vectors = get_db().query(EventVector).order_by(EventVector.value.asc()).all()
    all_users = get_db().query(User).all()
    return render_template('events/event_edit.html',
                           all_users=all_users,
                           event=event,
                           malware=malware,
                           campaigns=campaigns,
                           prevention_tools=prevention_tools,
                           remediations=remediations,
                           risk_levels=risk_levels,
                           statuses=statuses,
                           types=types,
                           vectors=vectors)

@events.route('/edit_event', methods=['POST'])
@require_permission('event', 'write')
def edit_event():
    event_id = request.form.get('event_id', None)
    event_name = request.form.get('event_name', None)
    event_type = get_db().query(EventType).filter(EventType.value == request.form.get('event_type', None)).one()
    event_vector = get_db().query(EventVector).filter(EventVector.value == request.form.get('event_vector', None)).one()
    event_risk_level = get_db().query(EventRiskLevel).filter(EventRiskLevel.value == request.form.get('event_risk_level', None)).one()
    event_prevention = get_db().query(EventPreventionTool).filter(EventPreventionTool.value == request.form.get('event_prevention', None)).one()
    event_comment = request.form.get('event_comment', None)
    event_status = get_db().query(EventStatus).filter(EventStatus.value == request.form.get('event_status', None)).one()
    event_remediation = get_db().query(EventRemediation).filter(EventRemediation.value == request.form.get('event_remediation', None)).one()
    event_disposition = request.form.get('event_disposition', None)
    event_owner_id = int(request.form.get('event_owner', None))
    campaign_id = request.form.get('campaign_id', None)
    new_campaign = request.form.get('new_campaign', None)

    if campaign_id == 'NEW' and new_campaign:
        campaign = get_db().query(Campaign).filter(Campaign.name == new_campaign).one_or_none()
        if campaign is None:
            campaign = Campaign(name=new_campaign)
            get_db().add(campaign)
    else:
        # The edit event form denotes value "0" as no campaign so that an analyst can remove a campaign
        # from an event if they assign one incorrectly.
        if campaign_id == '0':
            campaign = None
        else:
            campaign = get_db().query(Campaign).filter(Campaign.id == campaign_id).one_or_none()

    event = get_db().query(Event).filter(Event.id == event_id).one()
    event.campaign = campaign

    if event.status.value != get_config().events.closed_status:
        none_values = ['', 'None', None]

        event_time = request.form.get('event_time', None)
        if event_time not in none_values:
            event.event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')

        alert_time = request.form.get('alert_time', None)
        if alert_time not in none_values:
            event.alert_time = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')

        ownership_time = request.form.get('ownership_time', None)
        if ownership_time not in none_values:
            event.ownership_time = datetime.strptime(ownership_time, '%Y-%m-%d %H:%M:%S')

        disposition_time = request.form.get('disposition_time', None)
        if disposition_time not in none_values:
            event.disposition_time = datetime.strptime(disposition_time, '%Y-%m-%d %H:%M:%S')

        contain_time = request.form.get('contain_time', None)
        if contain_time not in none_values:
            event.contain_time = datetime.strptime(contain_time, '%Y-%m-%d %H:%M:%S')

        remediation_time = request.form.get('remediation_time', None)
        if remediation_time not in none_values:
            event.remediation_time = datetime.strptime(remediation_time, '%Y-%m-%d %H:%M:%S')

        # Enforce logical chronology
        dates = [d for d in
                 [event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time] if
                 d not in none_values]
        sorted_dates = sorted(dates)
        if not dates == sorted_dates:
            flash('One or more of your dates has been entered out of valid order. '
                  'Please ensure entered dates follow the scheme: '
                  'Event Time < Alert Time <= Ownership Time < Disposition Time <= Contain Time <= Remediation Time')
            return redirect(url_for('events.manage'))

    event.name = event_name
    event.status = event_status
    event.remediation = event_remediation
    event.type = event_type
    event.vector = event_vector
    event.risk_level = event_risk_level
    event.prevention_tool = event_prevention
    event.comment = event_comment
    event.owner_id = event_owner_id

    for mal_mapping in get_db().query(MalwareMapping).filter(MalwareMapping.event_id == event.id).all():
        get_db().delete(mal_mapping)

    for key in request.form.keys():
        if key.startswith('malware_selection_'):
            index = key[18:]
            mal_id = request.form.get(f'malware_selection_{index}')
            mal_name = request.form.get(f'mal_name_{index}', None)
            threats = request.form.getlist(f'threats_{index}', None)

            if mal_id == 'NEW' and mal_name and threats:
                mal = get_db().query(Malware).filter(Malware.name == mal_name).one_or_none()
                if mal is None:
                    mal = Malware(name=mal_name)
                    get_db().add(mal)
                    get_db().flush()

                for threat_selection in threats:
                    threat = get_db().query(Threat).filter(Threat.malware_id == mal.id, Threat.type == threat_selection).one_or_none()
                    if threat is None:
                        threat = Threat(malware_id=mal.id, type=threat_selection)
                        get_db().add(threat)
                        get_db().flush()
            else:
                mal = get_db().query(Malware).get(mal_id)

            if mal:
                mal_mapping = get_db().query(MalwareMapping).filter(MalwareMapping.malware_id == mal.id, MalwareMapping.event_id == event.id).one_or_none()
                if mal_mapping is None:
                    mal_mapping = MalwareMapping(event_id=event.id, malware_id=mal.id)
                    get_db().add(mal_mapping)

    get_db().commit()

    if '/manage' in request.referrer:
        return redirect(url_for('events.manage'))
    else:
        return redirect(url_for('events.index', direct=event_id))