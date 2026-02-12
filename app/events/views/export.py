from flask import make_response, request
from app.auth.permissions import require_permission
from app.blueprints import events
from saq.csv_builder import CSV
from saq.database.model import Event
from saq.database.pool import get_db

@events.route('/export_events_to_csv', methods=['GET'])
@require_permission('event', 'read')
def export_events_to_csv():
    """Compiles and returns a CSV of event details, given a set of event IDs within the request."""
    event_ids = request.args.getlist('checked_events[]')
    export_events = get_db().query(Event).filter(Event.id.in_(event_ids)).all()

    # Add event export headers
    csv = CSV(
        'id',
        'uuid',
        'creation_date',
        'name',
        'type',
        'vector',
        'threat_type',
        'threat_name',
        'severity',
        'prevention_tool',
        'remediation',
        'status',
        'owner',
        'comment',
        'campaign',
        'event_time',
        'alert_time',
        'ownership_time',
        'disposition_time',
        'contain_time',
        'remediation_time',
        'YEAR(events.alert_time)',
        'MONTH(events.alert_time)',
        'MAX(disposition)',
        'tags'
    )
    # Add data for each event
    for event in export_events:
        threat_types = ''
        for threat in event.threats:
            if threat_types == '':
                threat_types = threat
            else:
                threat_types = f'{threat_types}, {threat}'

        threat_names = ''
        for threat in event.malware_names:
            if threat_names == '':
                threat_names = threat
            else:
                threat_names = f'{threat_names}, {threat}'

        campaign = ''
        if event.campaign:
            campaign = event.campaign.name

        tags = ''
        for tag in event.tags:
            if tags == '':
                tags = tag.name
            else:
                tags = f'{tags}, {tag}'

        csv.add_row(
            event.id,
            event.uuid,
            event.creation_date,
            event.name,
            event.type.value,
            event.vector.value,
            threat_types,
            threat_names,
            event.risk_level.value,
            event.prevention_tool.value,
            event.remediation.value,
            event.status.value,
            event.owner,
            event.comment,
            campaign,
            event.event_time,
            event.alert_time,
            event.ownership_time,
            event.disposition_time,
            event.contain_time,
            event.remediation_time,
            event.alert_time.year,
            event.alert_time.strftime("%b"),
            event.disposition,
            tags
        )

    # send csv to client
    response = make_response(str(csv))
    return response