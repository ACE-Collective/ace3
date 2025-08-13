import logging
import os
import uuid
from flask import make_response, request
from app.auth.permissions import require_permission
from app.blueprints import events
from saq.configuration.config import get_config
from saq.csv_builder import CSV
from saq.database.model import Event
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock

@events.route('/send_event_to', methods=['POST'])
@require_permission('event', 'read')
def send_event_to():
    remote_host = request.json['remote_host']
    remote_path = get_config()[f"send_to_{remote_host}"].get("remote_path")
    event_uuid = request.json['event_uuid']

    try:
        event: Event = get_db().query(Event).filter(Event.uuid == event_uuid).one()

        # Events will be stored in an "events" subdirectory with spaces in the event name converted to underscores.
        remote_path = os.path.join(remote_path, "events", event.name.replace(" ", "_"))

        for alert_uuid in event.alerts:
            # NOTE: If we require the alert to be locked first, it can't be sent to the remote host until it finished analyzing.
            # This also prevents multiple people from trying to transfer the alert at the same time.
            lock_uuid = str(uuid.uuid4())
            if not acquire_lock(alert_uuid, lock_uuid):
                return f"Unable to lock alert {alert_uuid}", 500

            # Alerts might be large, so execute the rsync in the background instead of possibly timing out the GUI
            from saq.background_exec import add_background_task, BG_TASK_RSYNC_ALERT
            add_background_task(BG_TASK_RSYNC_ALERT, alert_uuid, remote_host, remote_path, lock_uuid)

    except Exception as error:
        logging.error(f"unable to send event {event_uuid} to {remote_host}:{remote_path} due to error: {error}")
        return f"Error: {error}", 400
        
    # Instead of using "finally" to release the lock on the alert, the lock is released in the rsync function. This is
    # because the rsync function is executed in the background, so this send_event_to function would release the lock
    # before the rsync function actually completes.

    return remote_path, 200

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