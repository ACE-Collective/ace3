from flask import redirect, request, url_for
from sqlalchemy import and_
from app.auth.permissions import require_permission
from app.blueprints import events
from saq.database.model import EventMapping
from saq.database.pool import get_db

@events.route('/remove_alerts', methods=['POST'])
@require_permission('event', 'write')
def remove_alerts():
    mappings = request.form['event_mappings'].split(',')

    for mapping in mappings:
        event_id, alert_id = mapping.split('_')

        mapping_obj = get_db().query(EventMapping).filter(
            and_(
                EventMapping.event_id == event_id,
                EventMapping.alert_id == alert_id
            )
        ).one_or_none()

        if mapping_obj:
            get_db().delete(mapping_obj)

    get_db().commit()

    if '/manage' in request.referrer:
        return redirect(url_for('events.manage'))
    else:
        return redirect(url_for('events.index', direct=event_id))