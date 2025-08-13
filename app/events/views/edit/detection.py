import json
import logging
from flask import request
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import events
from app.events.views.session import get_current_event, get_current_event_id
from saq.database.model import Observable
from saq.database.pool import get_db

@events.route('/set_observables_detection_status', methods=['POST'])
@require_permission('event', 'write')
def set_observables_detection_status():
    """This function expects to receive a JSON array in the form of:
    {"enabled": [1, 2, 3], "disabled": []}

    Where the keys are "enabled" and "disabled", and the values are lists of the observable IDs.
    """

    event = get_current_event()
    event_name = event.name if event else "?"
    event_id = get_current_event_id()

    if request.json['enabled']:
        get_db().execute(Observable.__table__.update().where(
            Observable.id.in_(request.json['enabled'])
        ).values(for_detection=True, enabled_by=current_user.id, detection_context=f"manually enabled in the gui by {current_user} for event {event_name} ({event_id})"))

    if request.json['disabled']:
        logging.info(f"{current_user} disabled observable detection status for {request.json['disabled']}")
        get_db().execute(Observable.__table__.update().where(
            Observable.id.in_(request.json['disabled'])
        ).values(for_detection=False))

    # why???
    #for for_detection_status, observable_ids in [ ('enabled', request.json['enabled']), ('disabled', request.json['disabled']) ]:
        #for observable_id in observable_ids:
            #try:
                #observable = get_db().query(Observable).filter(Observable.id == observable_id).first()
                #if observable:
                    #logging.info(f"{current_user} {for_detection_status} observable {observable.value} for detection")
            #except:
                #logging.warning(f"unable to query observable {observable_id}: {e}")

    try:
        get_db().commit()
        return json.dumps({'success': True}), 200, {'Content-Type': 'application/json'}
    except:
        get_db().rollback()
        return json.dumps({'success': False}), 500, {'Content-Type': 'application/json'}