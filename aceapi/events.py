# vim: sw=4:ts=4:et
#
# ACE API event routines

from aceapi.auth import api_auth_check
from aceapi.blueprints import events_bp

from flask import request, abort, Response
from aceapi.json import json_result
from saq.database import Event, EventStatus, get_db


@events_bp.route('/open', methods=['GET'])
@api_auth_check("event", "read")
def get_open_events():
    open_events = get_db().query(Event).filter(Event.status.has(value='OPEN')).all()
    return json_result([event.json for event in open_events])


@events_bp.route('/<int:event_id>/status', methods=['PUT'])
@api_auth_check("event", "write")
def update_event_status(event_id):
    event = get_db().query(Event).get(event_id)
    if not event:
        abort(Response("Event ID not found", 404))

    status = get_db().query(EventStatus).filter(EventStatus.value == request.values.get('status', None)).one_or_none()
    if status:
        event.status = status
        get_db().commit()
        return json_result(event.json)

    abort(Response("Must specify valid event status", 400))
