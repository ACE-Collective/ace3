import json
from app.auth.permissions import require_permission
from app.blueprints import events
from app.events.views.session import get_current_event
from saq.configuration.config import get_config
from saq.database.model import EventStatus
from saq.database.pool import get_db

@events.route('/close_event', methods=['POST'])
@require_permission('event', 'write')
def close_event():
    """This function sets the status of the given event to whatever is defined in the config as the closed status."""

    # Set the event status to the configured closed status
    try:
        event = get_current_event()
        config_closed_status = get_config().events.closed_status
        closed_status = get_db().query(EventStatus).filter(EventStatus.value == config_closed_status).one()
        event.status = closed_status
        get_db().commit()

        return json.dumps({'success': True}), 200, {'Content-Type': 'application/json'}
    except:
        return json.dumps({'success': False}), 500, {'Content-Type': 'application/json'}