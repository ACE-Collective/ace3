from app.auth.permissions import require_permission
from app.blueprints import events

@events.route('/add_indicators_to_event_in_tip', methods=['POST'])
@require_permission('event', 'write')
def add_indicators_to_event_in_tip():
    # Add the indicators to the TIP in the background
    pass