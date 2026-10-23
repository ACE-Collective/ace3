import logging
import re
from typing import Optional
from flask import request
from flask_login import current_user
import pytz

from saq.database.model import Event
from saq.database.pool import get_db


def get_current_event_id():
    """Returns the current event ID the analyst is looking at, or None if they are not looking at anything."""
    target_dict = request.form if request.method == 'POST' else request.args

    if 'direct' in target_dict:
        return target_dict['direct']
    elif 'event_id' in target_dict:
        return target_dict['event_id']

    # Check if the referring URL has the event ID in it (browsers can be set not to send one)
    m = re.search(r'direct=(\d+)', request.referrer or '')
    if m:
        return m.group(1)

    logging.debug("missing direct or event_id in get_current_event for user {0}".format(current_user))
    return None


def get_current_event() -> Optional[Event]:
    """Returns the current Event for this analysis page, or None if the id is invalid."""
    event_id = get_current_event_id()
    if event_id is None:
        return None

    try:
        # Allow getting an event by ID or UUID. This can't be combined into a single query since if you pass it a UUID
        # that happens to start with a number, the database will truncate everything after the number and will use
        # that as the ID. Example: 443c2e1a-719b-4f5d-b52a-feea593095fb -> Event.id == 443
        # This causes the wrong event page to load.
        try:
            int(event_id)
            result = get_db().query(Event).filter(Event.id == event_id).one()
        except ValueError:
            result = get_db().query(Event).filter(Event.uuid == event_id).one()

        if current_user.timezone:
            result.display_timezone = pytz.timezone(current_user.timezone)
        return result
    except Exception as e:
        logging.error(f"Could not get event {event_id}: {e}")

    return None