import logging
from flask import request
from flask_login import current_user
import pytz

from saq.database.pool import get_db
from saq.gui.alert import GUIAlert


def get_current_alert_uuid():
    """Returns the current alert UUID the analyst is looking at, or None if they are not looking at anything."""
    target_dict = request.form if request.method == 'POST' else request.args

    # either direct or alert_uuid are used
    if 'direct' in target_dict:
        return target_dict['direct']
    elif 'alert_uuid' in target_dict:
        return target_dict['alert_uuid']

    logging.debug("missing direct or alert_uuid in get_current_alert for user {0}".format(current_user))
    return None

def get_current_alert():
    """Returns the current Alert for this analysis page, or None if the uuid is invalid."""
    alert_uuid = get_current_alert_uuid()
    if alert_uuid is None:
        return None

    try:
        result = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
        if current_user.timezone:
            result.display_timezone = pytz.timezone(current_user.timezone)


        return result

    except Exception as e:
        logging.info(f"couldn't get alert {alert_uuid}: {e}")

    return None
