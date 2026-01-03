from datetime import timedelta
from flask import session
from flask_login import current_user

from app.filters import AutoTextFilter, BoolFilter, DateRangeFilter, MultiSelectFilter, SelectFilter, TextFilter, TypeValueFilter
from saq.configuration.config import get_config
from saq.constants import REMEDIATION_STATUS_GUI, VALID_DISPOSITIONS, VALID_OBSERVABLE_TYPES
from saq.database.model import DispositionBy, Observable, Owner, RemediatedBy, Remediation, Tag
from saq.gui.alert import GUIAlert
from saq.util.time import local_time


def _reset_filters():
    session["filters"] = [
        { "name": "Disposition", "inverted": False, "values": [ "OPEN" ] },
        { "name": "Owner", "inverted": False, "values": [ "None", current_user.display_name ] },
        { "name": "Queue", "inverted": False, "values": [ current_user.queue ] },
    ]
    session["search"] = None

def _reset_filters_special(hours: int):
    start = (local_time() - timedelta(hours=hours)).strftime("%m-%d-%Y %H:%M")
    end = local_time().strftime("%m-%d-%Y %H:%M")
    session["filters"] = [
        { "name": "Queue", "inverted": False, "values": [ current_user.queue ] },
        { "name": "Alert Date", "inverted": False, "values": [ f"{start} - {end}" ] },
    ]
    session["search"] = None

def reset_checked_alerts():
    session['checked'] = []

def reset_sort_filter():
    session['sort_filter'] = 'Alert Date'
    session['sort_filter_desc'] = True

def reset_pagination():
    session['page_offset'] = 0
    if 'page_size' not in session:
        session['page_size'] = 50

def hasFilter(name):
    _filters = session.get('filters', [])
    if not _filters:
        return False

    for _filter in _filters:
        if _filter["name"] == name:
            return True

    return False

def create_filter(filter_name: str, inverted: bool):
    return {
        'Alert Date': DateRangeFilter(GUIAlert.insert_date, inverted=inverted),
        'Alert Type': SelectFilter(GUIAlert.alert_type, inverted=inverted),
        'Description': TextFilter(GUIAlert.description, inverted=inverted),
        'Disposition': MultiSelectFilter(GUIAlert.disposition, nullable=False, options=VALID_DISPOSITIONS, inverted=inverted),
        'Disposition By': SelectFilter(DispositionBy.display_name, nullable=True, inverted=inverted),
        'Disposition Date': DateRangeFilter(GUIAlert.disposition_time, inverted=inverted),
        'Event Date': DateRangeFilter(GUIAlert.event_time, inverted=inverted),
        'Observable': TypeValueFilter(Observable.type, Observable.value, options=VALID_OBSERVABLE_TYPES, inverted=inverted),
        'Owner': SelectFilter(Owner.display_name, nullable=True, inverted=inverted),
        'Queue': SelectFilter(GUIAlert.queue, inverted=inverted),
        #'Remediated By': SelectFilter(RemediatedBy.display_name, nullable=True, inverted=inverted),
        #'Remediated Date': DateRangeFilter(GUIAlert.removal_time, inverted=inverted),
        #'Remediation Status': BoolFilter(Remediation.status, nullable=True, option_names=REMEDIATION_STATUS_GUI, inverted=inverted),
        'Tag': AutoTextFilter(Tag.name, case_sensitive=False, wildcardable=True, inverted=inverted),
    }[filter_name]

def getFilters():
    return {
        'Alert Date': DateRangeFilter(GUIAlert.insert_date),
        'Alert Type': SelectFilter(GUIAlert.alert_type),
        'Description': TextFilter(GUIAlert.description),
        'Disposition': MultiSelectFilter(GUIAlert.disposition, nullable=False, options=VALID_DISPOSITIONS),
        'Disposition By': SelectFilter(DispositionBy.display_name, nullable=True),
        'Disposition Date': DateRangeFilter(GUIAlert.disposition_time),
        'Event Date': DateRangeFilter(GUIAlert.event_time),
        'Observable': TypeValueFilter(Observable.type, Observable.value, options=VALID_OBSERVABLE_TYPES),
        'Owner': SelectFilter(Owner.display_name, nullable=True),
        'Queue': SelectFilter(GUIAlert.queue),
        #'Remediated By': SelectFilter(RemediatedBy.display_name, nullable=True),
        #'Remediated Date': DateRangeFilter(GUIAlert.removal_time),
        #'Remediation Status': BoolFilter(Remediation.status, nullable=True, option_names=REMEDIATION_STATUS_GUI),
        'Tag': AutoTextFilter(Tag.name, case_sensitive=False, wildcardable=True),
    }

def filter_special_tags(tags):
    # we don't show "special" tags in the display
    special_tag_names = [tag for tag in get_config().tags.keys() if get_config().tags[tag] == 'special']
    return [tag for tag in tags if tag not in special_tag_names]

def get_existing_filter(filter_name: str, inverted: bool):
    filters = session.get("filters")
    if not filters:
        return None

    for _filter in filters:
        if _filter["name"] == filter_name and _filter["inverted"] == inverted:
            return _filter

    return None