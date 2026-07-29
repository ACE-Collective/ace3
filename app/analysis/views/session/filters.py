import copy
from datetime import timedelta
import logging
import os
import yaml
from flask import session
from flask_login import current_user

from app.filters import AutoTextFilter, BoolFilter, DateRangeFilter, MultiSelectFilter, SelectFilter, TextFilter, TypeValueFilter
from saq.configuration.config import get_config
from saq.environment import get_base_dir
from aceapi_v2.sync import run_async
from aceapi_v2.observable_types.service import get_observable_types
from saq.constants import REMEDIATION_STATUS_GUI, VALID_DISPOSITIONS, VALID_DISPOSITION_REVIEWS
from saq.database.model import DispositionBy, Observable, Owner, RemediatedBy, Remediation, Tag, TagMapping
from saq.database.pool import get_db
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

# cache for get_quick_filters(): the parsed quick-filter list, the mtime of the
# file it was parsed from, and the path it was loaded from. The file is only
# re-read when its mtime changes (or the configured path changes), mirroring
# ACE's store-mtime/compare-on-next-access reload idiom (see saq/whitelist.py).
_quick_filters_cache: list = []
_quick_filters_mtime: float | None = None
_quick_filters_path: str | None = None

def get_quick_filters() -> list:
    """Loads GUI quick-filter badge definitions (see etc/gui_quick_filters.yaml
    for the schema). Deployments point gui.quick_filters_config_path at a
    site-specific file to add/edit quick filters without an ACE code change.
    The file is reloaded whenever its mtime changes, so those edits take effect
    on the next page load with no GUI restart -- but we avoid re-parsing the
    YAML on every call when the file is unchanged."""
    global _quick_filters_cache, _quick_filters_mtime, _quick_filters_path

    path = os.path.join(get_base_dir(), get_config().gui.quick_filters_config_path)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        # missing or unreadable file -- preserve the "return []" behavior and
        # drop any previously cached values so we re-check on the next call.
        _quick_filters_cache = []
        _quick_filters_mtime = None
        _quick_filters_path = path
        return []

    # cache hit: same file, same mtime -- return a copy without touching disk.
    if not (path == _quick_filters_path and mtime == _quick_filters_mtime):
        try:
            with open(path, 'r') as fp:
                data = yaml.safe_load(fp) or {}
        except Exception as e:
            logging.warning(f"failed to load quick filters config {path}: {e}")
            # leave the previously cached good copy in place on a transient
            # parse error rather than poisoning it.
            return copy.deepcopy(_quick_filters_cache)

        _quick_filters_cache = data.get('quick_filters', []) or []
        _quick_filters_mtime = mtime
        _quick_filters_path = path

    # return a deep copy so callers (e.g. manage.py, which writes a per-user
    # 'indicator_count' into each dict) can mutate their result without
    # corrupting the shared cache across concurrent requests.
    return copy.deepcopy(_quick_filters_cache)

def _resolve_quick_filter_values(values: list) -> list:
    return [current_user.queue if value == "$USER_QUEUE" else value for value in values]

def _reset_filters_quick(filter_id: str) -> bool:
    """Applies the named quick filter's session_filters. Returns False if no
    quick filter with that id is configured."""
    for quick_filter in get_quick_filters():
        if quick_filter.get('id') == filter_id:
            session["filters"] = [
                {
                    "name": session_filter["name"],
                    "inverted": session_filter.get("inverted", False),
                    "values": _resolve_quick_filter_values(session_filter.get("values", [])),
                }
                for session_filter in quick_filter.get("session_filters", [])
            ]
            session["search"] = None
            return True

    return False

def get_quick_filter_indicator_count(indicator: dict) -> int:
    """Computes the alert count for a quick filter's indicator dot definition.
    Supported keys: tag (str), queue (str), disposition (str), owned_only (bool).
    A quick filter with no `indicator` key configured never shows a dot (see
    manage.py, which only calls this when quick_filter.get('indicator') is set).
    The `queue` key accepts the "$USER_QUEUE" sentinel, resolved to the current
    user's default queue."""
    query = get_db().query(GUIAlert)
    if indicator.get('tag'):
        query = query.join(TagMapping, GUIAlert.id == TagMapping.alert_id)\
            .join(Tag, TagMapping.tag_id == Tag.id)\
            .filter(Tag.name == indicator['tag'])
    if indicator.get('queue'):
        queue = current_user.queue if indicator['queue'] == "$USER_QUEUE" else indicator['queue']
        query = query.filter(GUIAlert.queue == queue)
    if indicator.get('disposition'):
        query = query.filter(GUIAlert.disposition == indicator['disposition'])
    if indicator.get('reviewed'):
        query = query.filter(GUIAlert.disposition_review == indicator['reviewed'])
    if indicator.get('owned_only'):
        query = query.filter(GUIAlert.owner_id == current_user.id)
    return query.count()

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
        'Observable': TypeValueFilter(Observable.type, Observable.value, options=run_async(get_observable_types()), inverted=inverted),
        'Owner': SelectFilter(Owner.display_name, nullable=True, inverted=inverted),
        'Queue': SelectFilter(GUIAlert.queue, inverted=inverted),
        'Reviewed': MultiSelectFilter(GUIAlert.disposition_review, nullable=False, options=VALID_DISPOSITION_REVIEWS, inverted=inverted),
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
        'Observable': TypeValueFilter(Observable.type, Observable.value, options=run_async(get_observable_types())),
        'Owner': SelectFilter(Owner.display_name, nullable=True),
        'Queue': SelectFilter(GUIAlert.queue),
        'Reviewed': MultiSelectFilter(GUIAlert.disposition_review, nullable=False, options=VALID_DISPOSITION_REVIEWS),
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