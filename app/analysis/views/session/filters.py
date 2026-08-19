from datetime import timedelta
import logging
import os
from typing import Union
import yaml
from flask import session
from flask_login import current_user
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import distinct, func

from app.filters import AutoTextFilter, BoolFilter, DateRangeFilter, MultiSelectFilter, SelectFilter, TextFilter, TypeValueFilter
from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_global_runtime_settings
from aceapi_v2.sync import run_async
from aceapi_v2.observable_types.service import get_observable_types
from saq.constants import REMEDIATION_STATUS_GUI, VALID_DISPOSITIONS, VALID_DISPOSITION_REVIEWS
from saq.database.model import DispositionBy, Observable, ObservableMapping, ObservableRemediationMapping, Owner, RemediatedBy, Remediation, Tag, TagMapping
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert
from saq.util.time import local_time


def _default_filters() -> list:
    """The filter list the "Reset" action applies: open (or unowned) alerts, owned by no
    one or by the current user, in the current user's default queue. Factored out so the
    reset-alert notification dot (get_reset_filter_alert_count()) can count against the
    exact same criteria without touching session state."""
    return [
        { "name": "Disposition", "inverted": False, "values": [ "OPEN" ] },
        { "name": "Owner", "inverted": False, "values": [ "None", current_user.display_name ] },
        { "name": "Queue", "inverted": False, "values": [ current_user.queue ] },
    ]

def _reset_filters():
    session["filters"] = _default_filters()
    session["search"] = None

def get_reset_filter_alert_count() -> int:
    """Returns the number of alerts matching the "Reset" filter for the current user. Used
    to drive the browser-tab notification dot -- see reset_filter_alert_count() in
    app/analysis/views/manage.py."""
    return count_alerts(_default_filters())

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

def has_filter(filters: list, name: str) -> bool:
    """Returns True if `filters` (a session['filters']-shaped list) contains a filter
    with this name."""
    return any(_filter["name"] == name for _filter in filters or [])

def hasFilter(name):
    return has_filter(session.get('filters', []), name)

# the filter names create_filter() and getFilters() support. Quick filter config is
# validated against this so a typo'd name can never reach session['filters'], where it
# would make create_filter() raise KeyError on every subsequent /manage load. Kept in
# sync with the two dicts below by test_filter_names_match_get_filters.
FILTER_NAMES = frozenset([
    'Alert Date',
    'Alert Type',
    'Description',
    'Disposition',
    'Disposition By',
    'Disposition Date',
    'Event Date',
    'Observable',
    'Owner',
    'Queue',
    'Reviewed',
    'Tag',
])

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

def build_alert_query(filters: list):
    """Builds the GUIAlert query for a session['filters']-shaped list: the joins those
    filters require, the filter conditions themselves, and this node's alert visibility
    scoping.

    """
    query = get_db().query(GUIAlert).with_labels()
    query = query.outerjoin(Owner, GUIAlert.owner_id == Owner.id)
    if has_filter(filters, 'Disposition By'):
        query = query.outerjoin(DispositionBy, GUIAlert.disposition_user_id == DispositionBy.id)
    if has_filter(filters, 'Remediated By'):
        query = query.outerjoin(RemediatedBy, GUIAlert.removal_user_id == RemediatedBy.id)

    if has_filter(filters, 'Observable') or has_filter(filters, 'Remediation Status'):
        query = query.outerjoin(ObservableMapping)\
            .outerjoin(Observable)\
            .outerjoin(ObservableRemediationMapping)\
            .outerjoin(Remediation)

    if has_filter(filters, 'Tag'):
        query = query.outerjoin(TagMapping, GUIAlert.id == TagMapping.alert_id).join(Tag, TagMapping.tag_id == Tag.id)

    # apply filters
    for filter_dict in filters:
        _filter = create_filter(filter_dict["name"], inverted=filter_dict.get("inverted", False))
        query = _filter.apply(query, filter_dict["values"])

    # only show alerts from this node
    # NOTE: this will not be necessary once alerts are stored externally
    if get_config().gui.local_node_only:
        query = query.filter(GUIAlert.location == get_global_runtime_settings().saq_node)
    elif get_config().gui.display_node_list:
        # alternatively we can display alerts for specific nodes
        # this was added on 05/02/2023 to support a DR mode of operation
        query = query.filter(GUIAlert.location.in_(get_config().gui.display_node_list))

    return query

def count_alerts(filters: list) -> int:
    """Returns the number of alerts matching a session['filters']-shaped list. Counts
    distinct alert ids because the Tag and Observable joins can produce more than one row
    per alert."""
    count_query = build_alert_query(filters).statement.with_only_columns(func.count(distinct(GUIAlert.id)))
    return get_db().execute(count_query).scalar()

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

#
# quick filters
#
# The badges on the alert management page filter bar. Each one is just a named set of
# session filters that gets loaded into session['filters'] when clicked, optionally with
# a dot showing how many alerts it would show. See etc/gui_quick_filters.yaml.
#

# resolved against the logged in user when a quick filter is applied
QUICK_FILTER_USER_QUEUE = "$USER_QUEUE"
QUICK_FILTER_USER = "$USER"

class QuickFilterEntry(BaseModel):
    """One entry of a quick filter's `filters` list -- the same {name, inverted, values}
    shape the GUI's own filter editor writes into session['filters']."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="a filter name supported by create_filter()")
    inverted: bool = Field(default=False, description="negate this filter")
    # str for every filter except Observable, whose values are [type, value] pairs
    values: list[Union[str, list[str]]] = Field(min_length=1, description="the values to filter on")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in FILTER_NAMES:
            raise ValueError(f"unknown filter name {value!r} (expected one of {', '.join(sorted(FILTER_NAMES))})")

        return value

class QuickFilter(BaseModel):
    """A quick-filter badge definition."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    # the id goes into a URL path and a DOM attribute, so keep it to safe characters
    id: str = Field(pattern=r"^[A-Za-z0-9_-]+$", description="unique identifier for this quick filter")
    label: str = Field(min_length=1, description="the text shown on the badge")
    filters: list[QuickFilterEntry] = Field(min_length=1, description="the filters applied when the badge is clicked")
    indicator: bool = Field(default=False, description="show a dot with the number of alerts this badge would show")

# cache for get_quick_filters(): the parsed quick-filter list, the mtime of the file it
# was parsed from, and the path it was loaded from. The file is only re-read when its
# mtime changes (or the configured path changes), mirroring ACE's
# store-mtime/compare-on-next-access reload idiom (see saq/whitelist.py). This is what
# lets an analyst edit the file and see the change on the next page load.
_quick_filters_cache: list = []
_quick_filters_mtime: float | None = None
_quick_filters_path: str | None = None

def parse_quick_filters(data, path: str) -> list[QuickFilter]:
    """Validates the parsed contents of a quick filters config file. Invalid entries are
    logged and dropped rather than raising."""
    if not isinstance(data, dict):
        logging.error(f"quick filters config {path} is not a mapping")
        return []

    result = []
    seen_ids = set()
    for index, entry in enumerate(data.get("quick_filters") or []):
        try:
            quick_filter = QuickFilter.model_validate(entry)
        except ValidationError as e:
            logging.error(f"ignoring invalid quick filter at index {index} of {path}: {e}")
            continue

        if quick_filter.id in seen_ids:
            logging.warning(f"ignoring duplicate quick filter id {quick_filter.id} in {path}")
            continue

        seen_ids.add(quick_filter.id)
        result.append(quick_filter)

    return result

def get_quick_filters() -> list[QuickFilter]:
    """Loads the GUI quick-filter badge definitions (see etc/gui_quick_filters.yaml for
    the schema). Deployments point gui.quick_filters_config_path at a site-specific file
    to add or edit badges without an ACE code change. The file is re-read whenever its
    mtime changes, so those edits take effect on the next page load with no GUI restart,
    but an unchanged file is not re-parsed on every call."""
    global _quick_filters_cache, _quick_filters_mtime, _quick_filters_path

    path = os.path.join(get_base_dir(), get_config().gui.quick_filters_config_path)
    try:
        mtime = os.path.getmtime(path)
    except OSError as e:
        # missing or unreadable file -- no quick filters. only complain when this is news,
        # otherwise we log on every page load.
        if path != _quick_filters_path or _quick_filters_mtime is not None:
            logging.error(f"unable to read quick filters config {path}: {e}")

        _quick_filters_cache = []
        _quick_filters_mtime = None
        _quick_filters_path = path
        return []

    # cache hit: same file, same mtime -- don't touch disk
    if path == _quick_filters_path and mtime == _quick_filters_mtime:
        return _quick_filters_cache

    try:
        with open(path, 'r') as fp:
            data = yaml.safe_load(fp) or {}
    except Exception as e:
        logging.error(f"failed to load quick filters config {path}: {e}")
        # leave the previously cached good copy in place on a transient parse error rather
        # than poisoning it
        return _quick_filters_cache

    _quick_filters_cache = parse_quick_filters(data, path)
    _quick_filters_mtime = mtime
    _quick_filters_path = path
    return _quick_filters_cache

def resolve_quick_filter_value(value):
    """Resolves the sentinels a quick filter can use to refer to the logged in user."""
    if value == QUICK_FILTER_USER_QUEUE:
        return current_user.queue

    if value == QUICK_FILTER_USER:
        return current_user.display_name

    if isinstance(value, list):
        return [resolve_quick_filter_value(_) for _ in value]

    return value

def resolve_quick_filter_filters(quick_filter: QuickFilter) -> list:
    """Turns a quick filter into the session['filters'] shape: sentinels resolved against
    the logged in user, and entries sharing a name+inverted merged into one.

    The merge matters: session filters are ANDed together (see build_alert_query), so two
    separate Queue entries would match nothing. The GUI's own add_filter route merges them
    the same way via get_existing_filter()."""
    result = []
    merged_by_key = {}
    for entry in quick_filter.filters:
        key = (entry.name, entry.inverted)
        values = [resolve_quick_filter_value(_) for _ in entry.values]
        if key in merged_by_key:
            merged_by_key[key]["values"].extend(values)
            continue

        merged = {"name": entry.name, "inverted": entry.inverted, "values": values}
        merged_by_key[key] = merged
        result.append(merged)

    return result

def _reset_filters_quick(filter_id: str) -> bool:
    """Applies the named quick filter to the session. Returns False if no quick filter
    with that id is configured."""
    for quick_filter in get_quick_filters():
        if quick_filter.id == filter_id:
            session["filters"] = resolve_quick_filter_filters(quick_filter)
            session["search"] = None
            return True

    return False

def get_quick_filter_indicator_count(quick_filter: QuickFilter) -> int:
    """Returns the number of alerts a quick filter's badge would show. This runs the
    badge's own filters through the same build_alert_query() the alert management page
    uses, so the indicator dot cannot disagree with the list you get when you click it."""
    return count_alerts(resolve_quick_filter_filters(quick_filter))

def get_quick_filter_display_data() -> list:
    """Returns the quick-filter badge data for the alert management page. Builds fresh
    dicts rather than annotating the cached QuickFilter objects, since indicator_count is
    per-user and per-request."""
    return [
        {
            "id": quick_filter.id,
            "label": quick_filter.label,
            "indicator_count": get_quick_filter_indicator_count(quick_filter) if quick_filter.indicator else 0,
        }
        for quick_filter in get_quick_filters()
    ]