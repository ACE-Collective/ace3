import logging
from flask import g, session
from flask_login import current_user
from sqlalchemy import distinct, func

from app.filters import AutoTextFilter, DateRangeFilter, MultiSelectFilter, SelectFilter, TextFilter, TypeValueFilter
from saq.configuration.config import get_config
from saq.environment import get_global_runtime_settings
from aceapi_v2.sync import run_async, run_async_with_session
from aceapi_v2.observable_types.service import get_observable_types
from aceapi_v2.saved_filters import service as saved_filters_service
from aceapi_v2.saved_filters.schemas import FilterEntry, ScratchFilterWrite
from aceapi_v2.saved_filters.service import KIND_TEMP, KIND_WORKING
from saq.constants import VALID_DISPOSITIONS, VALID_DISPOSITION_REVIEWS
from saq.database.model import DispositionBy, Observable, ObservableMapping, ObservableRemediationMapping, Owner, RemediatedBy, Remediation, Tag, TagMapping
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert


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
    """The "Reset" action. Delegates to clear_filter_state() so there is exactly one place
    that knows how to put the session back to the built-in default."""
    clear_filter_state()

def get_reset_filter_alert_count() -> int:
    """Returns the number of alerts matching the "Reset" filter for the current user. Used
    to drive the browser-tab notification dot -- see reset_filter_alert_count() in
    app/analysis/views/manage.py."""
    return count_alerts(_default_filters())

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
    """Returns True if `filters` (a filter list) contains a filter with this name."""
    return any(_filter["name"] == name for _filter in filters or [])

def hasFilter(name):
    return has_filter(session.get('filters', []), name)

# The set of valid filter names lives in saq/gui/filter_names.py (FILTER_NAMES) so that
# aceapi_v2 can validate stored and URL-supplied filters against it without importing app
# (which would pull in flask_login). It is kept in sync with the two dicts below by
# test_filter_names_match_get_filters.

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
    """Builds the GUIAlert query for a filter list: the joins those
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
    """Returns the number of alerts matching a filter list. Counts
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
# filter sentinels
#
# $USER / $USER_QUEUE are resolved against whoever is logged in, at READ time, never at
# write time -- so the sentinel survives round-tripping through both the database and a
# share URL. That is what makes a link portable: a runbook link written as
# `queue:$USER_QUEUE` shows each reader their OWN queue rather than the author's.
#

QUICK_FILTER_USER_QUEUE = "$USER_QUEUE"
QUICK_FILTER_USER = "$USER"


def resolve_filter_sentinels(value):
    """Resolve the sentinels a stored or shared filter can use to refer to the viewer."""
    if value == QUICK_FILTER_USER_QUEUE:
        return current_user.queue

    if value == QUICK_FILTER_USER:
        return current_user.display_name

    if isinstance(value, list):
        return [resolve_filter_sentinels(_) for _ in value]

    return value


def resolve_saved_filter(filters: list) -> list:
    """Prepare a stored filter list for querying: sentinels resolved against the logged in
    user, and entries sharing a name+inverted merged into one.

    The merge matters. Filter entries are ANDed together (see build_alert_query), so two
    separate Queue entries would match nothing at all rather than either queue."""
    result = []
    merged_by_key = {}
    for entry in filters or []:
        key = (entry["name"], entry.get("inverted", False))
        values = [resolve_filter_sentinels(_) for _ in entry["values"]]
        if key in merged_by_key:
            merged_by_key[key]["values"].extend(values)
            continue

        merged = {"name": entry["name"], "inverted": entry.get("inverted", False), "values": values}
        merged_by_key[key] = merged
        result.append(merged)

    return result


#
# filter state
#
# The session holds UUIDs ONLY Filter contents live in the saved_filters table and are resolved per
# request. 
#
#   filter_uuid          the EFFECTIVE filter row driving the alert list (any kind)
#   filter_base_uuid     the named filter the analyst considers current; None = default
#   filter_state         'clean' | 'dirty' | 'temp'
#   filter_restore_uuid  what Revert returns to; set only while temp
#

FILTER_STATE_CLEAN = "clean"
FILTER_STATE_DIRTY = "dirty"
FILTER_STATE_TEMP = "temp"

# only these keys are filter state; used by tests to assert nothing else creeps in
FILTER_SESSION_KEYS = ("filter_uuid", "filter_base_uuid", "filter_state", "filter_restore_uuid")


def _write_scratch(kind: str, filters: list, label: str | None = None):
    """Persist a scratch row for the current user and return its uuid."""
    result = run_async_with_session(
        saved_filters_service.upsert_scratch_filter,
        current_user.id,
        kind,
        ScratchFilterWrite(filters=filters, label=label),
    )
    return result.uuid


def _read_filters(filter_uuid: str) -> list | None:
    """Return the filter list for a uuid, or None if it is gone or not ours."""
    if not filter_uuid:
        return None

    result = run_async_with_session(
        saved_filters_service.get_saved_filter, filter_uuid, current_user.id)
    if result is None:
        return None

    return [entry.model_dump() for entry in result.filters]


def get_current_filter() -> dict:
    """Display data for the filter bar: which named filter is in play and how it stands."""
    base_uuid = session.get("filter_base_uuid")
    name = None
    if base_uuid:
        result = run_async_with_session(
            saved_filters_service.get_saved_filter, base_uuid, current_user.id)
        # the base filter can be deleted out from under us; fall back rather than lie
        name = result.name if result else None
        if result is None:
            session["filter_base_uuid"] = None
            base_uuid = None

    return {
        "uuid": base_uuid,
        "name": name,
        "state": session.get("filter_state", FILTER_STATE_CLEAN),
    }


def get_temp_filter() -> dict | None:
    """The temporary-filter banner data, or None when no temp is active."""
    if session.get("filter_state") != FILTER_STATE_TEMP:
        return None

    result = run_async_with_session(
        saved_filters_service.get_saved_filter, session.get("filter_uuid"), current_user.id)
    return {"label": (result.description if result else None) or "Modified filter"}


def get_effective_filters() -> list:
    """The filter list currently driving the alert list."""

    # Resolves session['filter_uuid'] against the database, resolving $USER sentinels against
    # whoever is logged in. Memoized per request: build_manage_list_context() and the CSV
    # export both call this, and it must not issue the same query twice.

    # A missing row is NOT an error. The analyst can delete the filter they had selected, and
    # a cookie can outlive a database reset. Either way we fall back to the default working
    # set rather than 500 on a page they cannot escape from without clearing cookies.

    if "ace_effective_filters" in g.__dict__:
        return g.ace_effective_filters

    filters = _read_filters(session.get("filter_uuid"))
    if filters is None:
        filters = _default_filters()
        _select_working(filters)
        session["filter_base_uuid"] = None
        session["filter_state"] = FILTER_STATE_CLEAN
        session.pop("filter_restore_uuid", None)

    resolved = resolve_saved_filter(filters)
    g.ace_effective_filters = resolved
    return resolved


def _invalidate_effective_filters():
    g.__dict__.pop("ace_effective_filters", None)


def _select_working(filters: list):
    session["filter_uuid"] = _write_scratch(KIND_WORKING, filters)
    # keep the state keys consistently present so callers never have to guess whether a
    # missing key means "no named filter" or "never initialised"
    session.setdefault("filter_base_uuid", None)
    session.setdefault("filter_restore_uuid", None)
    session.setdefault("filter_state", FILTER_STATE_CLEAN)
    _invalidate_effective_filters()


def select_saved_filter(filter_uuid: str) -> bool:
    """Apply a named saved filter as the analyst's persistent selection."""
    if _read_filters(filter_uuid) is None:
        return False

    session["filter_uuid"] = filter_uuid
    session["filter_base_uuid"] = filter_uuid
    session["filter_state"] = FILTER_STATE_CLEAN
    session["filter_restore_uuid"] = None
    session.pop("filter_restore_state", None)
    _invalidate_effective_filters()
    return True


def write_working_filters(filters: list):
    """Apply an explicit edit. Writes the scratch row, never a named one -- persisting to a
    named filter only ever happens through Save or Save as."""
    if is_temporary_filter_active():
        # editing while a temp is active refines the temp, leaving the analyst's real
        # filter untouched and still restorable
        session["filter_uuid"] = _write_scratch(KIND_TEMP, filters, _temp_label())
        _invalidate_effective_filters()
        return

    _select_working(filters)
    session["filter_state"] = FILTER_STATE_DIRTY


def apply_temporary_filter(filters: list, label: str):
    """Apply a filter WITHOUT touching the analyst's persistent selection."""

    # This is what a pivot (clicking an observable, tag, owner, disposition) and an opened
    # share link do. filter_base_uuid is deliberately not touched, so Revert restores the
    # analyst's named filter exactly as it was.

    if not is_temporary_filter_active():
        # first temp only: preserve what to go back to. A second pivot must NOT overwrite
        # this, or Revert would land on the first pivot instead of the real filter.
        session["filter_restore_uuid"] = session.get("filter_uuid")
        session["filter_restore_state"] = session.get("filter_state", FILTER_STATE_CLEAN)

    session["filter_uuid"] = _write_scratch(KIND_TEMP, filters, label)
    session["filter_state"] = FILTER_STATE_TEMP
    _invalidate_effective_filters()


def is_temporary_filter_active() -> bool:
    return session.get("filter_state") == FILTER_STATE_TEMP


def _temp_label() -> str | None:
    temp = get_temp_filter()
    return temp["label"] if temp else None


def revert_temporary_filter() -> bool:
    """Discard the temporary filter and restore what the analyst was using."""
    if not is_temporary_filter_active():
        return False

    session["filter_uuid"] = session.get("filter_restore_uuid")
    session["filter_restore_uuid"] = None
    session["filter_state"] = session.pop("filter_restore_state", FILTER_STATE_CLEAN)
    _invalidate_effective_filters()

    # the restored row can itself have been deleted meanwhile; get_effective_filters()
    # repairs that on the next read
    return True


def clear_filter_state():
    """Reset to the built-in default set."""
    session["filter_base_uuid"] = None
    session["filter_restore_uuid"] = None
    session.pop("filter_restore_state", None)
    session["filter_state"] = FILTER_STATE_CLEAN
    session["search"] = None
    _select_working(_default_filters())


def migrate_legacy_session_filters():
    """Carry an in-flight pre-upgrade cookie over to a scratch row.

    Analysts will be mid-triage when this ships, holding a cookie with the old
    session['filters'] list. Without this their carefully built filter silently resets on
    the first page load after deploy. Removable a release later."""
    legacy = session.pop("filters", None)
    if session.get("filter_uuid") or not legacy:
        return

    try:
        _select_working([FilterEntry.model_validate(entry).model_dump() for entry in legacy])
        session["filter_state"] = FILTER_STATE_CLEAN
        logging.info("migrated legacy session filters for user %s", current_user.id)
    except Exception as e:
        # a malformed legacy cookie must not lock the analyst out of /manage
        logging.warning("could not migrate legacy session filters: %s", e)


#
# quick filters
#
# The badges on the alert management page filter bar. Each one is a saved filter the
# analyst chose to pin, in the order they chose. This replaced a global YAML config file
# that analysts could not edit.
#

def get_saved_filter_list() -> list:
    """The current user's named saved filters, pinned ones first in badge order."""
    return run_async_with_session(
        saved_filters_service.get_saved_filters_for_user, current_user.id)


def seed_default_saved_filters():
    """Give a brand-new analyst their Last 24h / Last 7d filters.

    This WRITES, so it must only be called from a real page render -- never from the polled
    refresh endpoint (docs/GUI_DATASTAR.md). It must also run BEFORE the working row is
    created, because the guard is "this user has no filter rows at all"."""
    run_async_with_session(saved_filters_service.ensure_default_saved_filters, current_user.id)


def get_quick_filter_display_data(saved_filters: list) -> list:
    """Badge data for the filter bar, built from the caller's pinned saved filters.

    The indicator count runs the badge's own filters through the same build_alert_query()
    the alert list uses, so the dot cannot disagree with what you get when you click it.
    Each count is a full joined query, so this is only ever called from a real page render
    -- see the note in build_manage_list_context()."""
    return [
        {
            "uuid": saved_filter.uuid,
            "label": saved_filter.name,
            "indicator_count": (
                count_alerts(resolve_saved_filter([e.model_dump() for e in saved_filter.filters]))
                if saved_filter.quick_filter_indicator else 0
            ),
        }
        for saved_filter in saved_filters
        if saved_filter.quick_filter_order is not None
    ]
