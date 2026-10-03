"""The alert management filter query builder.

A *filter list* is the universal shape the GUI editor produces, the `saved_filters` table
stores, a share link encodes (`saq/gui/filter_url.py`) and the API accepts:

    [{"name": "Observable", "inverted": False, "values": [["ip", "1.2.3.4"]]}, ...]

Entries are ANDed; the values inside one entry are ORed. `build_alert_query()` turns such a
list into the SQLAlchemy query the alert list, the CSV export, the quick-filter badge counts
and the search API all run.

This lives in `saq/gui/` rather than `app/` for the same reason `filter_names.py` does: the
FastAPI layer needs to run these filters, and importing `app` would pull in flask_login and a
request context that does not exist outside a browser request. Nothing here reads
`current_user` or `request` -- the caller passes the analyst's timezone and node scoping in.

`app/filters.py` re-exports the filter classes and keeps only the form-state helper that is
genuinely tied to a Flask request.
"""

import datetime
import hashlib
from functools import cached_property

import pytz
from sqlalchemy import LABEL_STYLE_TABLENAME_PLUS_COL, and_, exists, false, func, not_, or_, distinct

from saq.constants import VALID_DISPOSITION_REVIEWS
from saq.database.model import (
    Alert,
    AnalysisMapping,
    AnalysisType,
    DetectionPoint,
    DispositionBy,
    Observable,
    ObservableMapping,
    ObservableRemediationMapping,
    Owner,
    RemediatedBy,
    Remediation,
    Tag,
    TagMapping,
)
from saq.database.pool import get_db
from saq.database.util.alert import node_scope_locations
from saq.database.util.observable_detection import (
    InvalidDetectionValue,
    resolve_observable_identity,
)
from saq.disposition import get_dispositions
from saq.gui.detection_point_value import parse_detection_point_value
from saq.observables.type_hierarchy import get_all_valid_types
from saq.util.relative_time import parse_date_range

# the TypeValueFilter option meaning "any observable type with this value"
ANY_OBSERVABLE_TYPE = 'Any'

# sentinel distinguishing "scope to this node" (the default) from an explicit "do not scope"
_DEFAULT_LOCATIONS = object()


# exact match, provides text input
class Filter:
    # `entity` is the mapped class (or alias) the query selects. Only the filters that test a
    # mapping table with a correlated EXISTS (Tag, Detection Point, Analysis, Observable) use
    # it: the subquery has to correlate to the outer query's own entity, which is not `Alert`
    # when the caller selects an alias of it.
    def __init__(self, column, nullable=False, case_sensitive=True, wildcardable=False, inverted=False, entity=None):
        self.column = column
        self.nullable = nullable
        self.wildcardable = wildcardable
        self.case_sensitive = case_sensitive
        self.inverted = inverted
        self.entity = entity if entity is not None else Alert

    def apply(self, query, values):
        conditions = []
        for value in values:
            if value == 'None' and self.nullable:
                conditions.append(self.column == None)
            elif self.wildcardable:
                if self.case_sensitive:
                    conditions.append(self.column.like(value.replace('*','%')))
                else:
                    conditions.append(self.column.ilike(value.replace('*','%')))
            else:
                if self.case_sensitive:
                    conditions.append(self.column == value)
                else:
                    conditions.append(self.column.ilike(value))

        # A many-to-many filter is an EXISTS over the mapping table, in both directions.
        # Inverted, EXISTS is the only form that is true for an alert with no matching rows
        # at all: `NOT (tags.name = 'x')` evaluated against a joined row is never true for
        # an untagged alert. Non-inverted it avoids the row fan-out, so two separate Tag
        # entries mean "carries both".
        if str(self.column) == "Tag.name":
            subquery = exists().where(
                and_(
                    TagMapping.tag_id == Tag.id,
                    or_(*conditions)
                )
            ).where(TagMapping.alert_id == self.entity.id).correlate(self.entity)
            return query.filter(not_(subquery) if self.inverted else subquery)

        if self.inverted:
            return query.filter(not_(or_(*conditions)))

        return query.filter(or_(*conditions))

# case insensitive contains match, provides text input
class TextFilter(Filter):
    def apply(self, query, values):
        conditions = []
        for value in values:
            conditions.append(self.column.ilike(f"%{value}%"))
        if self.inverted:
            return query.filter(not_(or_(*conditions)))
        else:
            return query.filter(or_(*conditions))

# range match, provides a date range picker
class DateRangeFilter(Filter):
    """Filters on a time window. Each value is either the absolute wire format
    "MM-DD-YYYY HH:mm - MM-DD-YYYY HH:mm" that the daterangepicker writes, or a
    Splunk-style relative range like "-7d - now" or the shorthand "-24h"."""

    # Relative values are resolved HERE, on every query, and never normalized to absolute
    # anywhere upstream -- that is what keeps a saved "Last 24h" filter meaning the last 24
    # hours. See saq/util/relative_time.py.

    # `tz` is the analyst's display timezone, passed in by the caller: "today" means something
    # different in Sydney than in New York, and this module cannot read current_user.

    def __init__(self, column, tz=None, **kwargs):
        super().__init__(column, **kwargs)
        self.tz = tz or pytz.utc

    def apply(self, query, values):
        now = datetime.datetime.now(pytz.utc)

        conditions = []
        for value in values:
            start, end = parse_date_range(value, now=now, tz=self.tz)
            conditions.append(and_(self.column >= start, self.column <= end))
        if self.inverted:
            return query.filter(not_(or_(*conditions)))
        else:
            return query.filter(or_(*conditions))

# exact match, provides drop down menu for value selection
class SelectFilter(Filter):
    def __init__(self, column, nullable=False, options=None, case_sensitive=True, wildcardable=False, inverted=False, entity=None):
        super().__init__(column, nullable=nullable, case_sensitive=case_sensitive, wildcardable=wildcardable, inverted=inverted, entity=entity)
        self.options = options if options else [r[0] for r in get_db().query(self.column).order_by(self.column.asc()).distinct()]
        if nullable and 'None' not in self.options:
            self.options.insert(0, 'None')

# exact match, provides text input with choices in dropdown while typing
class AutoTextFilter(SelectFilter):
    pass

# exact match, allows shift/control use for selecting multipl options
class MultiSelectFilter(SelectFilter):
    pass

# signature match, provides text input for "<signature uuid>[:<version>]"
class DetectionPointFilter(Filter):
    """Alerts carrying a detection point from a given signature, optionally one version of it.

    Matched against the `detection_points` table, which has `alert_id` directly, so this is an
    EXISTS over that table (served by `ix_detection_points_signature`) -- see the note in
    Filter.apply for why EXISTS is the form that inverts correctly.
    """

    def _condition(self, value: str):
        try:
            signature_uuid, signature_version = parse_detection_point_value(value)
        except ValueError:
            # a stored filter or pasted share link can carry anything; an impossible value
            # matches nothing rather than raising on every /manage load
            return false()

        if signature_version is None:
            return DetectionPoint.signature_uuid == signature_uuid

        return and_(
            DetectionPoint.signature_uuid == signature_uuid,
            DetectionPoint.signature_version == signature_version,
        )

    def apply(self, query, values):
        conditions = [self._condition(value) for value in values]
        subquery = exists().where(
            and_(
                DetectionPoint.alert_id == self.entity.id,
                or_(*conditions)
            )
        ).correlate(self.entity)
        return query.filter(not_(subquery) if self.inverted else subquery)

# analysis type match, provides drop down menu of the analysis types that have been indexed
class AnalysisFilter(Filter):
    """Alerts containing a given type of analysis, by module path (module:Class[:instance]).

    Matched against `analysis_mapping`, which records only the analysis an alert's tree
    actually shows -- see is_indexed_analysis() in saq/database/util/index.py -- so an
    analysis that ran and found nothing does not match. An EXISTS over that table; see the
    note in Filter.apply for why.
    """

    @cached_property
    def options(self) -> list[tuple[str, str]]:
        """(module_path, display_name) for every analysis type at least one alert contains, by
        display name.

        The catalog is append-only, so it also holds types whose alerts have all been deleted;
        listing only types with a mapping row keeps the dropdown to choices that can match. The
        check is one probe into analysis_mapping's analysis_type_id index per catalog row.

        Lazy rather than a constructor argument: create_filter() builds this filter for every
        query, and only the filter editor needs the list.
        """
        in_use = exists().where(AnalysisMapping.analysis_type_id == AnalysisType.id)
        return [(module_path, display_name) for module_path, display_name in
                get_db().query(AnalysisType.module_path, AnalysisType.display_name)
                .filter(in_use)
                .order_by(AnalysisType.display_name, AnalysisType.module_path)]

    def apply(self, query, values):
        # a stored filter or pasted share link can carry anything; a value that cannot be a
        # module path matches nothing rather than raising on every /manage load
        module_paths = [value for value in values if isinstance(value, str)]
        condition = AnalysisType.module_path.in_(module_paths) if module_paths else false()

        subquery = exists().where(
            and_(
                AnalysisMapping.alert_id == self.entity.id,
                AnalysisMapping.analysis_type_id == AnalysisType.id,
                condition,
            )
        ).correlate(self.entity)
        return query.filter(not_(subquery) if self.inverted else subquery)


def get_analysis_type_labels(module_paths: list) -> dict[str, str]:
    """module_path -> display_name for the given module paths, for showing an Analysis
    filter's values as labels. A path that was never indexed is simply absent."""
    module_paths = [value for value in module_paths if isinstance(value, str)]
    if not module_paths:
        return {}

    return dict(get_db().query(AnalysisType.module_path, AnalysisType.display_name)
                .filter(AnalysisType.module_path.in_(module_paths)))


# exact match, provides type drop down menu with text input for value
class TypeValueFilter(SelectFilter):
    """Alerts carrying an observable of a given type and value.

    Matched on the `(type, sha256)` unique key (`i_type_sha256`). That is the shape every
    other observable lookup in the codebase uses (`saq/database/util/index.py`,
    `aceapi_v2/observables/service.py`). The value is first normalized by
    `resolve_observable_identity()`, the same way the engine normalizes it at index time.
    """

    def __init__(self, column, value_column, sha256_column=None, options=None, case_sensitive=True, wildcardable=False, inverted=False, entity=None):
        super().__init__(column, options=options, case_sensitive=case_sensitive, wildcardable=wildcardable, inverted=inverted, entity=entity)
        self.value_column = value_column
        self.sha256_column = sha256_column if sha256_column is not None else Observable.sha256
        if ANY_OBSERVABLE_TYPE not in self.options:
            self.options.insert(0, ANY_OBSERVABLE_TYPE)

    def _condition(self, observable_type: str, observable_value: str):
        if observable_type == ANY_OBSERVABLE_TYPE:
            # No type means nothing to normalize against, so match the digest of the raw value
            # (correct for every type but `file`, whose sha256 is unhex(value)) OR the stored
            # bytes, which covers `file` and anything that does not round-trip.
            encoded = observable_value.encode('utf8', errors='ignore')
            return or_(
                self.sha256_column == hashlib.sha256(encoded).digest(),
                self.value_column == encoded,
            )

        try:
            identity = resolve_observable_identity(observable_type, observable_value)
        except InvalidDetectionValue:
            # A value that is impossible for its type matches nothing. It must not raise: a
            # saved filter or a pasted share link can carry anything, and a 500 would lock the
            # analyst out of a page they cannot escape without clearing cookies.
            return false()

        return and_(self.column == identity.type, self.sha256_column == identity.value_sha256)

    def apply(self, query, values):
        conditions = [self._condition(value[0], value[1]) for value in values]

        # EXISTS in both directions -- see the note in Filter.apply. Two Observable entries
        # ANDed have to mean "carries both observables", which a single join cannot express.
        if str(self.column) == 'Observable.type':
            subquery = exists().where(
                and_(
                    ObservableMapping.observable_id == Observable.id,
                    or_(*conditions)
                )
            ).where(ObservableMapping.alert_id == self.entity.id).correlate(self.entity)
            return query.filter(not_(subquery) if self.inverted else subquery)

        if self.inverted:
            return query.filter(not_(or_(*conditions)))

        return query.filter(or_(*conditions))


# exact match, drop down menu for value selection that defaults to True, False and uses 1, 0 for querying
# Custom menu values for True/False can be defined using arg option_names
#       Ex. my_filter = BoolFilter(my_column, option_names={'True': 'Custom_true_value', 'False': 'Custom_false_value'})
class BoolFilter(SelectFilter):
    def __init__(self, column, nullable=False, option_names: dict = None, case_sensitive=True, wildcardable=False, inverted=False):
        super().__init__(column, nullable=nullable, case_sensitive=case_sensitive, wildcardable=wildcardable, inverted=inverted)
        self.options = [option_names['True'], option_names['False']] if option_names else ['True', 'False']
        if nullable:
            self.options.insert(0, 'None')

        if option_names:
            self.option_values = {option_names['True']: 1, option_names['False']: 0}
        else:
            self.option_values = {'True': 1, 'Value': 0}

    def apply(self, query, values):
        conditions = []
        for value in values:
            if value == 'None' and self.nullable:
                conditions.append(self.column == None)
            else:
                conditions.append(self.column == self.option_values[value])

        if self.inverted:
            return query.filter(not_(or_(*conditions)))
        else:
            return query.filter(or_(*conditions))


def create_filter(filter_name: str, inverted: bool = False, *, tz=None, entity=None):
    """Builds the filter that applies `filter_name` to a query.

    `entity` is the mapped class the query selects (GUIAlert for the browser, Alert for the
    API, or an alias of either). The filters that test a mapping table correlate their
    subquery to it, so it has to be the entity the outer query selects.

    The values are thunks rather than instances: SelectFilter's constructor runs a
    SELECT DISTINCT when it is not handed an options list, and building a dict of every filter
    just to pick one ran four of those per filter entry per query.
    """
    entity = entity if entity is not None else Alert
    return {
        'Alert Date': lambda: DateRangeFilter(entity.insert_date, tz=tz, inverted=inverted),
        'Alert Type': lambda: SelectFilter(entity.alert_type, inverted=inverted),
        'Analysis': lambda: AnalysisFilter(AnalysisType.module_path, inverted=inverted, entity=entity),
        'Description': lambda: TextFilter(entity.description, inverted=inverted),
        'Detection Point': lambda: DetectionPointFilter(DetectionPoint.signature_uuid, inverted=inverted, entity=entity),
        'Disposition': lambda: MultiSelectFilter(entity.disposition, nullable=False, options=list(get_dispositions()), inverted=inverted),
        'Disposition By': lambda: SelectFilter(DispositionBy.display_name, nullable=True, inverted=inverted),
        'Disposition Date': lambda: DateRangeFilter(entity.disposition_time, tz=tz, inverted=inverted),
        'Event Date': lambda: DateRangeFilter(entity.event_time, tz=tz, inverted=inverted),
        'Observable': lambda: TypeValueFilter(Observable.type, Observable.value, Observable.sha256, options=sorted(get_all_valid_types()), inverted=inverted, entity=entity),
        'Owner': lambda: SelectFilter(Owner.display_name, nullable=True, inverted=inverted),
        'Queue': lambda: SelectFilter(entity.queue, inverted=inverted),
        'Reviewed': lambda: MultiSelectFilter(entity.disposition_review, nullable=False, options=list(VALID_DISPOSITION_REVIEWS), inverted=inverted),
        'Tag': lambda: AutoTextFilter(Tag.name, case_sensitive=False, wildcardable=True, inverted=inverted, entity=entity),
    }[filter_name]()


# $USER / $USER_QUEUE are resolved against whoever is looking, at READ time, never at write
# time -- so the sentinel survives round-tripping through both the database and a share URL.
# That is what makes a link portable: a runbook link written as `queue:$USER_QUEUE` shows each
# reader their OWN queue rather than the author's.
FILTER_SENTINEL_USER_QUEUE = "$USER_QUEUE"
FILTER_SENTINEL_USER = "$USER"
FILTER_SENTINELS = frozenset([FILTER_SENTINEL_USER_QUEUE, FILTER_SENTINEL_USER])


def resolve_filter_sentinel(value, *, user_queue, user_display_name):
    """Resolve the sentinels a stored or shared filter value can use to refer to the viewer."""
    if value == FILTER_SENTINEL_USER_QUEUE:
        return user_queue

    if value == FILTER_SENTINEL_USER:
        return user_display_name

    if isinstance(value, list):
        return [resolve_filter_sentinel(_, user_queue=user_queue, user_display_name=user_display_name) for _ in value]

    return value


def resolve_filter_list(filters: list, *, user_queue, user_display_name) -> list:
    """Prepare a stored or shared filter list for querying: sentinels resolved against the
    viewer, and entries sharing a name+inverted merged into one.

    The merge matters. Filter entries are ANDed together (see build_alert_query), so two
    separate Queue entries would match nothing at all rather than either queue. The GUI and
    the alert listing API both query through this, so one link means one thing in both."""
    result = []
    merged_by_key = {}
    for entry in filters or []:
        key = (entry["name"], entry.get("inverted", False))
        values = [resolve_filter_sentinel(_, user_queue=user_queue, user_display_name=user_display_name)
                  for _ in entry["values"]]
        if key in merged_by_key:
            merged_by_key[key]["values"].extend(values)
            continue

        merged = {"name": entry["name"], "inverted": entry.get("inverted", False), "values": values}
        merged_by_key[key] = merged
        result.append(merged)

    return result


def uses_filter_sentinels(filters: list) -> bool:
    """True if any value of the filter list is a sentinel (and so needs a viewer to resolve)."""
    def _uses(value) -> bool:
        if isinstance(value, list):
            return any(_uses(_) for _ in value)
        return value in FILTER_SENTINELS

    return any(_uses(value) for entry in filters or [] for value in entry["values"])


def has_filter(filters: list, name: str) -> bool:
    """Returns True if `filters` (a filter list) contains a filter with this name."""
    return any(_filter["name"] == name for _filter in filters or [])


def build_alert_query(filters: list, *, entity=None, tz=None, locations=_DEFAULT_LOCATIONS):
    """Builds the alert query for a filter list: the joins those filters require, the filter
    conditions themselves, and this node's alert visibility scoping.

    Pass `locations=None` to skip node scoping entirely; the default asks
    `node_scope_locations()`, which is what every alert-listing caller wants.
    """
    entity = entity if entity is not None else Alert

    query = get_db().query(entity).set_label_style(LABEL_STYLE_TABLENAME_PLUS_COL)
    query = query.outerjoin(Owner, entity.owner_id == Owner.id)
    if has_filter(filters, 'Disposition By'):
        query = query.outerjoin(DispositionBy, entity.disposition_user_id == DispositionBy.id)
    if has_filter(filters, 'Remediated By'):
        query = query.outerjoin(RemediatedBy, entity.removal_user_id == RemediatedBy.id)

    # The Observable and Tag filters are self-contained EXISTS subqueries, so they need no
    # join here -- and without the join there is no row fan-out to collapse. Remediation
    # Status still would, but it is not in the registry (see create_filter); this branch is
    # kept for the day it comes back.
    if has_filter(filters, 'Remediation Status'):
        query = query.outerjoin(ObservableMapping)\
            .outerjoin(Observable)\
            .outerjoin(ObservableRemediationMapping)\
            .outerjoin(Remediation)

    # apply filters
    for filter_dict in filters or []:
        _filter = create_filter(filter_dict["name"], inverted=filter_dict.get("inverted", False), tz=tz, entity=entity)
        query = _filter.apply(query, filter_dict["values"])

    # only show alerts from this node (or the configured DR node list)
    # NOTE: this will not be necessary once alerts are stored externally
    if locations is _DEFAULT_LOCATIONS:
        locations = node_scope_locations()

    if locations is not None:
        query = query.filter(entity.location.in_(list(locations)))

    return query


def count_alerts(filters: list, *, entity=None, tz=None, locations=_DEFAULT_LOCATIONS) -> int:
    """Returns the number of alerts matching a filter list. Counts distinct alert ids because
    the Tag and Observable joins can produce more than one row per alert."""
    entity = entity if entity is not None else Alert
    query = build_alert_query(filters, entity=entity, tz=tz, locations=locations)
    count_query = query.statement.with_only_columns(func.count(distinct(entity.id)))
    return get_db().execute(count_query).scalar()


def filter_alert_uuids(filters: list, uuids: list, *, entity=None, tz=None, locations=_DEFAULT_LOCATIONS) -> list:
    """Of `uuids`, the ones the filter list lets through -- in the order given.

    This is the `post_filter` shape `saq.search.query` expects, and it is what makes the GUI's
    filter list authoritative over whatever the search ranked.
    """
    if not uuids:
        return []

    entity = entity if entity is not None else Alert
    query = build_alert_query(filters, entity=entity, tz=tz, locations=locations)
    visible = {row[0] for row in query.with_entities(entity.uuid).filter(entity.uuid.in_(uuids)).distinct()}
    return [alert_uuid for alert_uuid in uuids if alert_uuid in visible]
