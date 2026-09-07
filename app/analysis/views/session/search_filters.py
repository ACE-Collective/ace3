"""Translates the analyst's effective filter list into search pre-filters.

Only the filters the search index can express are mapped (they narrow the semantic lane so its
budget is not spent on alerts the analyst cannot see); the SQL post-filter built from the full
filter list remains authoritative for what is shown.
"""

import datetime
import logging

import pytz
from flask_login import current_user

from saq.database.util.alert import node_scope_locations
from saq.database.util.index import tag_key
from saq.search.types import SearchFilters
from saq.util.relative_time import RelativeTimeError, parse_date_range


def effective_filters_to_search_filters(filters: list) -> SearchFilters:
    timezone = pytz.timezone(current_user.timezone) if getattr(current_user, "timezone", None) else pytz.utc
    now = datetime.datetime.now(pytz.utc)

    fields = {}
    for entry in filters or []:
        name = entry.get("name")
        values = [v for v in entry.get("values", []) if v not in (None, "")]
        inverted = bool(entry.get("inverted", False))
        if not values:
            continue

        if name == "Alert Date":
            ranges = []
            for value in values:
                try:
                    ranges.append(parse_date_range(value, now=now, tz=timezone))
                except RelativeTimeError as e:
                    logging.debug(f"search pre-filter skipped unparsable date range {value!r}: {e}")
            if ranges:
                fields["insert_date_ranges"] = tuple(ranges)
                fields["insert_date_inverted"] = inverted
        elif name == "Alert Type":
            fields["alert_types"] = tuple(values)
            fields["alert_types_inverted"] = inverted
        elif name == "Disposition":
            fields["dispositions"] = tuple(values)
            fields["dispositions_inverted"] = inverted
        elif name == "Queue":
            fields["queues"] = tuple(values)
            fields["queues_inverted"] = inverted
        elif name == "Tag":
            # a wildcard tag pattern has no payload equivalent; leave it to the SQL post-filter
            if not any("*" in value for value in values):
                fields["tags"] = tuple(tag_key(value) for value in values)
                fields["tags_inverted"] = inverted

    locations = node_scope_locations()
    fields["locations"] = tuple(locations) if locations is not None else None
    return SearchFilters(**fields)
