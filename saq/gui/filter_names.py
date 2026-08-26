"""The alert management filter type registry."""

# The filter names create_filter() and getFilters() support. Anything stored in the
# database or accepted from a URL is validated against this set, so a typo can never reach
# the filter list where it would raise KeyError on every subsequent /manage load.
# Kept in sync with getFilters() by test_filter_names_match_get_filters.
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

# The filter names whose values are time windows, parsed by DateRangeFilter. Broken out so
# validators know which values to run through parse_date_range().
DATE_RANGE_FILTER_NAMES = frozenset([
    'Alert Date',
    'Disposition Date',
    'Event Date',
])

# Display name -> URL slug.
#
# PERMANENT CONTRACT: never rename or repurpose a slug. A filter link pasted into a wiki
# page means whatever its slugs meant on the day it was written, and it has to keep meaning
# that. Adding new slugs is fine; changing an existing one silently redirects old links to
# the wrong data. Display names, by contrast, are free to change precisely because the URL
# format never contains one.
FILTER_SLUGS = {
    'Alert Date': 'alert_date',
    'Alert Type': 'alert_type',
    'Description': 'description',
    'Disposition': 'disposition',
    'Disposition By': 'disposition_by',
    'Disposition Date': 'disposition_date',
    'Event Date': 'event_date',
    'Observable': 'observable',
    'Owner': 'owner',
    'Queue': 'queue',
    'Reviewed': 'reviewed',
    'Tag': 'tag',
}

FILTER_NAMES_BY_SLUG = {slug: name for name, slug in FILTER_SLUGS.items()}

# Display names as they appear inside legacy ?filters=<json> URLs, mapped to slugs.
#
# APPEND ONLY, FOREVER. Those URLs are already pasted in wikis and tickets and are
# permanently supported (they 302 to the modern format -- see app/analysis/views/edit/
# filters.py::set_filters). Because they embed *display names* rather than slugs, every
# string that has ever shipped as a display name has to keep resolving here even after the
# GUI renames it. Never remove or repoint an entry; only add.
LEGACY_FILTER_NAME_ALIASES = dict(FILTER_SLUGS)

__all__ = [
    "FILTER_NAMES",
    "DATE_RANGE_FILTER_NAMES",
    "FILTER_SLUGS",
    "FILTER_NAMES_BY_SLUG",
    "LEGACY_FILTER_NAME_ALIASES",
]
