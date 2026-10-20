"""The alert management filter type registry."""

# The filter names create_filter() and getFilters() support. Anything stored in the
# database or accepted from a URL is validated against this set, so a typo can never reach
# the filter list where it would raise KeyError on every subsequent /manage load.
# Kept in sync with getFilters() by test_filter_names_match_get_filters.
FILTER_NAMES = frozenset([
    'Alert Date',
    'Alert Type',
    'Analysis',
    'Description',
    'Detection Point',
    'Disposition',
    'Disposition By',
    'Disposition Date',
    'Event Date',
    'Observable',
    'Owner',
    'Queue',
    'Reviewed',
    'Tag',
    'Unconfirmed Detections',
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
    'Analysis': 'analysis',
    'Description': 'description',
    'Detection Point': 'detection_point',
    'Disposition': 'disposition',
    'Disposition By': 'disposition_by',
    'Disposition Date': 'disposition_date',
    'Event Date': 'event_date',
    'Observable': 'observable',
    'Owner': 'owner',
    'Queue': 'queue',
    'Reviewed': 'reviewed',
    'Tag': 'tag',
    'Unconfirmed Detections': 'unconfirmed_detections',
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

# The filters of the detection points screen (GET /api/v2/detection-points, docs/SVS_API.md):
# display name -> URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
DETECTION_POINT_FILTER_SLUGS = {
    'Alert Date': 'alert_date',
    'Family': 'family',
    'Has Override': 'has_override',
    'Queue': 'queue',
    'Signature': 'signature',
    'Source': 'source',
    'Verdict': 'verdict',
}

# The filters of the SVS samples screen (GET /api/v2/svs/samples, docs/SVS_API.md): display
# name -> URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_SAMPLE_FILTER_SLUGS = {
    'Alert': 'alert',
    'File Name': 'file_name',
    'Label': 'label',
    'Label Source': 'label_source',
    'Last Captured': 'last_captured',
    'Missing Data': 'missing_data',
    'Retired': 'retired',
    'Rule': 'rule',
    'SHA256': 'sha256',
    'Signature': 'signature',
    'Stored': 'stored',
    'Unknown Version': 'unknown_version',
}

# The filters of the SVS validations screen (GET /api/v2/svs/yara/validations,
# docs/SVS_API.md): display name -> URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_VALIDATION_FILTER_SLUGS = {
    'Branch': 'branch',
    'Compile Errors': 'compile_errors',
    'Created': 'created',
    'Has New FP': 'has_new_fp',
    'Has Regressions': 'has_regressions',
    'Head': 'head',
    'Repository': 'repository',
    'State': 'state',
}

# The filters of the SVS tests screen (GET /api/v2/svs/tests, docs/SVS_API.md): display name ->
# URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_TEST_FILTER_SLUGS = {
    'Executor': 'executor',
    'Name': 'name',
    'Platform': 'platform',
    'Removed': 'removed',
    'Repository': 'repository',
    'Technique': 'technique',
}

# The filters of the SVS runs screen (GET /api/v2/svs/runs, docs/SVS_API.md): display name ->
# URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_RUN_FILTER_SLUGS = {
    'Batch': 'batch',
    'Changed Since Review': 'changed_since_review',
    'Created': 'created',
    'Ended': 'ended',
    'Has Candidates': 'has_candidates',
    'Has Context Only': 'has_context_only',
    'Has Late': 'has_late',
    'Has Missing': 'has_missing',
    'Has Open Alerts': 'has_open_alerts',
    'Has Possibly Suppressed': 'has_possibly_suppressed',
    'Launcher': 'launcher',
    'Needs Attention': 'needs_attention',
    'Owner': 'owner',
    'Platform': 'platform',
    'Reason': 'reason',
    'Reviewed': 'reviewed',
    'Reviewer': 'reviewer',
    'Started': 'started',
    'State': 'state',
    'Target': 'target',
    'Technique': 'technique',
    'Test': 'test',
    'Test Name': 'test_name',
}

# The filters of the SVS coverage screen (GET /api/v2/svs/coverage, docs/SVS_API.md): display name
# -> URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_COVERAGE_FILTER_SLUGS = {
    'ATT&CK Platform': 'attack_platform',
    'Catalog Status': 'catalog_status',
    'Has Manual': 'has_manual',
    'Level': 'level',
    'Name': 'name',
    'Own State': 'own_state',
    'Platform': 'platform',
    'Retired': 'retired',
    'State': 'state',
    'State Changed': 'state_changed',
    'Tactic': 'tactic',
    'Technique': 'technique',
}

# The filters of the SVS coverage history (GET /api/v2/svs/coverage/history, docs/SVS_API.md):
# display name -> URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_COVERAGE_HISTORY_FILTER_SLUGS = {
    'Date': 'date',
    'Level': 'level',
    'Own State': 'own_state',
    'Platform': 'platform',
    'State': 'state',
    'Technique': 'technique',
}

# The filters of the SVS worklist (GET /api/v2/svs/worklist, docs/SVS_API.md): display name -> URL
# slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
SVS_WORKLIST_FILTER_SLUGS = {
    'Family': 'family',
    'Kind': 'kind',
    'Resolution': 'resolution',
    'Resolved': 'resolved',
    'Resolved By': 'resolved_by',
    'Signature': 'signature',
    'Status': 'status',
    'Technique': 'technique',
}

# The filters of the Remediations page (GET /api/v2/remediation/remediations): display name ->
# URL slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
REMEDIATION_FILTER_SLUGS = {
    'Action': 'action',
    'Analyst': 'analyst',
    'Created': 'created',
    'ID': 'id',
    'Remediator': 'remediator',
    'Result': 'result',
    'Status': 'status',
    'Type': 'type',
    'Value': 'value',
}

# The filters of the File Collections page (GET /api/v2/file-collections): display name -> URL
# slug, under the same PERMANENT CONTRACT as FILTER_SLUGS.
FILE_COLLECTION_FILTER_SLUGS = {
    'Alert': 'alert',
    'Collector': 'collector',
    'Created': 'created',
    'ID': 'id',
    'Result': 'result',
    'Status': 'status',
    'Type': 'type',
    'Value': 'value',
}

__all__ = [
    "FILTER_NAMES",
    "DATE_RANGE_FILTER_NAMES",
    "FILTER_SLUGS",
    "FILTER_NAMES_BY_SLUG",
    "LEGACY_FILTER_NAME_ALIASES",
    "DETECTION_POINT_FILTER_SLUGS",
    "SVS_SAMPLE_FILTER_SLUGS",
    "SVS_VALIDATION_FILTER_SLUGS",
    "SVS_TEST_FILTER_SLUGS",
    "SVS_RUN_FILTER_SLUGS",
    "REMEDIATION_FILTER_SLUGS",
    "FILE_COLLECTION_FILTER_SLUGS",
]
