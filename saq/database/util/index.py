"""Reconciles an alert's search index with its analysis tree.

An alert's index footprint spans five tables: the append-only catalogs `observables`
and `tags`, and the per-alert junction tables `observable_mapping`, `tag_mapping` and
`observable_tag_index` (plus `detection_points`, handled here for the same reason).

The diff is computed against the DATABASE, never against cached in-process state. That
is not an implementation detail to optimize away later: workers are separate processes,
multiple nodes share the database, and `_sync_alert_to_database` re-queries the `Alert`
on every pass, so there is no in-memory snapshot that could be trusted.
"""

import json
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import TypeVar

from saq.analysis.detection_point import DetectionPoint
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis

T = TypeVar("T")

# (casefolded observable type, sha256 digest bytes)
ObservableKey = tuple[str, bytes]

# Rows per statement.
#
# Not driven by max_allowed_packet: pymysql interpolates parameters client-side (so the
# 65,535-placeholder limit of the binary protocol does not apply) and both ends are
# configured at 1 GiB. The binding limit is range_optimizer_max_mem_size (8 MiB): if a
# row-constructor IN list exceeds it, MySQL abandons range access on i_type_sha256 and
# full-scans `observables` -- silently, because rebuild_index() runs under
# warnings.simplefilter('ignore'), which swallows warning 3170. 500 rows of
# (64-byte type + 32-byte sha256 + overhead) is ~60 KB, two orders of magnitude clear.
#
# The secondary reason is InnoDB's per-statement lock and undo footprint.
CHUNK_SIZE = 500


def tag_key(name: str) -> str:
    """Normalizes a tag name the way the `tags.name` unique key does.

    `tags.name` is utf8mb4_unicode_520_ci, so 'Foo' and 'foo' are the same row. Matching
    Python-side on the raw string would treat a row we just selected as missing, the
    follow-up INSERT IGNORE would be a silent no-op (unique-key hit under the CI
    collation), and the tag would never be indexed. casefold() is a conservative
    approximation of that collation -- it does not fold accents -- so anything it still
    fails to match is counted and logged rather than raising.
    """
    return name.casefold()


def observable_key(observable_type: str, sha256: bytes) -> ObservableKey:
    """Normalizes an observable's natural key the way `i_type_sha256` does.

    `observables.type` shares the case-insensitive collation described in tag_key().
    `observables.sha256` is VARBINARY and compares byte-exact, so it is used verbatim.
    """
    return (observable_type.casefold(), sha256)


def chunked(items: Sequence[T], size: int = CHUNK_SIZE) -> Iterator[list[T]]:
    """Yields successive chunks of at most size items."""
    for index in range(0, len(items), size):
        yield list(items[index:index + size])


def _placeholders(count: int) -> str:
    """Returns "%s,%s,..." for a single-column IN list."""
    return ','.join(['%s'] * count)


def _row_placeholders(rows: int, columns: int) -> str:
    """Returns "(%s,%s),(%s,%s),..." for a VALUES list or row-constructor IN list."""
    return ','.join(['({})'.format(_placeholders(columns))] * rows)


@dataclass(frozen=True)
class DesiredIndex:
    """What the analysis tree says the alert's index rows should be."""

    # observable key -> a representative Observable carrying the type/value/hash
    observables: dict[ObservableKey, Observable]
    # tag key -> the original (unfolded) name, which is what we INSERT
    tags: dict[str, str]
    observable_tags: set[tuple[ObservableKey, str]]
    detection_points: dict[str, DetectionPoint]


@dataclass
class IndexSyncResult:
    """What the sync actually wrote. Zero across the board means nothing changed."""

    observables_created: int = 0
    tags_created: int = 0
    observable_mappings_added: int = 0
    observable_mappings_removed: int = 0
    tag_mappings_added: int = 0
    tag_mappings_removed: int = 0
    observable_tag_index_added: int = 0
    observable_tag_index_removed: int = 0
    detection_points_written: int = 0
    detection_points_removed: int = 0
    # keys the catalogs could not resolve even after INSERT IGNORE -- only reachable
    # via a collation fold casefold() does not model. Never expected to be non-zero.
    unresolved_tags: int = 0
    unresolved_observables: int = 0

    @property
    def total_writes(self) -> int:
        return (self.observables_created + self.tags_created
                + self.observable_mappings_added + self.observable_mappings_removed
                + self.tag_mappings_added + self.tag_mappings_removed
                + self.observable_tag_index_added + self.observable_tag_index_removed
                + self.detection_points_written + self.detection_points_removed)

    @property
    def changed(self) -> bool:
        return self.total_writes > 0

    def __str__(self) -> str:
        return (f"observables +{self.observables_created} "
                f"tags +{self.tags_created} "
                f"observable_mapping +{self.observable_mappings_added}/-{self.observable_mappings_removed} "
                f"tag_mapping +{self.tag_mappings_added}/-{self.tag_mappings_removed} "
                f"observable_tag_index +{self.observable_tag_index_added}/-{self.observable_tag_index_removed} "
                f"detection_points ~{self.detection_points_written}/-{self.detection_points_removed}")


def build_desired_index(root_analysis: RootAnalysis) -> DesiredIndex:
    """Computes the desired index state from the analysis tree."""
    observables: dict[ObservableKey, Observable] = {}
    observable_tags: set[tuple[ObservableKey, str]] = set()

    for observable in root_analysis.all_observables:
        if observable.ignored:
            continue

        key = observable_key(observable.type, observable.sha256_bytes)
        observables.setdefault(key, observable)
        for tag in observable.tags:
            observable_tags.add((key, tag_key(tag)))

    # all_tags spans both Analysis and Observable objects, so every tag referenced by
    # observable_tags is guaranteed to be resolvable through this map.
    tags = {tag_key(name): name for name in root_analysis.all_tags}

    detection_points = {dp.content_hash: dp for dp in root_analysis.all_detection_points}

    return DesiredIndex(
        observables=observables,
        tags=tags,
        observable_tags=observable_tags,
        detection_points=detection_points)


def read_current_observables(c, alert_id: int) -> dict[ObservableKey, int]:
    """Returns the observables currently mapped to this alert, keyed by natural key."""
    # deliberately two statements rather than one join. The join form
    # (observable_mapping om JOIN observables o ON o.id = om.observable_id WHERE
    # om.alert_id = %s) lets the optimizer invert the join order and full-scan
    # `observables` when it thinks that table is small -- catastrophic against a
    # production catalog. Split this way, the first is a covering index lookup on
    # alert_id and the second is N primary-key lookups, unconditionally.
    c.execute("SELECT observable_id FROM observable_mapping WHERE alert_id = %s", (alert_id,))
    observable_ids = [row[0] for row in c.fetchall()]
    if not observable_ids:
        return {}

    result: dict[ObservableKey, int] = {}
    for chunk in chunked(observable_ids):
        c.execute(
            "SELECT id, type, sha256 FROM observables WHERE id IN ({})".format(_placeholders(len(chunk))),
            tuple(chunk))
        for observable_id, observable_type, sha256 in c.fetchall():
            result[observable_key(observable_type, sha256)] = observable_id

    return result


def read_current_tags(c, alert_id: int) -> dict[str, int]:
    """Returns the tags currently mapped to this alert, keyed by folded tag name."""
    c.execute("""SELECT t.id, t.name
                 FROM tag_mapping tm JOIN tags t ON t.id = tm.tag_id
                 WHERE tm.alert_id = %s""", (alert_id,))
    return {tag_key(name): tag_id for tag_id, name in c.fetchall()}


def read_current_observable_tags(c, alert_id: int) -> set[tuple[int, int]]:
    """Returns the (observable_id, tag_id) pairs currently indexed for this alert."""
    c.execute("SELECT observable_id, tag_id FROM observable_tag_index WHERE alert_id = %s", (alert_id,))
    return {(observable_id, tag_id) for observable_id, tag_id in c.fetchall()}


def resolve_tag_ids(c, tags: dict[str, str], result: IndexSyncResult) -> dict[str, int]:
    """Resolves tag names to `tags.id`, creating catalog rows only for genuine misses."""
    if not tags:
        return {}

    resolved: dict[str, int] = {}
    _select_tag_ids(c, list(tags.values()), resolved)

    missing = [name for key, name in tags.items() if key not in resolved]
    if not missing:
        return resolved

    for chunk in chunked(missing):
        c.execute(
            "INSERT IGNORE INTO tags ( name ) VALUES {}".format(_row_placeholders(len(chunk), 1)),
            tuple(chunk))

    # re-read rather than trusting lastrowid: INSERT IGNORE reports nothing for rows it
    # skipped. The raw pymysql pool runs at READ COMMITTED (saq/database/pool.py), so
    # this sees rows another worker committed between our SELECT and our INSERT IGNORE.
    # Under REPEATABLE READ it would not, and those tags would be silently dropped.
    before = len(resolved)
    _select_tag_ids(c, missing, resolved)
    result.tags_created += len(resolved) - before

    return resolved


def _select_tag_ids(c, names: list[str], resolved: dict[str, int]):
    for chunk in chunked(names):
        c.execute(
            "SELECT id, name FROM tags WHERE name IN ({})".format(_placeholders(len(chunk))),
            tuple(chunk))
        for tag_id, name in c.fetchall():
            resolved[tag_key(name)] = tag_id


def resolve_observable_ids(
        c,
        observables: dict[ObservableKey, Observable],
        result: IndexSyncResult) -> dict[ObservableKey, int]:
    """Resolves observables to `observables.id`, creating catalog rows only for misses."""
    if not observables:
        return {}

    resolved: dict[ObservableKey, int] = {}
    _select_observable_ids(c, list(observables.values()), resolved)

    missing = [observable for key, observable in observables.items() if key not in resolved]
    if not missing:
        return resolved

    for chunk in chunked(missing):
        params = []
        for observable in chunk:
            params.extend((observable.type, observable.value, observable.sha256_bytes))

        c.execute(
            "INSERT IGNORE INTO observables ( type, value, sha256 ) VALUES {}".format(
                _row_placeholders(len(chunk), 3)),
            tuple(params))

    # see the READ COMMITTED note in resolve_tag_ids()
    before = len(resolved)
    _select_observable_ids(c, missing, resolved)
    result.observables_created += len(resolved) - before

    return resolved


def _select_observable_ids(c, observables: list[Observable], resolved: dict[ObservableKey, int]):
    for chunk in chunked(observables):
        params = []
        for observable in chunk:
            params.extend((observable.type, observable.sha256_bytes))

        # (type, sha256) is an exact prefix of the i_type_sha256 unique key, so MySQL's
        # range optimizer turns this row-constructor IN into a covering index range
        # scan -- one seek per element. 
        c.execute(
            "SELECT id, type, sha256 FROM observables WHERE (type, sha256) IN ({})".format(
                _row_placeholders(len(chunk), 2)),
            tuple(params))
        for observable_id, observable_type, sha256 in c.fetchall():
            resolved[observable_key(observable_type, sha256)] = observable_id


def apply_id_diff(c, alert_id: int, table: str, column: str,
                  desired: set[int], current: set[int]) -> tuple[int, int]:
    """Writes only the difference between desired and current for a single-column
    junction table. Returns (added, removed)."""
    added = sorted(desired - current)
    removed = sorted(current - desired)

    for chunk in chunked(removed):
        c.execute(
            f"DELETE FROM {table} WHERE alert_id = %s AND {column} IN ({_placeholders(len(chunk))})",
            (alert_id, *chunk))

    for chunk in chunked(added):
        # INSERT IGNORE, not INSERT: an analyst tagging an alert from the GUI while the
        # engine syncs the same alert can insert the same pair first. The previous
        # implementation used a bare INSERT and raised 1062 when that happened, which
        # execute_with_retry does not retry (it only handles 1213/1205).
        c.execute(
            f"INSERT IGNORE INTO {table} ( alert_id, {column} ) VALUES "
            + _row_placeholders(len(chunk), 2),
            tuple(value for row_id in chunk for value in (alert_id, row_id)))

    return len(added), len(removed)


def sync_observable_tag_index(c, alert_id: int, desired: set[tuple[int, int]],
                              current: set[tuple[int, int]], result: IndexSyncResult):
    """Writes only the difference for the two-column observable_tag_index table."""
    added = sorted(desired - current)
    removed = sorted(current - desired)

    for chunk in chunked(removed):
        c.execute(
            "DELETE FROM observable_tag_index WHERE alert_id = %s AND (observable_id, tag_id) IN ({})".format(
                _row_placeholders(len(chunk), 2)),
            (alert_id, *(value for pair in chunk for value in pair)))

    for chunk in chunked(added):
        c.execute(
            "INSERT IGNORE INTO observable_tag_index ( alert_id, observable_id, tag_id ) VALUES "
            + _row_placeholders(len(chunk), 3),
            tuple(value for observable_id, tag_id in chunk for value in (alert_id, observable_id, tag_id)))

    result.observable_tag_index_added += len(added)
    result.observable_tag_index_removed += len(removed)


def sync_detection_points(c, alert_id: int, desired: dict[str, DetectionPoint],
                          result: IndexSyncResult):
    """Reconciles the detection_points rows for this alert, writing only the delta."""
    # content_hash = sha256(signature_uuid + description + details_json), so a matching
    # hash already implies description, details and signature_uuid match. Only queue and
    # signature_version can drift, so those are the only columns worth reading back --
    # which also keeps the MEDIUMTEXT `details` column off the wire entirely.
    c.execute("""SELECT content_hash, queue, signature_version
                 FROM detection_points WHERE alert_id = %s""", (alert_id,))
    current = {content_hash: (queue, signature_version)
               for content_hash, queue, signature_version in c.fetchall()}

    removed = sorted(content_hash for content_hash in current if content_hash not in desired)
    to_write = sorted(
        content_hash for content_hash, dp in desired.items()
        if content_hash not in current
        or current[content_hash] != (dp.queue, dp.signature_version))

    for chunk in chunked(removed):
        c.execute(
            "DELETE FROM detection_points WHERE alert_id = %s AND content_hash IN ({})".format(
                _placeholders(len(chunk))),
            (alert_id, *chunk))

    for chunk in chunked(to_write):
        # ON DUPLICATE KEY UPDATE rather than INSERT IGNORE so rows whose queue or
        # signature_version drifted are actually corrected, and so a row another worker
        # inserted between our SELECT and this INSERT still ends up with our values.
        sql = """INSERT INTO detection_points
                    ( alert_id, description, details, queue, signature_uuid, signature_version, content_hash )
                 VALUES {}
                 ON DUPLICATE KEY UPDATE
                    description = VALUES(description),
                    details = VALUES(details),
                    queue = VALUES(queue),
                    signature_uuid = VALUES(signature_uuid),
                    signature_version = VALUES(signature_version)""".format(
                    _row_placeholders(len(chunk), 7))

        parameters = []
        for content_hash in chunk:
            dp = desired[content_hash]
            parameters.append(alert_id)
            parameters.append(dp.description)
            parameters.append(
                json.dumps(dp.details, sort_keys=True, default=str) if dp.details else None)
            parameters.append(dp.queue)
            parameters.append(dp.signature_uuid)
            parameters.append(dp.signature_version)
            parameters.append(content_hash)

        c.execute(sql, tuple(parameters))

    result.detection_points_written += len(to_write)
    result.detection_points_removed += len(removed)


def sync_alert_index(c, alert_id: int, root_analysis: RootAnalysis) -> IndexSyncResult:
    """Reconciles every index table for this alert against its analysis tree, writing
    only what changed. The caller owns the transaction (commit is not issued here)."""
    result = IndexSyncResult()
    desired = build_desired_index(root_analysis)

    current_observables = read_current_observables(c, alert_id)
    current_tags = read_current_tags(c, alert_id)
    current_pairs = read_current_observable_tags(c, alert_id)

    # anything already mapped to this alert is already resolved -- only genuinely new
    # keys need to touch the catalog tables. In the steady state this is nothing, so the
    # (type, sha256) IN (...) resolution is skipped entirely.
    new_observables = {key: observable for key, observable in desired.observables.items()
                       if key not in current_observables}
    new_tags = {key: name for key, name in desired.tags.items() if key not in current_tags}

    observable_ids = current_observables | resolve_observable_ids(c, new_observables, result)
    tag_ids = current_tags | resolve_tag_ids(c, new_tags, result)

    result.unresolved_observables = sum(
        1 for key in desired.observables if key not in observable_ids)
    result.unresolved_tags = sum(1 for key in desired.tags if key not in tag_ids)

    added, removed = apply_id_diff(
        c, alert_id, "observable_mapping", "observable_id",
        desired={observable_ids[key] for key in desired.observables if key in observable_ids},
        current=set(current_observables.values()))
    result.observable_mappings_added += added
    result.observable_mappings_removed += removed

    added, removed = apply_id_diff(
        c, alert_id, "tag_mapping", "tag_id",
        desired={tag_ids[key] for key in desired.tags if key in tag_ids},
        current=set(current_tags.values()))
    result.tag_mappings_added += added
    result.tag_mappings_removed += removed

    sync_observable_tag_index(
        c, alert_id,
        desired={(observable_ids[observable], tag_ids[tag])
                 for observable, tag in desired.observable_tags
                 if observable in observable_ids and tag in tag_ids},
        current=current_pairs,
        result=result)

    sync_detection_points(c, alert_id, desired.detection_points, result)

    if result.unresolved_observables or result.unresolved_tags:
        logging.warning(
            "alert_id %s: unable to resolve %s observable(s) and %s tag(s) to catalog rows "
            "-- they are missing from the index",
            alert_id, result.unresolved_observables, result.unresolved_tags)

    return result
