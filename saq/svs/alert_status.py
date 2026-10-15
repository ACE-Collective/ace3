"""The SVS status of alerts (docs/SVS.md, Part 3, *What analysts see*), derived from
svs_attributions whenever it is read, the way a sample's label is: test, test?, partial or
mismatch, and the runs it links to. alert_svs_view() is what one alert's page shows of it.

An alert is *fully attributed* when every one of its detections (its detection_points rows) has an
attribution that holds, to any run. The marker router judges the alert from its tree
(saq.svs.attribution.evaluate); everything that reads alerts from the database (the alerts API,
closing a run's alerts, the runs' Needs attention view) judges it from these rows, by the same rule
(derive_status).
"""

import json
from dataclasses import dataclass, field
from typing import Iterable, Optional

from sqlalchemy import and_, exists, literal, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import Alert, DetectionPoint, SVSAttribution, SVSCatalogTest, SVSRun, Tag, TagMapping
from saq.database.pool import get_db
from saq.signatures.builtin import SVS_MARKER_MISMATCH
from saq.svs.constants import TAG_MARKER_MISMATCH, AttributionConfidence, SVSStatus


def derive_status(detections: Iterable[str],
                  confidences: dict[str, set[AttributionConfidence]]) -> Optional[SVSStatus]:
    """The status of an alert whose detections (content hashes) hold the given attributions
    (content hash -> the confidences of the attributions that hold): None when none is attributed,
    partial when some are, and test or test? when all are, test? when context is all there is."""
    detections = set(detections)
    attributed = detections & set(confidences)
    if not attributed:
        return None
    if attributed != detections:
        return SVSStatus.PARTIAL
    if all(confidences[h] == {AttributionConfidence.CONTEXT} for h in attributed):
        return SVSStatus.TEST_CONTEXT
    return SVSStatus.TEST


def fully_attributed_condition() -> ColumnElement[bool]:
    """On alerts: the alert has an attribution that holds, and none of its detections lacks one.
    It correlates with alerts only, so a query that also selects from svs_attributions or
    detection_points can use it."""
    held = aliased(SVSAttribution)
    covering = aliased(SVSAttribution)
    detection = aliased(DetectionPoint)
    covered = (select(literal(1))
               .where(covering.alert_uuid == Alert.uuid, covering.content_hash == detection.content_hash,
                      covering.removed_at.is_(None))
               .correlate(Alert, detection))
    uncovered = (select(literal(1))
                 .where(detection.alert_id == Alert.id, ~exists(covered))
                 .correlate(Alert))
    attributed = (select(literal(1))
                  .where(held.alert_uuid == Alert.uuid, held.removed_at.is_(None))
                  .correlate(Alert))
    return and_(exists(attributed), ~exists(uncovered))


@dataclass(frozen=True)
class AlertSVSStatus:
    status: SVSStatus
    # the uuids of the runs the alert is attributed to, oldest run first; none for a mismatch
    runs: tuple[str, ...] = field(default_factory=tuple)


def alert_svs_statuses(alerts: dict[int, str]) -> dict[int, AlertSVSStatus]:
    """The SVS status of each of the alerts (id -> uuid) that has one: three queries, whatever the
    number of alerts. An alert with attributions that hold is judged by them; otherwise one tagged
    svs:marker_mismatch is a mismatch."""
    if not alerts:
        return {}

    db = get_db()
    ids_by_uuid = {alert_uuid: alert_id for alert_id, alert_uuid in alerts.items()}

    confidences: dict[int, dict[str, set[AttributionConfidence]]] = {}
    runs: dict[int, dict[str, int]] = {}
    for alert_uuid, content_hash, confidence, run_uuid, run_id in db.execute(
            select(SVSAttribution.alert_uuid, SVSAttribution.content_hash, SVSAttribution.confidence,
                   SVSRun.uuid, SVSRun.id)
            .join(SVSRun, SVSRun.id == SVSAttribution.run_id)
            .where(SVSAttribution.alert_uuid.in_(list(ids_by_uuid)), SVSAttribution.removed_at.is_(None))):
        alert_id = ids_by_uuid[alert_uuid]
        confidences.setdefault(alert_id, {}).setdefault(content_hash, set()).add(AttributionConfidence(confidence))
        runs.setdefault(alert_id, {})[run_uuid] = run_id

    detections: dict[int, set[str]] = {}
    if confidences:
        for alert_id, content_hash in db.execute(
                select(DetectionPoint.alert_id, DetectionPoint.content_hash)
                .where(DetectionPoint.alert_id.in_(list(confidences)))):
            detections.setdefault(alert_id, set()).add(content_hash)

    mismatched = set(db.execute(
        select(TagMapping.alert_id)
        .join(Tag, Tag.id == TagMapping.tag_id)
        .where(TagMapping.alert_id.in_(list(alerts)), Tag.name == TAG_MARKER_MISMATCH)).scalars())

    result = {}
    for alert_id in alerts:
        status = derive_status(detections.get(alert_id, ()), confidences.get(alert_id, {}))
        if status is not None:
            ordered = sorted(runs[alert_id].items(), key=lambda item: item[1])
            result[alert_id] = AlertSVSStatus(status, tuple(run_uuid for run_uuid, _ in ordered))
        elif alert_id in mismatched:
            result[alert_id] = AlertSVSStatus(SVSStatus.MISMATCH)
    return result


#
# one alert, as its page shows it
#

@dataclass(frozen=True)
class RunRef:
    """A run, as an alert names it."""
    uuid: str
    state: str
    test_guid: str
    # the catalog's name of the test; None when the catalog no longer has it
    test_name: Optional[str] = None


@dataclass(frozen=True)
class MarkerMismatch:
    """A marker in the alert that doesn't agree with its run (saq.modules.svs.SVSAlertTagger)."""
    marker: str
    # how it disagrees (saq.svs.constants.MarkerResult): unknown, other host, outside window
    result: str
    # the run the marker belongs to; None when no run has it
    run: Optional[RunRef] = None


@dataclass(frozen=True)
class AlertSVSView:
    status: Optional[SVSStatus]
    # the runs whose attributions of the alert hold, oldest first
    runs: tuple[RunRef, ...] = field(default_factory=tuple)
    # detection content hash -> the uuids of the runs it is attributed to
    detections: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mismatches: tuple[MarkerMismatch, ...] = field(default_factory=tuple)


def _run_refs(condition) -> list[tuple[str, RunRef]]:
    """(marker, run) of the runs matching the condition, oldest first."""
    return [(marker, RunRef(uuid, state, test_guid, name)) for marker, uuid, state, test_guid, name in get_db().execute(
        select(SVSRun.marker, SVSRun.uuid, SVSRun.state, SVSRun.test_guid, SVSCatalogTest.name)
        .outerjoin(SVSCatalogTest, SVSCatalogTest.guid == SVSRun.test_guid)
        .where(condition)
        .order_by(SVSRun.id))]


def _mismatches(alert_id: int) -> tuple[MarkerMismatch, ...]:
    """The alert's marker mismatch detections, each with the run its marker belongs to."""
    found = []
    for details in get_db().execute(
            select(DetectionPoint.details)
            .where(DetectionPoint.alert_id == alert_id, DetectionPoint.signature_uuid == SVS_MARKER_MISMATCH.uuid)
            .order_by(DetectionPoint.id)).scalars():
        try:
            parsed = json.loads(details) if details else {}
        except ValueError:
            parsed = {}
        if isinstance(parsed, dict) and parsed.get("marker"):
            found.append((str(parsed["marker"]), str(parsed.get("result") or "")))
    if not found:
        return ()
    # markers are stored lower case (saq.svs.markers), a marker in an alert may be in any case
    runs = dict(_run_refs(SVSRun.marker.in_({marker.lower() for marker, _ in found})))
    return tuple(MarkerMismatch(marker, result, runs.get(marker.lower())) for marker, result in found)


def alert_svs_view(alert_id: int, alert_uuid: str) -> Optional[AlertSVSView]:
    """What the alert's page shows of SVS: its status, the runs it is attributed to, which of its
    detections each holds, and the markers that disagree with their run. None when SVS never
    touched the alert."""
    status = alert_svs_statuses({alert_id: alert_uuid}).get(alert_id)
    mismatches = _mismatches(alert_id)
    if status is None and not mismatches:
        return None

    detections: dict[str, list[str]] = {}
    held_runs: set[int] = set()
    for content_hash, run_id, run_uuid in get_db().execute(
            select(SVSAttribution.content_hash, SVSRun.id, SVSRun.uuid)
            .join(SVSRun, SVSRun.id == SVSAttribution.run_id)
            .where(SVSAttribution.alert_uuid == alert_uuid, SVSAttribution.removed_at.is_(None))
            .order_by(SVSRun.id)):
        detections.setdefault(content_hash, []).append(run_uuid)
        held_runs.add(run_id)
    runs = tuple(ref for _, ref in _run_refs(SVSRun.id.in_(held_runs))) if held_runs else ()

    return AlertSVSView(
        status=status.status if status is not None else SVSStatus.MISMATCH,
        runs=runs,
        detections={content_hash: tuple(run_uuids) for content_hash, run_uuids in detections.items()},
        mismatches=mismatches)
