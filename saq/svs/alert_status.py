"""The SVS status of alerts (docs/SVS.md, Part 3, *What analysts see*), derived from
svs_attributions whenever it is read, the way a sample's label is: test, test?, partial or
mismatch, and the runs it links to.

An alert is *fully attributed* when every one of its detections (its detection_points rows) has an
attribution that holds, to any run. The marker router judges the alert from its tree
(saq.svs.attribution.evaluate); everything that reads alerts from the database (the alerts API,
closing a run's alerts, the runs' Needs attention view) judges it from these rows, by the same rule
(derive_status).
"""

from dataclasses import dataclass, field
from typing import Iterable, Optional

from sqlalchemy import and_, exists, literal, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import ColumnElement

from saq.database.model import Alert, DetectionPoint, SVSAttribution, SVSRun, Tag, TagMapping
from saq.database.pool import get_db
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
