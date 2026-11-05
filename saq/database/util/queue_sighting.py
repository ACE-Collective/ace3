"""Finds other alerts in a given queue that contain an observable, with the evidence that the
observable mattered in them. Backs the observable modifier's seen_in_queue condition."""

from dataclasses import dataclass, field
from typing import Iterable, Optional

from sqlalchemy import or_

from saq.database.model import (
    Alert as DBAlert,
    DetectionPoint as DBDetectionPoint,
    Observable as DBObservable,
    ObservableDetection as DBObservableDetection,
    ObservableMapping,
    ObservableTagIndex,
    Tag as DBTag,
)
from saq.database.pool import get_db

# detection points sitting on the observable itself or on one of its analyses; a root-level
# detection says the alert fired, not that this observable is why
OBSERVABLE_NODE_KINDS = ("observable", "analysis")


@dataclass
class QueueSighting:
    alert_uuid: str
    # why the observable mattered in that alert: "detection_point" or "tag:<name>"
    reasons: list[str] = field(default_factory=list)


@dataclass
class QueueSightings:
    queue: str
    # alerts in the queue holding the observable, newest first: the scan_limit newest, plus any
    # older one that carries an indicator tag on it
    alerts: list[QueueSighting] = field(default_factory=list)
    # importance that is not tied to any one alert: "observable_detection", "is_interesting"
    global_reasons: list[str] = field(default_factory=list)
    # True when more alerts hold the observable than were scanned: older alerts without an
    # indicator tag were not looked at, so alerts is not the full count
    truncated: bool = False

    @property
    def important_alerts(self) -> list[QueueSighting]:
        return [a for a in self.alerts if a.reasons]


def find_queue_sightings(
    observable_types: Iterable[str],
    sha256_bytes: bytes,
    queue: str,
    exclude_alert_uuid: Optional[str],
    indicator_tags: list[str],
    scan_limit: int = 200,
) -> QueueSightings:
    """Returns the alerts in queue (other than exclude_alert_uuid) that contain the observable.

    The observable is identified by its sha256 key and any of observable_types, so the caller
    can match across related types (an email_from is the same address as an email_address).

    Each sighting carries the reasons the observable mattered in that alert: one of
    indicator_tags on the observable there, or a detection point attributed to the observable
    (or to one of its analyses). Indicator tags are found in every alert; the rest only in the
    scan_limit newest, so a very common observable costs a bounded lookup.
    """
    from saq.util.time import local_time

    result = QueueSightings(queue=queue)
    types = sorted(set(observable_types))
    db = get_db()

    db_observables = db.query(DBObservable.id, DBObservable.is_interesting).filter(
        DBObservable.sha256 == sha256_bytes,
        DBObservable.type.in_(types),
    ).all()
    if not db_observables:
        return result
    observable_ids = [row.id for row in db_observables]

    def in_queue(query):
        query = query.filter(DBAlert.queue == queue)
        if exclude_alert_uuid:
            query = query.filter(DBAlert.uuid != exclude_alert_uuid)
        return query

    # observable_mapping's primary key leads with observable_id, so this is driven from the
    # observable's own mappings rather than from every alert in the queue
    candidates = in_queue(db.query(DBAlert.id, DBAlert.uuid).join(
        ObservableMapping, ObservableMapping.alert_id == DBAlert.id,
    ).filter(
        ObservableMapping.observable_id.in_(observable_ids),
    )).distinct().order_by(DBAlert.id.desc()).limit(scan_limit).all()
    # the common case: nothing else holds the observable, and two queries settled it
    if not candidates:
        return result

    result.truncated = len(candidates) == scan_limit
    by_id = {row.id: QueueSighting(alert_uuid=row.uuid) for row in candidates}

    # an indicator is what this lookup exists to find, so it is not subject to scan_limit.
    # observable_tag_index's primary key leads with observable_id too
    if indicator_tags:
        tag_rows = in_queue(db.query(DBAlert.id, DBAlert.uuid, DBTag.name).join(
            ObservableTagIndex, ObservableTagIndex.alert_id == DBAlert.id,
        ).join(
            DBTag, DBTag.id == ObservableTagIndex.tag_id,
        ).filter(
            ObservableTagIndex.observable_id.in_(observable_ids),
            DBTag.name.in_(indicator_tags),
        )).distinct().all()
        for row in tag_rows:
            by_id.setdefault(row.id, QueueSighting(alert_uuid=row.uuid)).reasons.append(f"tag:{row.name}")

    # detection_points has no index on the node, so this is driven from the scanned alerts
    detection_rows = db.query(DBDetectionPoint.alert_id).filter(
        DBDetectionPoint.alert_id.in_([row.id for row in candidates]),
        DBDetectionPoint.node_kind.in_(OBSERVABLE_NODE_KINDS),
        DBDetectionPoint.node_type.in_(types),
        DBDetectionPoint.node_value_sha256 == sha256_bytes.hex(),
    ).distinct().all()
    for row in detection_rows:
        by_id[row.alert_id].reasons.append("detection_point")

    active_detection = db.query(DBObservableDetection.id).filter(
        DBObservableDetection.type.in_(types),
        DBObservableDetection.value_sha256 == sha256_bytes,
        or_(DBObservableDetection.expires_on.is_(None), local_time() < DBObservableDetection.expires_on),
    ).first()
    if active_detection is not None:
        result.global_reasons.append("observable_detection")
    if any(row.is_interesting for row in db_observables):
        result.global_reasons.append("is_interesting")

    result.alerts = [by_id[alert_id] for alert_id in sorted(by_id, reverse=True)]
    return result
