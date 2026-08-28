"""Event service for ACE API v2.

``Event.json`` (and the ``sorted_tags``/``tags`` properties it reads) issue
synchronous ``get_db()`` queries, so events cannot be serialized through an
``AsyncSession``-loaded instance. Following the pattern established in
``aceapi_v2/alerts/service.py``, the database work is done in synchronous
helpers that use ``get_db()`` and is dispatched from the async service via
``run_db_in_thread`` so it never blocks the event loop and the worker thread's
sync session is reset after each call. The sync helpers return
fully-materialized dicts/strings, so nothing lazy-loads back in the async
context.
"""

from fastapi import HTTPException

from saq.csv_builder import CSV
from saq.database import Event, EventStatus, get_db

from aceapi_v2.sync import run_db_in_thread


def _serialize_event(event: Event) -> dict:
    """Reproduce the legacy ``Event.json`` payload, normalizing ``owner``.

    ``Event.json`` stores ``owner`` as a ``User`` object; the legacy Flask JSON
    encoder rendered it via ``User.json``. We do the same so the response shape
    matches the legacy endpoint exactly.
    """
    data = event.json
    owner = data.get("owner")
    data["owner"] = owner.json if owner is not None else None
    return data


def _get_open_events_sync() -> list[dict]:
    open_events = get_db().query(Event).filter(Event.status.has(value="OPEN")).all()
    return [_serialize_event(event) for event in open_events]


def _get_event_sync(event_id: int) -> dict:
    event = get_db().get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event ID not found")
    return _serialize_event(event)


def _set_event_status_sync(event_id: int, status_value: str) -> dict:
    event = get_db().get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event ID not found")

    status = (
        get_db()
        .query(EventStatus)
        .filter(EventStatus.value == status_value)
        .one_or_none()
    )
    if status is None:
        raise HTTPException(status_code=400, detail="Must specify valid event status")

    event.status = status
    get_db().commit()
    return _serialize_event(event)


def _export_events_to_csv_sync(event_ids: list[int]) -> str:
    export_events = get_db().query(Event).filter(Event.id.in_(event_ids)).all()

    csv = CSV(
        "id",
        "uuid",
        "creation_date",
        "name",
        "type",
        "vector",
        "threat_type",
        "threat_name",
        "severity",
        "prevention_tool",
        "remediation",
        "status",
        "owner",
        "comment",
        "campaign",
        "event_time",
        "alert_time",
        "ownership_time",
        "disposition_time",
        "contain_time",
        "remediation_time",
        "YEAR(events.alert_time)",
        "MONTH(events.alert_time)",
        "MAX(disposition)",
        "tags",
        "alert_tags",
    )

    for event in export_events:
        threat_types = ", ".join(event.threats)
        threat_names = ", ".join(event.malware_names)
        campaign = event.campaign.name if event.campaign else ""
        tags = ", ".join(tag.name for tag in event.tags)
        # sorted_tags walks EventMapping -> Alert -> TagMapping at query time;
        # nothing is written back to event_tag_mapping.
        alert_tags = ", ".join(event.sorted_tags)

        csv.add_row(
            event.id,
            event.uuid,
            event.creation_date,
            event.name,
            event.type.value,
            event.vector.value,
            threat_types,
            threat_names,
            event.risk_level.value,
            event.prevention_tool.value,
            event.remediation.value,
            event.status.value,
            event.owner,
            event.comment,
            campaign,
            event.event_time,
            event.alert_time,
            event.ownership_time,
            event.disposition_time,
            event.contain_time,
            event.remediation_time,
            event.alert_time.year if event.alert_time else "",
            event.alert_time.strftime("%b") if event.alert_time else "",
            event.disposition,
            tags,
            alert_tags,
        )

    return str(csv)


async def get_open_events() -> list[dict]:
    """Return all events with status ``OPEN`` serialized as ``Event.json`` dicts."""
    return await run_db_in_thread(_get_open_events_sync)


async def get_event(event_id: int) -> dict:
    """Return a single event serialized as an ``Event.json`` dict. Raises 404.

    The ``alerts`` key holds the UUIDs of every alert mapped to the event.
    """
    return await run_db_in_thread(_get_event_sync, event_id)


async def set_event_status(event_id: int, status_value: str) -> dict:
    """Set an event's status, returning the updated event. Raises 404/400."""
    return await run_db_in_thread(_set_event_status_sync, event_id, status_value)


async def export_events_to_csv(event_ids: list[int]) -> str:
    """Return a CSV export of the given events."""
    return await run_db_in_thread(_export_events_to_csv_sync, event_ids)
