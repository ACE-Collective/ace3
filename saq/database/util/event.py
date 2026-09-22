from sqlalchemy.orm import joinedload, lazyload, selectinload

from saq.configuration.config import get_config
from saq.database.model import Alert, Event, EventMapping, EventTagMapping, Malware, MalwareMapping, Tag, TagMapping, Threat
from saq.database.pool import get_db
from saq.util.ui import get_tag_score


def event_list_load_options() -> list:
    """Loader options for a query that returns many events and then reads, for each one, its
    disposition (every mapped alert) and its malware and threat names.

    Left lazy, those are a query per event for the mappings plus a query per mapped alert.
    With these the whole list costs a fixed number of queries however long it is."""
    return [
        # Alert.tag_mappings is lazy='joined'; nothing that lists events reads alert tags
        # through the alert, so the join would only multiply rows
        selectinload(Event.alert_mappings).joinedload(EventMapping.alert).options(lazyload(Alert.tag_mappings)),
        selectinload(Event.malware).joinedload(MalwareMapping.malware).selectinload(Malware.threats).joinedload(Threat.threat_type),
    ]


def event_alerts_load_options() -> list:
    """Loader options for a query that returns one event and then lists its alerts the way the
    alert management page does: each alert's status (its lock, delayed analysis and workload
    rows) and its tags."""
    return [
        selectinload(Event.alert_mappings).selectinload(EventMapping.alert).options(
            selectinload(Alert.lock),
            selectinload(Alert.delayed_analysis),
            selectinload(Alert.workload),
            selectinload(Alert.tag_mappings).joinedload(TagMapping.tag),
        ),
    ]


def get_event_tags(event_ids: list[int]) -> dict[int, list[Tag]]:
    """Event.tags for many events in one query: event id -> the tags mapped directly to that
    event, by name, without the special and hidden ones. Every requested id has an entry."""
    event_tags = {event_id: [] for event_id in event_ids}
    if not event_ids:
        return event_tags

    ignore_tags = [tag for tag in get_config().tags.keys() if get_config().tags[tag] in ['special', 'hidden']]
    query = get_db().query(EventTagMapping.event_id, Tag) \
        .join(Tag, Tag.id == EventTagMapping.tag_id) \
        .filter(EventTagMapping.event_id.in_(event_ids), Tag.name.notin_(ignore_tags)) \
        .order_by(Tag.name.asc())

    for event_id, tag in query:
        event_tags[event_id].append(tag)

    return event_tags


def get_event_alert_tag_names(event_ids: list[int]) -> dict[int, list[str]]:
    """Event.sorted_tags for many events in one query: event id -> the distinct names of the
    tags carried by that event's alerts, highest scoring first. Every requested id has an entry."""
    tag_names = {event_id: [] for event_id in event_ids}
    if not event_ids:
        return tag_names

    query = get_db().query(EventMapping.event_id, Tag.name) \
        .join(TagMapping, TagMapping.alert_id == EventMapping.alert_id) \
        .join(Tag, Tag.id == TagMapping.tag_id) \
        .filter(EventMapping.event_id.in_(event_ids)) \
        .distinct()

    for event_id, name in query:
        tag_names[event_id].append(name)

    for names in tag_names.values():
        names.sort(key=lambda name: (-get_tag_score(name), name.lower()))

    return tag_names
