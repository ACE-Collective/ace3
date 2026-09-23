import logging
from dataclasses import dataclass, field
from datetime import datetime

from saq.analysis.root import RootAnalysis
from saq.constants import (
    ANALYSIS_MODE_DISPOSITIONED,
    DISPOSITION_IGNORE,
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    REVIEW_COMMENT_PREFIX,
)
from saq.database.model import Alert, new_alert_version
from saq.configuration.config import get_config
from saq.database.pool import get_db, get_db_connection
from saq.environment import get_global_runtime_settings
from saq.search.tasks import submit_index_task, submit_payload_task


def _fetch_disposition_context(c, alert_uuids: list) -> dict:
    """Read the alert metadata worth recording alongside a disposition change,
    keyed by alert uuid.

    Must be called BEFORE the UPDATE: it captures the outgoing disposition,
    which the UPDATE overwrites in place, and the pre-existing owner, which
    set_dispositions() back-fills when it is NULL.

    Alerts dispositioned IGNORE are eventually deleted outright, taking their
    title with them. The log line these fields produce is the only lasting
    record, so an analyst searching for an ignored alert by name has something
    to find.
    """
    if not alert_uuids:
        return {}

    uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
    c.execute(f"""
              SELECT a.uuid, a.description, a.disposition, a.alert_type, a.tool,
                     a.tool_instance, a.queue, a.insert_date, a.event_time,
                     c.name, o.username
              FROM alerts a
                  LEFT JOIN company c ON a.company_id = c.id
                  LEFT JOIN users o ON a.owner_id = o.id
              WHERE a.uuid IN ( {uuid_placeholders} )""", tuple(alert_uuids))

    return {
        row[0]: {
            "alert_uuid": row[0],
            "alert_description": row[1],
            "old_disposition": row[2],
            "alert_type": row[3],
            "alert_tool": row[4],
            "alert_tool_instance": row[5],
            "alert_queue": row[6],
            "alert_insert_date": row[7].isoformat() if row[7] else None,
            "alert_event_time": row[8].isoformat() if row[8] else None,
            "alert_company": row[9],
            "alert_owner": row[10],
        }
        for row in c.fetchall()
    }


@dataclass(frozen=True)
class AlertOwner:
    """Who owns an alert, as the ownership check needs to know it."""
    user_id: int | None = None
    name: str | None = None
    enabled: bool = True


@dataclass
class OwnershipCheck:
    """Which of the alerts a user asked to change they may change.

    An alert owned by another analyst is changed only when the user confirmed taking it
    from that analyst. Alerts owned by a disabled account count as unowned."""
    # the alerts that may be changed, in the order they were asked for
    permitted: list[str] = field(default_factory=list)
    # the permitted alerts that change hands: taken from another analyst, or owned by a
    # disabled account
    reassigned: list[str] = field(default_factory=list)
    # alert uuid -> display name of the analyst who owns it, for the alerts left alone
    skipped: dict[str, str] = field(default_factory=dict)


def check_alert_ownership(
    alert_uuids: list[str],
    owners: dict[str, AlertOwner],
    user_id: int,
    confirmed_takes: dict[str, int] | None = None,
) -> OwnershipCheck:
    """Decides which of alert_uuids the user may change (see OwnershipCheck).

    :param owners: the owner of each alert that exists; an alert missing from it is dropped.
    :param confirmed_takes: alert uuid -> id of the analyst the user agreed to take it from.
        The confirmation only counts while that analyst still owns the alert, so an alert
        someone else took in the meantime is left alone rather than taken from them unseen."""
    confirmed_takes = confirmed_takes or {}
    result = OwnershipCheck()
    for alert_uuid in dict.fromkeys(alert_uuids):
        owner = owners.get(alert_uuid)
        if owner is None:
            continue

        if owner.user_id is None or owner.user_id == user_id:
            result.permitted.append(alert_uuid)
        elif not owner.enabled or confirmed_takes.get(alert_uuid) == owner.user_id:
            result.permitted.append(alert_uuid)
            result.reassigned.append(alert_uuid)
        else:
            result.skipped[alert_uuid] = owner.name

    return result


def _fetch_alert_owners(c, alert_uuids: list) -> dict[str, AlertOwner]:
    """Reads the owner of each alert and locks the alert rows until the transaction ends, so
    ownership cannot change between the check and the UPDATE that relies on it."""
    if not alert_uuids:
        return {}

    uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
    c.execute(f"""
              SELECT a.uuid, a.owner_id, COALESCE(o.display_name, o.username), o.enabled
              FROM alerts a
                  LEFT JOIN users o ON a.owner_id = o.id
              WHERE a.uuid IN ( {uuid_placeholders} )
              FOR UPDATE OF a""", tuple(alert_uuids))

    # an owner whose users row is gone has nobody left to protect, the same as a disabled one
    return {
        row[0]: AlertOwner(user_id=row[1], name=row[2], enabled=bool(row[3]))
        for row in c.fetchall()
    }


def _fetch_username(c, user_id: int) -> str | None:
    """Resolve a user id to a username for logging. These helpers receive an id
    rather than a User object, and the id alone is meaningless in a log."""
    c.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    return row[0] if row else None


def _log_disposition_changes(event: str, context: dict, changed_uuids: list, **fields):
    """Emit one structured audit line per alert whose disposition actually changed.

    Per-alert rather than per-batch: a bulk disposition of 50 alerts needs 50
    lines, because the whole point is attaching each alert's own title to its
    own event.

    The fields ride in extra={} only, never repeated in the message text --
    see ExtraAwareTextFormatter in saq/logging.py for why.
    """
    for uuid in changed_uuids:
        logging.info(event, extra={**context[uuid], **fields})


def _log_ownership_taken(context: dict, taken_uuids: list, new_owner: str | None):
    """Emit one audit line per alert taken from another analyst (or from a disabled account).
    The context's alert_owner is who had it."""
    for uuid in taken_uuids:
        logging.info("AUDIT: alert ownership taken", extra={**context[uuid], "new_owner": new_owner})


def ALERT(root: RootAnalysis, owner_id: int | None = None) -> Alert:
    """Converts the given RootAnalysis object to an Alert by inserting it into the database. Returns the (detached) Alert object.
       :param owner_id: When given, the id of the User who owns the alert from the moment it exists."""
    alert = Alert.create_from_root_analysis(root)
    if owner_id is not None:
        alert.owner_id = owner_id
        alert.owner_time = datetime.now()
    alert.sync()
    return alert

def get_alert_by_uuid(uuid: str) -> Alert | None:
    """Given a UUID, this function will return the Alert object from the database, or None if it does not exist."""
    return get_db().query(Alert).filter(Alert.uuid == uuid).one_or_none()

def touch_alerts(alert_uuids: list[str], cursor=None) -> None:
    """Rotates alerts.version for the given alerts so that API clients polling them see a change.

    Call this from any code path that changes something about an alert without going through
    Alert.sync() (which rotates the version itself) -- comments, ownership, event membership.
    Pass the caller's pymysql cursor to rotate inside the caller's transaction; without one the
    UPDATE is issued on the get_db() session and the caller is expected to commit it."""
    if not alert_uuids:
        return

    version = new_alert_version()
    if cursor is not None:
        uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
        cursor.execute(f"UPDATE alerts SET version = %s WHERE uuid IN ( {uuid_placeholders} )",
                       [version, *alert_uuids])
        return

    get_db().execute(Alert.__table__.update().where(Alert.uuid.in_(alert_uuids)).values(version=version))

def node_scope_locations() -> list[str] | None:
    """The alert locations (nodes) this deployment lets analysts see, or None for no scoping.

    This is the only server-side visibility rule ACE applies to alert lists; the GUI alert
    query and the search API both use it so a search can never show an alert the manage page
    would not.
    """
    if get_config().gui.local_node_only:
        return [get_global_runtime_settings().saq_node]

    if get_config().gui.display_node_list:
        return list(get_config().gui.display_node_list)

    return None

def _submit_search_updates(alert_uuids, reindex: bool) -> None:
    """Queues search index updates for alerts whose disposition (and possibly comments) changed."""
    submit = submit_index_task if reindex else submit_payload_task
    for alert_uuid in alert_uuids:
        submit(alert_uuid)

def _reassign_owner(c, alert_uuids: list, user_id: int) -> None:
    """Makes user_id the owner of the given alerts, inside the caller's transaction."""
    if not alert_uuids:
        return

    uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
    c.execute(f"""UPDATE alerts SET owner_id = %s, owner_time = NOW(), version = %s
                  WHERE uuid IN ( {uuid_placeholders} )""",
              [user_id, new_alert_version(), *alert_uuids])

def set_dispositions(alert_uuids, disposition, user_id, user_comment=None, confirmed_takes=None) -> OwnershipCheck:
    """Utility function to the set disposition of many Alerts at once.

    An alert owned by another analyst is left alone unless the user confirmed taking it, in
    which case the user becomes its owner (see check_alert_ownership).

       :param alert_uuids: A list of UUIDs of Alert objects to set.
       :param disposition: The disposition to set the Alerts.
       :param user_id: The id of the User that is setting the disposition.
       :param user_comment: Optional comment the User is providing as part of the disposition.
       :param confirmed_takes: alert uuid -> id of the analyst the User agreed to take it from.
       :returns: which alerts were dispositioned and which were left alone."""

    with get_db_connection() as db:
        c = db.cursor()

        ownership = check_alert_ownership(alert_uuids, _fetch_alert_owners(c, alert_uuids), user_id, confirmed_takes)
        alert_uuids = ownership.permitted
        if not alert_uuids:
            return ownership

        # capture what the alerts look like before the UPDATE overwrites the
        # outgoing disposition (and before the owner changes below)
        context = _fetch_disposition_context(c, alert_uuids)
        acting_username = _fetch_username(c, user_id)

        _reassign_owner(c, ownership.reassigned, user_id)

        # update dispositions
        uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
        sql = f"""UPDATE alerts SET
                      disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                      owner_id = IF(owner_id IS NULL, %s, owner_id), owner_time = IF(owner_time IS NULL, NOW(), owner_time),
                      version = %s
                  WHERE
                      (disposition IS NULL OR disposition != %s) AND uuid IN ( {uuid_placeholders} )"""
        parameters = [disposition, user_id, user_id, new_alert_version(), disposition]
        parameters.extend(alert_uuids)
        c.execute(sql, parameters)

        # add the comment if it exists
        if user_comment:
            for uuid in alert_uuids:
                c.execute("""
                          INSERT INTO comments ( user_id, uuid, comment ) 
                          VALUES ( %s, %s, %s )""", ( user_id, uuid, user_comment))

            # the UPDATE above only rotates the version of alerts whose disposition changed,
            # but the comment landed on all of them
            touch_alerts(alert_uuids, cursor=c)

        # now we need to insert each of these alert back into the workload
        # if we are setting the disposition to anything but IGNORE
        if disposition != DISPOSITION_IGNORE:
            sql = f"""
INSERT IGNORE INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, storage_dir ) 
SELECT 
    alerts.uuid, 
    nodes.id,
    %s, 
    NOW(),
    alerts.company_id, 
    alerts.storage_dir 
FROM 
    alerts JOIN nodes ON alerts.location = nodes.name
WHERE 
    uuid IN ( {uuid_placeholders} )"""
            params = [ ANALYSIS_MODE_DISPOSITIONED ]
            params.extend(alert_uuids)
            c.execute(sql, tuple(params))

        db.commit()

    # keep the search index in step: a comment means new text to index, otherwise only
    # the disposition in the payload changes
    _submit_search_updates(alert_uuids, reindex=bool(user_comment))

    # log only alerts that actually changed, mirroring the UPDATE's own guard --
    # re-applying the same disposition is a no-op and must not look like an event.
    # emitted after the commit so nothing durable-looking is logged for a rollback
    changed_uuids = [
        uuid for uuid, row in context.items() if row["old_disposition"] != disposition
    ]
    _log_disposition_changes(
        "AUDIT: alert dispositioned", context, changed_uuids,
        new_disposition=disposition,
        disposition_user=acting_username,
        disposition_comment=user_comment,
    )
    _log_ownership_taken(context, ownership.reassigned, acting_username)

    return ownership

def take_ownership(alert_uuids, user_id, confirmed_takes=None) -> OwnershipCheck:
    """Makes the user the owner of the given alerts. An alert owned by another analyst is left
    alone unless the user confirmed taking it (see check_alert_ownership).
       :param confirmed_takes: alert uuid -> id of the analyst the User agreed to take it from.
       :returns: which alerts were taken and which were left alone."""
    with get_db_connection() as db:
        c = db.cursor()

        ownership = check_alert_ownership(alert_uuids, _fetch_alert_owners(c, alert_uuids), user_id, confirmed_takes)
        if not ownership.permitted:
            return ownership

        context = _fetch_disposition_context(c, ownership.reassigned)
        acting_username = _fetch_username(c, user_id)

        _reassign_owner(c, ownership.permitted, user_id)
        db.commit()

    _log_ownership_taken(context, ownership.reassigned, acting_username)
    return ownership

def set_disposition_reviews(alert_uuids, review_result, reviewer_id, corrected_disposition=None, review_comment=None):
    """Utility function to record a senior analyst's review of the disposition of many Alerts at once.
       :param alert_uuids: A list of UUIDs of Alert objects to review.
       :param review_result: Either DISPOSITION_REVIEW_CORRECT or DISPOSITION_REVIEW_INCORRECT.
       :param reviewer_id: The id of the User performing the review.
       :param corrected_disposition: When the review result is INCORRECT, the disposition to correct the alerts to.
       :param review_comment: Optional comment describing the review; stored as an alert comment prefixed with
                              REVIEW_COMMENT_PREFIX. Required by the caller when the result is INCORRECT."""

    # build the prefixed review comment if one was provided
    prefixed_comment = None
    if review_comment:
        prefixed_comment = f"{REVIEW_COMMENT_PREFIX}{review_comment.strip()}"

    if review_result == DISPOSITION_REVIEW_INCORRECT:
        # the disposition is wrong and must be corrected

        # preserve the original (incorrect) disposition, apply the correction, and record the review in a single
        # transaction. the preserve+correct happen in one UPDATE: MySQL evaluates SET assignments left to right
        # using prior column values, so incorrect_disposition captures the original disposition before it is
        # overwritten. the WHERE guard ensures we only touch alerts whose disposition is actually changing.
        with get_db_connection() as db:
            c = db.cursor()

            # capture the outgoing (incorrect) disposition before it moves to
            # incorrect_disposition and the correction takes its place
            context = _fetch_disposition_context(c, alert_uuids)
            acting_username = _fetch_username(c, reviewer_id)

            uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
            sql = f"""UPDATE alerts SET
                          incorrect_disposition = disposition,
                          incorrect_disposition_user_id = disposition_user_id,
                          incorrect_disposition_time = disposition_time,
                          disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                          owner_id = IF(owner_id IS NULL, %s, owner_id), owner_time = IF(owner_time IS NULL, NOW(), owner_time),
                          disposition_review = %s, review_user_id = %s, review_time = NOW(),
                          version = %s
                      WHERE
                          disposition != %s AND uuid IN ( {uuid_placeholders} )"""
            parameters = [corrected_disposition, reviewer_id, reviewer_id, DISPOSITION_REVIEW_INCORRECT, reviewer_id, new_alert_version(), corrected_disposition]
            parameters.extend(alert_uuids)
            c.execute(sql, parameters)

            # add the review comment if it exists
            if prefixed_comment:
                for uuid in alert_uuids:
                    c.execute("""
                              INSERT INTO comments ( user_id, uuid, comment )
                              VALUES ( %s, %s, %s )""", ( reviewer_id, uuid, prefixed_comment))

                # the comment landed on every alert, not just the ones the UPDATE guard let through
                touch_alerts(alert_uuids, cursor=c)

            # re-insert each corrected alert back into the workload unless the correction is IGNORE
            if corrected_disposition != DISPOSITION_IGNORE:
                sql = f"""
INSERT IGNORE INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, storage_dir )
SELECT
    alerts.uuid,
    nodes.id,
    %s,
    NOW(),
    alerts.company_id,
    alerts.storage_dir
FROM
    alerts JOIN nodes ON alerts.location = nodes.name
WHERE
    uuid IN ( {uuid_placeholders} )"""
                params = [ ANALYSIS_MODE_DISPOSITIONED ]
                params.extend(alert_uuids)
                c.execute(sql, tuple(params))

            db.commit()

        _submit_search_updates(alert_uuids, reindex=bool(review_comment))

        # a correction to IGNORE deletes the alert just as a direct disposition
        # does, so this path needs the same lasting record
        changed_uuids = [
            uuid for uuid, row in context.items()
            if row["old_disposition"] != corrected_disposition
        ]
        _log_disposition_changes(
            "AUDIT: alert disposition reviewed", context, changed_uuids,
            new_disposition=corrected_disposition,
            review_result=review_result,
            disposition_user=acting_username,
            disposition_comment=review_comment,
        )
    else:
        # the disposition was correct; just record the review (and optional comment)
        with get_db_connection() as db:
            c = db.cursor()

            context = _fetch_disposition_context(c, alert_uuids)
            acting_username = _fetch_username(c, reviewer_id)

            uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
            sql = f"""UPDATE alerts SET
                          disposition_review = %s, review_user_id = %s, review_time = NOW(),
                          version = %s
                      WHERE
                          uuid IN ( {uuid_placeholders} )"""
            parameters = [DISPOSITION_REVIEW_CORRECT, reviewer_id, new_alert_version()]
            parameters.extend(alert_uuids)
            c.execute(sql, parameters)

            # add the review comment if it exists
            if prefixed_comment:
                for uuid in alert_uuids:
                    c.execute("""
                              INSERT INTO comments ( user_id, uuid, comment )
                              VALUES ( %s, %s, %s )""", ( reviewer_id, uuid, prefixed_comment))

            db.commit()

        if prefixed_comment:
            _submit_search_updates(alert_uuids, reindex=True)

        # the review confirms the existing disposition rather than changing it,
        # so old and new are the same -- but the review itself is still an event
        for row in context.values():
            row["new_disposition"] = row["old_disposition"]
        _log_disposition_changes(
            "AUDIT: alert disposition reviewed", context, list(context),
            review_result=review_result,
            disposition_user=acting_username,
            disposition_comment=review_comment,
        )
