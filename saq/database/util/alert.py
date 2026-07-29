from typing import Optional
from saq.analysis.root import RootAnalysis
from saq.constants import (
    ANALYSIS_MODE_DISPOSITIONED,
    DISPOSITION_IGNORE,
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    REVIEW_COMMENT_PREFIX,
)
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection


def ALERT(root: RootAnalysis) -> Alert:
    """Converts the given RootAnalysis object to an Alert by inserting it into the database. Returns the (detached) Alert object."""
    alert = Alert.create_from_root_analysis(root)
    alert.sync()
    return alert

def get_alert_by_uuid(uuid: str) -> Optional[Alert]:
    """Given a UUID, this function will return the Alert object from the database, or None if it does not exist."""
    return get_db().query(Alert).filter(Alert.uuid == uuid).one_or_none()

def set_dispositions(alert_uuids, disposition, user_id, user_comment=None):
    """Utility function to the set disposition of many Alerts at once.
       :param alert_uuids: A list of UUIDs of Alert objects to set.
       :param disposition: The disposition to set the Alerts.
       :param user_id: The id of the User that is setting the disposition.
       :param user_comment: Optional comment the User is providing as part of the disposition."""

    # NOTE: this used to call refresh_observable_expires_on() on a malicious disposition, which
    # walked every observable in the alerts and issued an UPDATE per observable type (committing
    # inside the loop) to push observables.expires_on forward. Nothing read that column except the
    # detection cache, and detection expiration now lives in observable_detections.expires_on, set
    # explicitly by an analyst. Silently extending an analyst-chosen expiration as a side effect of
    # dispositioning would be wrong, so the behavior is gone rather than repointed.

    with get_db_connection() as db:
        c = db.cursor()
        # update dispositions
        uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
        sql = f"""UPDATE alerts SET 
                      disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                      owner_id = IF(owner_id IS NULL, %s, owner_id), owner_time = IF(owner_time IS NULL, NOW(), owner_time)
                  WHERE 
                      (disposition IS NULL OR disposition != %s) AND uuid IN ( {uuid_placeholders} )"""
        parameters = [disposition, user_id, user_id, disposition]
        parameters.extend(alert_uuids)
        c.execute(sql, parameters)
        
        # add the comment if it exists
        if user_comment:
            for uuid in alert_uuids:
                c.execute("""
                          INSERT INTO comments ( user_id, uuid, comment ) 
                          VALUES ( %s, %s, %s )""", ( user_id, uuid, user_comment))

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
            uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
            sql = f"""UPDATE alerts SET
                          incorrect_disposition = disposition,
                          incorrect_disposition_user_id = disposition_user_id,
                          incorrect_disposition_time = disposition_time,
                          disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                          owner_id = IF(owner_id IS NULL, %s, owner_id), owner_time = IF(owner_time IS NULL, NOW(), owner_time),
                          disposition_review = %s, review_user_id = %s, review_time = NOW()
                      WHERE
                          disposition != %s AND uuid IN ( {uuid_placeholders} )"""
            parameters = [corrected_disposition, reviewer_id, reviewer_id, DISPOSITION_REVIEW_INCORRECT, reviewer_id, corrected_disposition]
            parameters.extend(alert_uuids)
            c.execute(sql, parameters)

            # add the review comment if it exists
            if prefixed_comment:
                for uuid in alert_uuids:
                    c.execute("""
                              INSERT INTO comments ( user_id, uuid, comment )
                              VALUES ( %s, %s, %s )""", ( reviewer_id, uuid, prefixed_comment))

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
    else:
        # the disposition was correct; just record the review (and optional comment)
        with get_db_connection() as db:
            c = db.cursor()
            uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
            sql = f"""UPDATE alerts SET
                          disposition_review = %s, review_user_id = %s, review_time = NOW()
                      WHERE
                          uuid IN ( {uuid_placeholders} )"""
            parameters = [DISPOSITION_REVIEW_CORRECT, reviewer_id]
            parameters.extend(alert_uuids)
            c.execute(sql, parameters)

            # add the review comment if it exists
            if prefixed_comment:
                for uuid in alert_uuids:
                    c.execute("""
                              INSERT INTO comments ( user_id, uuid, comment )
                              VALUES ( %s, %s, %s )""", ( reviewer_id, uuid, prefixed_comment))

            db.commit()
