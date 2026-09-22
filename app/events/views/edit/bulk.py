import logging
import uuid as uuidlib

from flask import flash, redirect, request, url_for
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import events
from saq.constants import (
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    VALID_DISPOSITIONS,
)
from saq.database.model import Comment
from saq.database.pool import get_db
from saq.database.util.alert import set_disposition_reviews, set_dispositions, touch_alerts
from saq.database.util.locking import acquire_lock, release_lock
from saq.error.reporting import report_exception
from saq.gui.alert import GUIAlert
from saq.search.tasks import submit_index_task


def _parse_bulk_request() -> tuple[str | None, list[str]]:
    """Returns the target event id and the list of selected alert uuids from the request form."""
    event_id = request.form.get('event_id')
    alert_uuids = [u for u in request.form.get('alert_uuids', '').split(',') if u]
    return event_id, alert_uuids


def _event_redirect(event_id: str | None):
    if event_id:
        return redirect(url_for('events.index', direct=event_id))
    return redirect(url_for('events.manage'))


def _apply_tags(alert_uuids: list[str], tags: list[str], add: bool) -> int:
    failed_count = 0
    for uuid in alert_uuids:
        alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == uuid).one_or_none()
        if alert is None:
            continue

        try:
            lock_uuid = str(uuidlib.uuid4())
            if acquire_lock(uuid=str(alert.uuid), lock_uuid=lock_uuid):
                alert.lock_uuid = lock_uuid
            else:
                failed_count += 1
                continue

            alert.load()
            for tag in tags:
                if add:
                    alert.root_analysis.add_tag(tag)
                else:
                    alert.root_analysis.remove_tag(tag)

            alert.sync()

        except Exception as e:
            logging.error(f"unable to modify tags on {alert}: {e}")
            failed_count += 1

        finally:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)

    return failed_count


@events.route('/bulk_add_tag', methods=['POST'])
@require_permission('alert', 'write')
def bulk_add_tag():
    event_id, alert_uuids = _parse_bulk_request()
    redirection = _event_redirect(event_id)

    if not alert_uuids:
        flash("you must select one or more alerts")
        return redirection

    tags = request.form.get('tag', '').split()
    if not tags:
        flash("you must specify one or more tags to add")
        return redirection

    logging.info(f"AUDIT: user {current_user} added tags {tags} to alerts {alert_uuids}")
    if _apply_tags(alert_uuids, tags, add=True):
        flash("unable to modify some alerts: alert is currently being analyzed")

    return redirection


@events.route('/bulk_remove_tag', methods=['POST'])
@require_permission('alert', 'write')
def bulk_remove_tag():
    event_id, alert_uuids = _parse_bulk_request()
    redirection = _event_redirect(event_id)

    if not alert_uuids:
        flash("you must select one or more alerts")
        return redirection

    tags = request.form.get('tag', '').split()
    if not tags:
        flash("you must specify one or more tags to remove")
        return redirection

    logging.info(f"AUDIT: user {current_user} removed tags {tags} from alerts {alert_uuids}")
    if _apply_tags(alert_uuids, tags, add=False):
        flash("unable to modify some alerts: alert is currently being analyzed")

    return redirection


@events.route('/bulk_add_comment', methods=['POST'])
@require_permission('alert', 'write')
def bulk_add_comment():
    event_id, alert_uuids = _parse_bulk_request()
    redirection = _event_redirect(event_id)

    if not alert_uuids:
        flash("you must select one or more alerts")
        return redirection

    user_comment = request.form.get('comment', '')
    if len(user_comment.strip()) < 1:
        flash("comment cannot be empty")
        return redirection

    logging.info(f"AUDIT: user {current_user} added comment {user_comment} to alerts {','.join(alert_uuids)}")

    for uuid in alert_uuids:
        get_db().add(Comment(user=current_user, uuid=uuid, comment=user_comment))

    touch_alerts(alert_uuids)
    get_db().commit()

    for uuid in alert_uuids:
        submit_index_task(uuid)

    flash("added comment to {0} alert{1}".format(len(alert_uuids), "s" if len(alert_uuids) != 1 else ''))
    return redirection


@events.route('/bulk_set_disposition', methods=['POST'])
@require_permission('alert', 'write')
def bulk_set_disposition():
    event_id, alert_uuids = _parse_bulk_request()
    redirection = _event_redirect(event_id)

    disposition = request.form.get('disposition', None)
    user_comment = request.form.get('comment', None)
    if user_comment is not None:
        user_comment = user_comment.strip()

    if not alert_uuids:
        flash("you must select one or more alerts")
        return redirection

    if disposition not in VALID_DISPOSITIONS:
        flash("invalid alert disposition: {0}".format(disposition))
        return redirection

    try:
        set_dispositions(alert_uuids, disposition, current_user.id, user_comment=user_comment)
        comment_clause = f"with comment {user_comment}" if user_comment else "without a comment"
        logging.info(f"AUDIT: user {current_user} set disposition of alerts {','.join(alert_uuids)} to {disposition} {comment_clause}")
        flash("disposition set for {} alerts".format(len(alert_uuids)))
    except Exception as e:
        flash("unable to set disposition (review error logs)")
        logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
        report_exception()

    return redirection


@events.route('/bulk_review_disposition', methods=['POST'])
@require_permission('alert', 'review')
def bulk_review_disposition():
    event_id, alert_uuids = _parse_bulk_request()
    redirection = _event_redirect(event_id)

    review_result = request.form.get('review_result', None)
    corrected_disposition = request.form.get('corrected_disposition', None)
    review_comment = request.form.get('comment', None)
    if review_comment is not None:
        review_comment = review_comment.strip()

    if not alert_uuids:
        flash("you must select one or more alerts")
        return redirection

    if review_result not in (DISPOSITION_REVIEW_CORRECT, DISPOSITION_REVIEW_INCORRECT):
        flash("invalid review result: {0}".format(review_result))
        return redirection

    if review_result == DISPOSITION_REVIEW_INCORRECT:
        if corrected_disposition not in VALID_DISPOSITIONS:
            flash("invalid corrected disposition: {0}".format(corrected_disposition))
            return redirection
        if not review_comment:
            flash("a review comment is required when marking a disposition incorrect")
            return redirection

    try:
        set_disposition_reviews(
            alert_uuids, review_result, current_user.id,
            corrected_disposition=corrected_disposition, review_comment=review_comment)
        comment_clause = f"with comment {review_comment}" if review_comment else "without a comment"
        logging.info(
            f"AUDIT: user {current_user} reviewed disposition of alerts {','.join(alert_uuids)} "
            f"as {review_result} (corrected disposition {corrected_disposition}) {comment_clause}")
        flash("disposition review recorded for {} alerts".format(len(alert_uuids)))
    except Exception as e:
        flash("unable to record disposition review (review error logs)")
        logging.error("unable to review disposition for {} alerts: {}".format(len(alert_uuids), e))
        report_exception()

    return redirection
