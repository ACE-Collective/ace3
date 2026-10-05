import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.alert_ownership import confirmed_takes_from_form, describe_skipped
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.alert import set_dispositions
from saq.detection_verdicts.query import list_alert_detection_points
from saq.detection_verdicts.store import VerdictNotAllowed, clear_verdict, confirm_alert, set_verdict
from saq.disposition import DISPOSITION_CLASS_TP, get_disposition_class, is_selectable_disposition
from saq.error.reporting import report_exception


def apply_detection_verdicts(alert_uuid: str, form) -> None:
    """Applies the disposition dialog's detection verdict section (templates/analysis/index.html)
    after the alert's disposition was set: the checked detections become FP, the unchecked ones
    lose an FP they had, and "confirm" upgrades the remaining unconfirmed TPs. The section's
    inputs are only submitted when the analyst opened it, so verdict_listed is absent otherwise
    and nothing changes."""
    if not form.get("verdict_listed"):
        return

    alert_id = get_db().query(Alert.id).filter(Alert.uuid == alert_uuid).scalar()
    marked_fp = set(form.getlist("verdict_fp"))
    for row in list_alert_detection_points(alert_id):
        if row["content_hash"] in marked_fp:
            set_verdict(alert_id, row["content_hash"], "fp", current_user.id)
        elif row["override"] == "fp":
            clear_verdict(alert_id, row["content_hash"], current_user.id)

    if form.get("verdict_confirm"):
        confirm_alert(alert_id, current_user.id)

@analysis.route('/set_disposition', methods=['POST'])
@require_permission('alert', 'write')
def set_disposition():
    alert_uuids = []
    analysis_page = False

    # get disposition and user comment
    disposition = request.form.get('disposition', None)
    user_comment = request.form.get('comment', None)

    # format user comment
    if user_comment is not None:
        user_comment = user_comment.strip()

    # a configured disposition an analyst may set; the modal only offers those, so anything
    # else is a stale page or a hand-made request
    if not is_selectable_disposition(disposition):
        flash("invalid alert disposition: {0}".format(disposition))
        return redirect(url_for('analysis.index'))

    # get uuids
    # we will either get one uuid from the analysis page or multiple uuids from the management page
    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        alert_uuids = request.form['alert_uuids'].split(',')
    else:
        logging.debug("neither of the expected request fields were present")
        flash("internal error; no alerts were selected")
        return redirect(url_for('analysis.index'))

    # update the database
    logging.debug("user {} updating {} alerts to {}".format(current_user.username, len(alert_uuids), disposition))
    try:
        ownership = set_dispositions(alert_uuids, disposition, current_user.id, user_comment=user_comment,
                                     confirmed_takes=confirmed_takes_from_form(request.form))
        comment_clause = f"with comment {user_comment}" if user_comment else "without a comment"
        logging.info(f"AUDIT: user {current_user} set disposition of alerts {','.join(ownership.permitted)} to {disposition} {comment_clause}")
        message = "disposition set for {} alerts".format(len(ownership.permitted))
        skipped = describe_skipped(ownership)
        flash(f"{message}; {skipped}" if skipped else message)

        # the verdict step is offered on the alert page only, for a tp disposition; the manage
        # page's bulk disposition has none
        if analysis_page and alert_uuids[0] in ownership.permitted \
                and get_disposition_class(disposition) == DISPOSITION_CLASS_TP:
            try:
                apply_detection_verdicts(alert_uuids[0], request.form)
            except VerdictNotAllowed as e:
                flash(f"detection verdicts not saved: {e}")
    except Exception as e:
        flash("unable to set disposition (review error logs)")
        logging.error("unable to set disposition for {} alerts: {}".format(len(alert_uuids), e))
        report_exception()

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))