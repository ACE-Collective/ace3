import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import (
    DISPOSITION_REVIEW_CORRECT,
    DISPOSITION_REVIEW_INCORRECT,
    VALID_DISPOSITIONS,
)
from saq.database.util.alert import set_disposition_reviews
from saq.error.reporting import report_exception

@analysis.route('/review_disposition', methods=['POST'])
@require_permission('alert', 'review')
def review_disposition():
    alert_uuids = []
    analysis_page = False

    # get the review result and (when incorrect) the corrected disposition and comment
    review_result = request.form.get('review_result', None)
    corrected_disposition = request.form.get('corrected_disposition', None)
    review_comment = request.form.get('comment', None)

    # format the review comment
    if review_comment is not None:
        review_comment = review_comment.strip()

    # the review result must be one of the two valid values
    if review_result not in (DISPOSITION_REVIEW_CORRECT, DISPOSITION_REVIEW_INCORRECT):
        flash("invalid review result: {0}".format(review_result))
        return redirect(url_for('analysis.manage'))

    # marking a disposition incorrect requires a corrected disposition and a review comment
    if review_result == DISPOSITION_REVIEW_INCORRECT:
        if corrected_disposition not in VALID_DISPOSITIONS:
            flash("invalid corrected disposition: {0}".format(corrected_disposition))
            return redirect(url_for('analysis.manage'))
        if not review_comment:
            flash("a review comment is required when marking a disposition incorrect")
            return redirect(url_for('analysis.manage'))

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
        return redirect(url_for('analysis.manage'))

    # update the database
    logging.debug("user %s reviewing %s alerts as %s", current_user.username, len(alert_uuids), review_result)
    try:
        set_disposition_reviews(
            alert_uuids, review_result, current_user.id,
            corrected_disposition=corrected_disposition, review_comment=review_comment)
        comment_clause = f"with comment {review_comment}" if review_comment else "without a comment"
        logging.info(
            "AUDIT: user %s reviewed disposition of alerts %s as %s (corrected disposition %s) %s",
            current_user, ','.join(alert_uuids), review_result, corrected_disposition, comment_clause)
        flash("disposition review recorded for {} alerts".format(len(alert_uuids)))
    except Exception as e:
        flash("unable to record disposition review (review error logs)")
        logging.error("unable to review disposition for %s alerts: %s", len(alert_uuids), e)
        report_exception()

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))
