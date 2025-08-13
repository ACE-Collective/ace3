import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import VALID_DISPOSITIONS
from saq.database.util.alert import set_dispositions
from saq.error.reporting import report_exception

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

    # check if disposition is valid
    if disposition not in VALID_DISPOSITIONS:
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
        set_dispositions(alert_uuids, disposition, current_user.id, user_comment=user_comment)
        logging.info("AUDIT: user %s set disposition of alerts %s to %s with comment %s", 
                     current_user,
                     ",".join(alert_uuids),
                     disposition,
                     user_comment)
        flash("disposition set for {} alerts".format(len(alert_uuids)))
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