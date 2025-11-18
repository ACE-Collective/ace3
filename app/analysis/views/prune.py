import logging
from flask import redirect, request, session, url_for
from flask_login import current_user, login_required
from app.blueprints import analysis
from saq.constants import DEFAULT_PRUNE, DEFAULT_PRUNE_VOLATILE

@analysis.route('/toggle_prune', methods=['POST', 'GET'])
@login_required
def toggle_prune():
    # Critical Analysis view is disabled - always force Detailed Analysis
    session['prune'] = False
    logging.debug("prune forced to False (Critical Analysis disabled) for {}".format(current_user))

    alert_uuid = None
    if 'alert_uuid' in request.values:
        alert_uuid = request.values['alert_uuid']

    return redirect(url_for('analysis.index', alert_uuid=alert_uuid))

@analysis.route('/toggle_prune_volatile', methods=['POST', 'GET'])
@login_required
def toggle_prune_volatile():
    if 'prune_volatile' not in session:
        session['prune_volatile'] = DEFAULT_PRUNE_VOLATILE

    if not isinstance(session['prune_volatile'], bool):
        session['prune_volatile'] = DEFAULT_PRUNE_VOLATILE

    session['prune_volatile'] = not session['prune_volatile']
    logging.debug("prune volatile set to {} for {}".format(session['prune_volatile'], current_user))

    alert_uuid = None
    if 'alert_uuid' in request.values:
        alert_uuid = request.values['alert_uuid']

    return redirect(url_for('analysis.index', alert_uuid=alert_uuid))
