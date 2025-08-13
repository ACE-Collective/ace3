from datetime import datetime
import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.model import User
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert

@analysis.route('/assign_ownership', methods=['POST'])
@require_permission('alert', 'write')
def assign_ownership():
    analysis_page = False
    alert_uuids = []

    try:
        owner_id = int(request.form['selected_user_id'])
    except ValueError:
        logging.warning("invalid user id: %s", request.form['selected_user_id'])
        flash("invalid user id: {0}".format(request.form['selected_user_id']))
        return redirect(url_for('analysis.index'))

    if 'alert_uuid' in request.form:
        analysis_page = True
        alert_uuids.append(request.form['alert_uuid'])
    elif 'alert_uuids' in request.form:
        # otherwise we will have an alert_uuids field with one or more alert UUIDs set
        alert_uuids = request.form['alert_uuids'].split(',')
        session['checked'] = alert_uuids
    else:
        logging.debug("neither of the expected request fields were present")
        flash("internal error; no alerts were selected")
        return redirect(url_for('analysis.index'))

    if len(alert_uuids):
        get_db().execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(alert_uuids)).values(
            owner_id=owner_id,
            owner_time=datetime.now()))
        get_db().commit()

    target_user = "unknown"

    try:
        target_user = get_db().query(User).filter(User.id == int(request.form['selected_user_id'])).first()
    except Exception as e:
        logging.warning("unable to get target user: %s", e)

    logging.info("AUDIT: user %s assigned ownership of alerts %s to %s", current_user, ",".join(alert_uuids), target_user)

    flash("assigned ownership of {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    if analysis_page:
        return redirect(url_for('analysis.index', direct=alert_uuids[0]))

    return redirect(url_for('analysis.manage'))

@analysis.route('/set_owner', methods=['GET', 'POST'])
@require_permission('alert', 'write')
def set_owner():
    session['checked'] = request.args.getlist('alert_uuids') if request.method == 'GET' else request.form.getlist('alert_uuids')
    get_db().execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(session['checked'])).values(owner_id=current_user.id,owner_time=datetime.now()))
    get_db().commit()
    return ('', 204)