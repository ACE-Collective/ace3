import logging
from datetime import datetime

from flask import flash, redirect, request, session, url_for
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.model import User, new_alert_version
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert


@analysis.route('/assign_ownership', methods=['POST'])
@require_permission('alert', 'write')
def assign_ownership():
    analysis_page = False
    alert_uuids = []

    raw_user_id = request.form.get('selected_user_id', '')
    unassign = raw_user_id == ''
    owner_id = None
    if not unassign:
        try:
            owner_id = int(raw_user_id)
        except ValueError:
            logging.warning(f"invalid user id: {raw_user_id}")
            flash(f"invalid user id: {raw_user_id}")
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
            owner_id=None if unassign else owner_id,
            owner_time=None if unassign else datetime.now(),
            version=new_alert_version()))
        get_db().commit()

    target_user = "unassigned" if unassign else "unknown"

    if not unassign:
        try:
            target_user = get_db().query(User).filter(User.id == owner_id).first()
        except Exception as e:
            logging.warning(f"unable to get target user: {e}")

    logging.info(f"AUDIT: user {current_user} assigned ownership of alerts {','.join(alert_uuids)} to {target_user}")

    if unassign:
        flash("unassigned {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    else:
        flash("assigned ownership of {0} alert{1}".format(len(alert_uuids), "" if len(alert_uuids) == 1 else "s"))
    if analysis_page:
        return redirect(url_for('analysis.index', direct=alert_uuids[0]))

    return redirect(url_for('analysis.manage'))

@analysis.route('/set_owner', methods=['POST'])
@require_permission('alert', 'write')
def set_owner():
    # POST-only: this endpoint writes to the database. As a GET it let any prefetcher or
    # link scanner assign alert ownership by merely visiting a URL.
    session['checked'] = request.form.getlist('alert_uuids')
    get_db().execute(GUIAlert.__table__.update().where(GUIAlert.uuid.in_(session['checked'])).values(owner_id=current_user.id, owner_time=datetime.now(), version=new_alert_version()))
    get_db().commit()
    return ('', 204)