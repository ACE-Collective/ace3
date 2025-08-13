import logging
import uuid as uuidlib
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import REDIRECT_MAP
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.gui.alert import GUIAlert

@analysis.route('/add_tag', methods=['POST'])
@require_permission('alert', 'write')
def add_tag():
    for expected_form_item in ['tag', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    tags = request.form['tag'].split()
    if len(tags) < 1:
        flash("you must specify one or more tags to add")
        return redirection

    failed_count = 0

    logging.info("AUDIT: user %s added tags %s to alerts %s", 
                 current_user,
                 ",".join(tags),
                 ",".join(uuids))

    for uuid in uuids:
        logging.debug("attempting to lock alert {} for tagging".format(uuid))
        alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
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
                alert.root_analysis.add_tag(tag)

            alert.sync()

        except Exception as e:
            logging.error(f"unable to add tag to {alert}: {e}")
            failed_count += 1

        finally:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)

    if failed_count:
        flash("unable to modify alert: alert is currently being analyzed")

    if redirect_to == "analysis.manage":
        session['checked'] = uuids

    return redirection

@analysis.route('/remove_tag', methods=['POST'])
@require_permission('alert', 'write')
def remove_tag():
    for expected_form_item in ['tag', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    tags = request.form['tag'].split()
    if len(tags) < 1:
        flash("you must specify one or more tags to remove")
        return redirection

    failed_count = 0

    for uuid in uuids:
        logging.debug("attempting to lock alert {} for tagging".format(uuid))
        alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
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
                alert.root_analysis.remove_tag(tag)

            alert.sync()
            logging.info("AUDIT: user %s removed tag %s from alert %s", current_user, tag, alert)

        except Exception as e:
            logging.error(f"unable to remove tag from {alert}: {e}")
            failed_count += 1

        finally:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)

    if failed_count:
        flash("unable to modify alert: alert is currently being analyzed")

    if redirect_to == "analysis.manage":
        session['checked'] = uuids

    return redirection