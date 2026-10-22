from datetime import datetime
import logging
import os
import tempfile
from uuid import uuid4
from flask import flash, redirect, request, url_for
from flask_login import current_user
from aceapi_v2.observable_comments.service import create_comment
from aceapi_v2.sync import run_async_with_session
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_FILE
from saq.database.util.alert import ALERT, AlertFrozen, ensure_not_frozen, get_alert_by_uuid
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import request_analyst_analysis
from saq.environment import get_temp_dir
from saq.util import local_time, safe_file_name


def _mark_added_by_current_user(file_observable):
    """Records the analyst who uploaded the file; the alert page shows it as "added by"."""
    file_observable.added_by = current_user.username
    file_observable.added_time = local_time()


def _add_upload_comment(file_observable, comment: str, alert_uuid: str):
    """Saves the upload form's comment as an observable comment on the uploaded file. The upload has
    already happened by now, so a failure here is reported rather than failing the request."""
    if not comment.strip():
        return

    try:
        run_async_with_session(create_comment, current_user.id, F_FILE, file_observable.value, comment)
    except Exception as e:
        logging.exception(f"unable to add the upload comment to {file_observable} in alert {alert_uuid}: {e}")
        flash("uploaded the file, but unable to save the comment")
        return

    logging.info(f"AUDIT: user {current_user} added comment {comment} to observable {F_FILE} {file_observable.value} in alert {alert_uuid}")

@analysis.route('/upload_file', methods=['POST'])
@require_permission('alert', 'create')
def upload_file():
    file_path = request.files.get('file_path')
    comment = request.form.get("comment", "")
    alert_uuid = request.form.get("alert_uuid","")
    if not file_path:
        flash("No file specified for upload.")
        return redirect(url_for('analysis.file'))

    file_name = file_path.filename

    # the client's name is stored in the alert, so it is made a plain file name, but one that
    # keeps spaces and non-ascii characters
    target_name = safe_file_name(file_name)

    # a temporary file of the request's own: the alert's copy is a hardlink to it, so a temporary
    # path named after the upload would let the next upload by that name rewrite this one's bytes
    fd, temp_path = tempfile.mkstemp(dir=get_temp_dir())
    os.close(fd)
    try:
        return _store_upload(file_path, temp_path, file_name, target_name, comment, alert_uuid)
    finally:
        os.unlink(temp_path)


def _store_upload(file_path, temp_path: str, file_name: str, target_name: str, comment: str, alert_uuid: str):
    try:
        file_path.save(temp_path)
    except Exception as e:
        logging.exception(f"unable to save file to {temp_path}: {e}")
        flash(f"unable to save file to temporary location: {e}")
        return redirect(url_for('analysis.file'))

    if not alert_uuid:
        root = RootAnalysis()
        root.tool = 'Manual File Upload - '+file_name
        root.tool_instance = get_config().global_settings.instance_name
        root.alert_type = 'manual_upload'
        root.description = 'Manual File upload {0}'.format(file_name)
        root.event_time = datetime.now()
        root.details = {'user': current_user.username, 'comment': comment}

        file_observable = root.add_file_observable(temp_path, target_name)
        if file_observable:
            _mark_added_by_current_user(file_observable)
        root.save()

        alert = ALERT(root)
        alert.root_analysis.schedule()
        logging.info(f"AUDIT: user {current_user} uploaded file {file_name} as new alert {alert.uuid}")

    else:
        alert = get_current_alert()
        if not alert:
            flash("no alert found")
            return redirect(url_for('analysis.index'))

        try:
            ensure_not_frozen(alert)
        except AlertFrozen as e:
            flash(str(e))
            return redirect(url_for('analysis.index', direct=alert.uuid))

        lock_uuid = str(uuid4())
        if not acquire_lock(alert.uuid, lock_uuid):
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        try:
            if not alert.root_analysis.load():
                flash("unable to load alert {}".format(alert))
                return redirect(url_for('analysis.index'))

            # the same file at the same path is the observable already in the tree, which the engine
            # may have added, so only a new observable is marked as the analyst's
            existing_uuids = {o.uuid for o in alert.root_analysis.all_observables}
            file_observable = alert.root_analysis.add_file_observable(temp_path, target_name)
            if file_observable and file_observable.uuid not in existing_uuids:
                _mark_added_by_current_user(file_observable)

            # back to correlation mode, or a file uploaded to a dispositioned alert is queued in a
            # mode that runs almost no modules
            request_analyst_analysis(alert.root_analysis)
            alert.sync()
        finally:
            lock_released = release_lock(alert.uuid, lock_uuid)

        if not lock_released:
            flash("unable to release lock for alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        alert.root_analysis.schedule()
        logging.info(f"AUDIT: user {current_user} uploaded file {file_name} to alert {alert.uuid}")

    if file_observable:
        _add_upload_comment(file_observable, comment, alert.uuid)

    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/analyze_alert', methods=['POST'])
@require_permission('alert', 'write')
def analyze_alert():
    alert_uuid = request.form.get("alert_uuid")
    if not alert_uuid:
        flash("no alert UUID provided")
        return redirect(url_for('analysis.index'))

    alert = get_alert_by_uuid(alert_uuid)
    if not alert:
        flash("alert not found")
        return redirect(url_for('analysis.index'))

    try:
        ensure_not_frozen(alert)
    except AlertFrozen as e:
        flash(str(e))
        return redirect(url_for('analysis.index', direct=alert.uuid))

    alert.root_analysis.schedule()
    return redirect(url_for('analysis.index', direct=alert.uuid))