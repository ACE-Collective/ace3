from datetime import datetime
import os
from uuid import uuid4
from flask import flash, redirect, request, url_for
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import get_temp_dir
from saq.error.reporting import report_exception

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

    # securely save the file to a temporary location
    from werkzeug.utils import secure_filename

    # Use secure_filename to sanitize the uploaded file name
    safe_file_name = secure_filename(file_name)
    temp_dir = get_temp_dir()
    temp_path = os.path.join(temp_dir, safe_file_name)

    try:
        file_path.save(temp_path)
    except Exception as e:
        flash(f"unable to save file to temporary location: {e}")
        report_exception()
        return redirect(url_for('analysis.file'))

    if not alert_uuid:
        root = RootAnalysis()
        root.tool = 'Manual File Upload - '+file_name
        root.tool_instance = get_config()['global']['instance_name']
        root.alert_type = 'manual_upload'
        root.description = 'Manual File upload {0}'.format(file_name)
        root.event_time = datetime.now()
        root.details = {'user': current_user.username, 'comment': comment}

        root.add_file_observable(temp_path, file_name)
        root.save()

        alert = ALERT(root)
        alert.root_analysis.schedule()

    else:
        alert = get_current_alert()
        if not alert:
            flash("no alert found")
            return redirect(url_for('analysis.index'))

        lock_uuid = str(uuid4())
        if not acquire_lock(alert.uuid, lock_uuid):
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        if not alert.root_analysis.load():
            flash("unable to load alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        alert.root_analysis.add_file_observable(temp_path, file_name)
        alert.sync()

        if not release_lock(alert.uuid, lock_uuid):
            flash("unable to release lock for alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        alert.root_analysis.schedule()

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

    alert.root_analysis.schedule()
    return redirect(url_for('analysis.index', direct=alert.uuid))