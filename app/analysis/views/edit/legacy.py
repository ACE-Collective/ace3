import logging
import uuid as uuidlib
import traceback
from flask import flash, request, url_for
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.util.locking import acquire_lock, release_lock

@analysis.route('/mark_suspect', methods=['POST'])
@require_permission('alert', 'write')
def mark_suspect():
    alert = get_current_alert()
    observable_uuid = request.form.get("observable_uuid")

    lock_uuid = str(uuidlib.uuid4())
    if acquire_lock(uuid=str(alert.uuid), lock_uuid=lock_uuid):
        alert.lock_uuid = lock_uuid
    else:
        flash("unable to lock alert")
        return "", 400

    try:
        if not alert.load():
            flash("unable to load alert")
            return "", 400
        observable = alert.analysis_tree_manager.get_observable_by_id(observable_uuid)
        if observable:
            observable.add_detection_point(f"user {current_user} marked observable as malicious")
            alert.sync()

        logging.info("AUDIT: user %s marked observable %s in alert %s as suspect", current_user, observable, alert)
    except Exception as e:
        flash("unable to load alert {0}: {1}".format(alert, str(e)))
        traceback.print_exc()
        return "", 400
    finally:
        if alert.lock_uuid:
            release_lock(str(alert.uuid), alert.lock_uuid)

    return url_for("analysis.index", direct=str(alert.uuid)), 200