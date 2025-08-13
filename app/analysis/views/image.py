import logging
import os
from flask import make_response, render_template, request
from flask_login import login_required
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert

@analysis.route('/image', methods=['GET'])
@require_permission('alert', 'read')
def image():
    alert_uuid = request.values.get("alert_uuid")
    observable_uuid = request.values.get("observable_uuid")

    if not alert_uuid:
        logging.info("attempted to display image but alert_uuid is missing")
        return "alert_uuid is missing", 400

    if not observable_uuid:
        logging.info("attempted to display image but observable_uuid is missing")
        return "observable_uuid is missing", 400

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()

    if not alert:
        logging.info(f"attempted to display image but alert with uuid {alert_uuid} does not exist")
        return "unknown alert", 404

    alert.root_analysis.load()
    _file = alert.root_analysis.get_observable(observable_uuid)

    if not _file:
        logging.info(f"attempted to display file observable with uuid {observable_uuid} as image but file observable does not exist")
        return "unknown file", 404

    if not os.path.exists(_file.path):
        logging.info(f"attempted to display {_file.path} as image but file does not exist")
        return "unknown file", 404

    with open(_file.path, 'rb') as fp:
        result = fp.read()

    response = make_response(result)
    response.headers['Content-Type'] = _file.mime_type
    return response

@analysis.route('/image_full', methods=['GET'])
@require_permission('alert', 'read')
def image_full():
    alert_uuid = request.values.get("alert_uuid")
    observable_uuid = request.values.get("observable_uuid")

    if not alert_uuid:
        logging.info("attempted to display image_full but alert_uuid is missing")
        return "alert_uuid is missing", 400

    if not observable_uuid:
        logging.info("attempted to display image_full but observable_uuid is missing")
        return "observable_uuid is missing", 400

    return render_template(
        'analysis/image_full.html',
        alert = alert_uuid,
        observable = observable_uuid,
    )