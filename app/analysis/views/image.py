import logging
from flask import render_template, request
from app.auth.permissions import require_permission
from app.blueprints import analysis

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