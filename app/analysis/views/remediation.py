from flask import render_template, request
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.remediation.database import get_current_restore_key
from saq.remediation.target import RemediationTarget, get_remediation_targets_by_alert_uuids
from saq.remediation.types import RemediationAction

@analysis.route('/remediation_targets', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
@require_permission('remediation', 'read')
def remediation_targets():
    # get request body
    body = request.get_json()

    # return rendered target selection table
    if request.method == 'POST':
        targets = get_remediation_targets_by_alert_uuids(body['alert_uuids'])
        return render_template('analysis/remediation_targets.html', targets=targets)

    if request.method == 'PATCH':
        for target in body['targets']:
            if body['action'] == 'stop':
                RemediationTarget(remediator_name=target['name'], observable_type=target['type'], observable_value=target['value']).cancel_current_remediation()
                return 'remediation stopped', 200
            elif body['action'] == 'delete':
                RemediationTarget(remediator_name=target['name'], observable_type=target['type'], observable_value=target['value']).delete_current_remediation()
                return 'remediation deleted', 200

    for target_dict in body["targets"]:
        target = RemediationTarget(remediator_name=target_dict['name'], observable_type=target_dict['type'], observable_value=target_dict['value'])
        if request.method == "DELETE":
            target.queue_remediation(RemediationAction.REMOVE, current_user.id)
        elif request.method == "PUT":
            # XXX the use of get_current_restore_key here is not ideal because it's not guaranteed to be the correct restore key
            # once we get the remediation history display in the GUI working we can remediate using the database ID instead
            target.queue_remediation(RemediationAction.RESTORE, current_user.id, get_current_restore_key(target))
        else:
            raise ValueError(f"Invalid request method: {request.method}")

    return 'remediation queued', 200