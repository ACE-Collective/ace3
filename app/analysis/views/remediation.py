import bisect
import time
from flask import render_template, request
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.remediation import RemediationTarget, get_remediation_targets

# XXX there is a TODO list item for this -- call should not block like it does
# instead, the remediation should be queued and the call should return immediately
# then the analyst (or whoever) should be notified somehow

@analysis.route('/remediation_targets', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
@require_permission('remediation', 'read')
def remediation_targets():
    # get request body
    body = request.get_json()

    # return rendered target selection table
    if request.method == 'POST':
        unchecked_types = [_.strip() for _ in get_config()['service_remediation']['unchecked_types'].split(',')]
        targets = get_remediation_targets(body['alert_uuids'])
        targets_by_type = {}
        for target in targets:
            if target.type in targets_by_type:
                bisect.insort(targets_by_type[target.type], target)
            else:
                targets_by_type[target.type] = [target]

        return render_template('analysis/remediation_targets.html', targets=targets, unchecked_types=unchecked_types,
                               targets_by_type=targets_by_type,
                               target_types=sorted([*targets_by_type]))

    if request.method == 'PATCH':
        for target in body['targets']:
            if body['action'] == 'stop':
                RemediationTarget(id=target).stop_remediation()
                return 'remediation stopped', 200
            elif body['action'] == 'delete':
                RemediationTarget(id=target).delete_remediation()
                return 'remediation deleted', 200

    # queue targets for removal/restoration
    action = 'remove' if request.method == 'DELETE' else 'restore'
    for target in body['targets']:
        RemediationTarget(id=target).queue(action, current_user.id)

    # wait until all remediations are complete or we run out of time
    complete = False
    quit_time = time.time() + get_config()['service_remediation'].getint('request_wait_time', fallback=10)
    while not complete and time.time() < quit_time:
        complete = True
        for target in body['targets']:
            if RemediationTarget(id=target).processing:
                complete = False
                break
        time.sleep(1)

    # return rendered remediation results table
    targets=[RemediationTarget(id=target) for target in body['targets']]
    sorted_targets = {}
    for t in targets:
        if t.type not in sorted_targets:
            sorted_targets[t.type] = []
        sorted_targets[t.type].append(t)
    return render_template('analysis/remediation_results.html', target_types=sorted_targets)