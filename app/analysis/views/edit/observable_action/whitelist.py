import logging
from flask import request
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.util.tag_mapping import add_observable_tag_mapping, remove_observable_tag_mapping

@analysis.route('/observable_action_whitelist', methods=['POST'])
@require_permission('whitelist', 'write')
def observable_action_whitelist():
    
    alert = get_current_alert()
    if alert is None:
        return "operation failed: unable to find alert", 200

    try:
        alert.root_analysis.load()
    except Exception as e:
        return f"operation failed: unable to load alert {alert}: {e}", 200

    observable = alert.root_analysis.get_observable(request.form.get('id'))
    if not observable:
        return "operation failed: unable to find observable in alert", 200

    try:
        if add_observable_tag_mapping(observable, 'whitelisted'):
            logging.info("AUDIT: user %s whitelisted observable %s", current_user, observable)
            return "whitelisting added", 200
        else:
            return "operation failed", 200

    except Exception as e:
        return f"operation failed: {e}", 200

@analysis.route('/observable_action_un_whitelist', methods=['POST'])
@require_permission('whitelist', 'write')
def observable_action_un_whitelist():
    alert = get_current_alert()
    if alert is None:
        return "operation failed: unable to find alert", 200

    try:
        alert.root_analysis.load()
    except Exception as e:
        return f"operation failed: unable to load alert {alert}: {e}", 200

    observable = alert.root_analysis.get_observable(request.form.get('id'))
    if not observable:
        return "operation failed: unable to find observable in alert", 200

    try:
        if remove_observable_tag_mapping(observable, 'whitelisted'):
            logging.info("AUDIT: user %s removed whitelisting for observable %s", current_user, observable)
            return "removed whitelisting", 200
        else:
            return "operation failed", 200

    except Exception as e:
        return f"operation failed: {e}", 200