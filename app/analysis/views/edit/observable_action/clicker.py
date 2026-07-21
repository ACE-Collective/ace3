import logging
import traceback
import uuid as uuid_module

from flask import jsonify, request
from flask_login import current_user

from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.clicker_detection.config import build_splunk_clicker_search_urls, load_clicker_config
from saq.clicker_detection.timeline import REGISTERED_CLICKER_PROVIDERS
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_CLICKER_DETECTION, F_FQDN, F_URL
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload, request_analyst_analysis
from saq.error.reporting import report_exception

# saq config instance/name of the Splunk clicker module (analysis_module_clicker_detection_splunk).
CLICKER_SPLUNK_MODULE_NAME = "clicker_detection_splunk"

CLICKER_OBSERVABLE_TYPES = (F_URL, F_FQDN)


@analysis.route('/observable_action_check_for_clickers', methods=['POST'])
@require_permission('observable', 'write')
def observable_action_check_for_clickers():
    """Tag a url/fqdn observable with the clicker_detection directive and requeue the
    alert so every configured clicker module runs against it."""
    alert = get_current_alert()
    if alert is None:
        return jsonify({"status": "error", "message": "alert not found"}), 404

    observable_uuid = request.form.get("observable_uuid")
    if not observable_uuid:
        return jsonify({"status": "error", "message": "missing observable_uuid"}), 400

    lock_uuid = str(uuid_module.uuid4())
    if not acquire_lock(alert.uuid, lock_uuid):
        return jsonify({"status": "error", "message": "unable to lock alert"}), 500

    try:
        if not alert.load():
            return jsonify({"status": "error", "message": "unable to load alert"}), 500

        observable = alert.root_analysis.get_observable(observable_uuid)
        if observable is None:
            return jsonify({"status": "error", "message": "observable not found"}), 404

        if observable.type not in CLICKER_OBSERVABLE_TYPES:
            return jsonify({
                "status": "error",
                "message": f"clicker detection only supports url/fqdn observables (got {observable.type})",
            }), 400

        logging.info(
            "AUDIT: user %s requested clicker detection for observable %s in alert %s",
            current_user, observable, alert,
        )

        observable.add_directive(DIRECTIVE_CLICKER_DETECTION)

        # An analyst re-running this action wants a fresh check. The engine skips a module whose
        # completed analysis already exists (saq/modules/base_module.py accepts()), so drop any
        # prior clicker-provider analyses to force a clean re-run that picks up new clicks.
        # delete_analysis also prunes the state the old analysis owned (its in-tree detection
        # points, generated observables, and detail files); the following sync() reconciles the
        # detection_points table to match, so stale hits do not linger.
        for existing in list(observable.all_analysis):
            if type(existing) in REGISTERED_CLICKER_PROVIDERS:
                observable.delete_analysis(existing)

        # NOTE this sets the mode on root_analysis (what sync()/add_workload read), not on the Alert
        # ORM column — otherwise an already-dispositioned alert re-queues in 'dispositioned' mode,
        # whose module group is empty, and no clicker module ever runs.
        request_analyst_analysis(alert.root_analysis)
        alert.sync()
        add_workload(alert.root_analysis)

        return jsonify({"status": "ok", "message": "Clicker detection requested."}), 200

    except Exception as e:
        logging.error("clicker detection request failed for alert %s: %s", alert.uuid, e)
        report_exception()
        return jsonify({"status": "error", "message": f"clicker detection request failed: {e}"}), 500

    finally:
        release_lock(alert.uuid, lock_uuid)


@analysis.route('/observable_action_open_clicker_search_splunk', methods=['POST'])
@require_permission('observable', 'read')
def observable_action_open_clicker_search_splunk():
    """Return a Splunk web URL for the clicker search that applies to this observable so
    the analyst can investigate the logs directly (no detection run required)."""
    alert = get_current_alert()
    if alert is None:
        return jsonify({"status": "error", "message": "alert not found"}), 404

    observable_uuid = request.form.get("observable_uuid")
    if not observable_uuid:
        return jsonify({"status": "error", "message": "missing observable_uuid"}), 400

    try:
        if not alert.load():
            return jsonify({"status": "error", "message": "unable to load alert"}), 500

        observable = alert.root_analysis.get_observable(observable_uuid)
        if observable is None:
            return jsonify({"status": "error", "message": "observable not found"}), 404

        try:
            module_config = get_analysis_module_config(CLICKER_SPLUNK_MODULE_NAME)
        except Exception:
            return jsonify({"status": "error", "message": "Splunk clicker module is not configured"}), 200

        config = load_clicker_config(module_config.config_path)
        urls = build_splunk_clicker_search_urls(config, observable, api_name=module_config.api_name)
        if not urls:
            return jsonify({
                "status": "error",
                "message": f"No Splunk clicker search is configured for {observable.type} observables.",
            }), 200

        logging.info(
            "AUDIT: user %s opened %d Splunk clicker search(es) for observable %s in alert %s",
            current_user, len(urls), observable, alert,
        )
        return jsonify({"status": "ok", "urls": urls}), 200

    except Exception as e:
        logging.error("failed to build Splunk clicker search for alert %s: %s", alert.uuid, e)
        report_exception()
        return jsonify({"status": "error", "message": f"failed to build Splunk clicker search: {e}"}), 500
