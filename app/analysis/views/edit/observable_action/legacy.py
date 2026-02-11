import logging
import traceback
import uuid
from flask import request
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import ACTION_COLLECT_FILE, ACTION_FILE_RENDER, ACTION_URL_CRAWL, ANALYSIS_MODE_CORRELATION, DIRECTIVE_COLLECT_FILE, DIRECTIVE_CRAWL
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.error.reporting import report_exception

#
# refactor this to use registered handlers
#

@analysis.route('/observable_action', methods=['POST'])
@require_permission('observable', 'write')
def observable_action():
    alert = get_current_alert()
    observable_uuid = request.form.get('observable_uuid')
    action_id = request.form.get('action_id')

    lock_uuid = str(uuid.uuid4())
    if not acquire_lock(alert.uuid, lock_uuid):
        return "Unable to lock alert.", 500
    try:
        if not alert.load():
            return "Unable to load alert.", 500

        observable = alert.root_analysis.observable_store[observable_uuid]

        logging.info("AUDIT: user %s used action %s for observable %s in alert %s", 
                    current_user, action_id, observable, alert)

        if action_id == 'mark_as_suspect':
            if not observable.has_detection_points():
                alert.sync()
                return "Observable marked as suspect.", 200

        elif action_id == ACTION_COLLECT_FILE:
            try:
                logging.info("user {} added directive {} to {}".format(current_user, DIRECTIVE_COLLECT_FILE, observable))
                observable.add_directive(DIRECTIVE_COLLECT_FILE)
                alert.sync()
                alert.root_analysis.schedule()
                return "File collection requested.", 200
            except Exception:
                logging.error("unable to mark observable {} for file collection".format(observable))
                report_exception()
                return "request failed - check logs", 500

        elif action_id in [ACTION_URL_CRAWL, ACTION_FILE_RENDER]:
            from saq.modules.url import CrawlphishAnalyzer
            #from saq.modules.render import RenderAnalyzer

            # make sure alert is locked before starting new analysis
            if alert.is_locked():
                try:
                    # crawlphish only works for URL observables, so we want to limit these actions to the URL observable action only
                    if action_id == ACTION_URL_CRAWL:
                        observable.add_directive(DIRECTIVE_CRAWL)
                        observable.remove_analysis_exclusion(CrawlphishAnalyzer)
                        logging.info(f"user {current_user} added directive {DIRECTIVE_CRAWL} to {observable}")

                    # both URLs and files can be rendered, so we can do that in either case (ACTION_URL_CRAWL or ACTION_FILE_RENDER)

                    #observable.remove_analysis_exclusion(RenderAnalyzer)
                    logging.info(f"user {current_user} removed analysis exclusion for RenderAnalyzer for {observable}")

                    alert.analysis_mode = ANALYSIS_MODE_CORRELATION
                    alert.sync()

                    add_workload(alert)

                except Exception:
                    logging.error(f"unable to mark observable {observable} for crawl/render")
                    report_exception()
                    return "Error: Crawl/Render Request failed - Check logs", 500

                else:
                    return "URL crawl/render successfully requested.", 200

            else:
                return "Alert wasn't locked for crawl/render, try again later", 500

        return "invalid action_id", 500

    except Exception as e:
        traceback.print_exc()
        return "Unable to load alert: {}".format(str(e)), 500
    finally:
        if lock_uuid:
            release_lock(alert.uuid, lock_uuid)