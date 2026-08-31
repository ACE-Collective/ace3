import logging

import pymysql
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.environment import get_global_runtime_settings
from saq.error import report_exception


def add_delayed_analysis_request(root, observable, analysis_module, hours, minutes, seconds) -> bool:
    """Records a request to analyze the given observable with the given analysis module later.

    Returns True if the request was recorded (and something will eventually resume
    the analysis) and False if it was not."""
    try:
        with get_db_connection() as db:
            c = db.cursor()
            execute_with_retry(db, c, """
                               INSERT INTO delayed_analysis ( 
                                    uuid, 
                                    observable_uuid, 
                                    analysis_module, 
                                    delayed_until, 
                                    node_id, 
                                    storage_dir, 
                                    insert_date 
                               ) VALUES ( 
                                    %s, 
                                    %s, 
                                    %s, 
                                    DATE_ADD(DATE_ADD(DATE_ADD(NOW(), INTERVAL %s HOUR), INTERVAL %s MINUTE), INTERVAL %s SECOND),
                                    %s, 
                                    %s, 
                                    NOW() )""", 
                              ( 
                                  root.uuid, 
                                  observable.uuid, 
                                  analysis_module.name, 
                                  hours, 
                                  minutes, 
                                  seconds, 
                                  get_global_runtime_settings().saq_node_id,
                                  root.storage_dir 
                              ))
            db.commit()

            logging.info("added delayed analysis uuid {} observable_uuid {} analysis_module {} delayed for {}:{}:{} node {} storage_dir {}".format(
                         root.uuid, observable.uuid, analysis_module.name, hours, minutes, seconds, get_global_runtime_settings().saq_node_id, root.storage_dir))

            return True

    except pymysql.err.IntegrityError as ie:
        # a row for this target already exists, so the analysis really is delayed
        # NOTE unreachable with the current schema: delayed_analysis has no unique
        # constraint on (uuid, observable_uuid, analysis_module) -- see docs/ENGINE.md 19.4
        logging.warning(str(ie))
        logging.warning("already waiting for delayed analysis on {} by {} for {}".format(
                         root, analysis_module.name, observable))
        return True
    except Exception as e:
        logging.error("unable to insert delayed analysis on {} by {} for {}: {}".format(
                         root, analysis_module.name, observable, e))
        report_exception()
        return False

def clear_delayed_analysis_requests(root):
    """Clears all delayed analysis requests for the given RootAnalysis object."""
    with get_db_connection() as db:
        c = db.cursor()
        execute_with_retry(db, c, "DELETE FROM delayed_analysis WHERE uuid = %s", (root.uuid,), commit=True)