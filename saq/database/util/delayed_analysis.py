import logging

import pymysql
from saq.constants import G_SAQ_NODE_ID
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.environment import g_int
from saq.error import report_exception


def add_delayed_analysis_request(root, observable, analysis_module, hours, minutes, seconds):
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
                                  analysis_module.config_section_name, 
                                  hours, 
                                  minutes, 
                                  seconds, 
                                  g_int(G_SAQ_NODE_ID), 
                                  root.storage_dir 
                              ))
            db.commit()

            logging.info("added delayed analysis uuid {} observable_uuid {} analysis_module {} delayed for {}:{}:{} node {} storage_dir {}".format(
                         root.uuid, observable.uuid, analysis_module.config_section_name, hours, minutes, seconds, g_int(G_SAQ_NODE_ID), root.storage_dir))

    except pymysql.err.IntegrityError as ie:
        logging.warning(str(ie))
        logging.warning("already waiting for delayed analysis on {} by {} for {}".format(
                         root, analysis_module.config_section_name, observable))
        return True
    except Exception as e:
        logging.error("unable to insert delayed analysis on {} by {} for {}: {}".format(
                         root, analysis_module.config_section_name, observable, e))
        report_exception()
        return False

def clear_delayed_analysis_requests(root):
    """Clears all delayed analysis requests for the given RootAnalysis object."""
    with get_db_connection() as db:
        c = db.cursor()
        execute_with_retry(db, c, "DELETE FROM delayed_analysis WHERE uuid = %s", (root.uuid,), commit=True)