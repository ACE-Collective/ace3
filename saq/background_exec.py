import json
import logging
import time
import threading

import redis

from saq.configuration import get_config, get_config_value, get_config_value_as_int
from saq.constants import CONFIG_REDIS, CONFIG_REDIS_HOST, CONFIG_REDIS_PASSWORD, CONFIG_REDIS_PORT, CONFIG_REDIS_USERNAME, REDIS_DB_BG_TASKS
from saq.database import get_db
from saq.error import report_exception
from saq.service import ACEServiceInterface

# XXX terrible hack, replace this with a proper system

def get_redis_connection():
    """Returns the Redis object to use to store/retrieve signature info."""
    return redis.Redis(
            host=get_config_value(CONFIG_REDIS, CONFIG_REDIS_HOST),
            port=get_config_value_as_int(CONFIG_REDIS, CONFIG_REDIS_PORT),
            username=get_config_value(CONFIG_REDIS, CONFIG_REDIS_USERNAME),
            password=get_config_value(CONFIG_REDIS, CONFIG_REDIS_PASSWORD),
            db=REDIS_DB_BG_TASKS,
            decode_responses=True,
            encoding='utf-8',
            health_check_interval=30)

TASK_KEY = "tasks"
BG_TASK_CLOSE_EVENT = "close_event"
BG_TASK_RSYNC_ALERT = "rsync_alert"

def add_background_task(name: str, *args):
    rc = get_redis_connection()
    rc.rpush(TASK_KEY, json.dumps({ 'name': name, 'args': args }))

class BackgroundExecutor(ACEServiceInterface):
    def __init__(self):
        self.service_config = get_config()['service_background_executor']
        self.service_started = False
        self.service_stopping = False
        self.shutdown_event = threading.Event()
        self.service_started_event = threading.Event()

    def start(self):
        self.service_started = True
        self.execute_service()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.service_started
    
    def start_single_threaded(self):
        self.start()
    
    def stop(self): 
        self.service_stopping = True
    
    def wait(self):
        pass

    def execute_service(self):
        self.initialize_message_queue()
        while not self.service_stopping:
            try:
                self.execute_background_tasks()
            except Exception as e:
                logging.error(f"uncaught exception: {e}")
                report_exception()
                time.sleep(1)

    def initialize_message_queue(self):
        logging.debug("initializing message queue")
        connection = get_redis_connection()
        connection.rpush(TASK_KEY, "")
        connection.lpop(TASK_KEY)

    def execute_background_tasks(self):
        logging.debug("getting next task")
        task = self.get_next_task()
        if not task:
            return

        logging.info(f"got task {task}")
        key_name, task = task
        self.execute_task(json.loads(task))

    def get_next_task(self):
        redis_connection = get_redis_connection()
        return redis_connection.blpop(TASK_KEY, timeout=1)

    def execute_task(self, task: dict):
        t = threading.Thread(target=self.execute_threaded_task, args=(task,), name=str(task), daemon=True)
        t.start()

    def execute_threaded_task(self, task: dict):
        try:
            self.execute_threaded_task_wrapper(task)
        except Exception as e:
            logging.error(f"uncaught exception: {e}")
            report_exception()
        finally:
            get_db().remove()

    def execute_threaded_task_wrapper(self, task: dict):
        logging.info(f"started task {task}")
        if task['name'] == BG_TASK_CLOSE_EVENT:
            self.execute_close_event(task)
        elif task['name'] == BG_TASK_RSYNC_ALERT:
            self.execute_rsync_alert(task)
        else:
            logging.error(f"unknown task name {task['name']}")

    def execute_close_event(self, task: dict):
        event_id = task['args'][0]
        logging.info(f"got background task to close event {event_id}")
        from app.events.helpers import event_closing_tasks

        try:
            event_closing_tasks(event_id)
        except Exception as e:
            logging.error(f"unable to close event {event_id}: {e}")
            report_exception()

    def execute_rsync_alert(self, task: dict):
        from saq.gui import GUIAlert
        from saq.file_upload import rsync

        alert_uuid, remote_host, remote_path, lock_uuid = task['args']
        logging.info(f"got background task to copy alert {alert_uuid} to {remote_host} path {remote_path} lock {lock_uuid}")
        try:
            alert: GUIAlert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
            rsync(alert=alert, remote_host=remote_host, remote_path=remote_path, lock_uuid=lock_uuid)
        except Exception as e:
            logging.error(f"unable to copy alert {alert_uuid}: {e}")
            report_exception()
