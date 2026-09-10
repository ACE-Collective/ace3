import logging
from threading import Event, Thread
from uuid import uuid4

from sqlalchemy import or_, text
from sqlalchemy.sql import func

from saq.database.model import Remediation
from saq.database.pool import get_db, remove_all_sessions
from saq.error.reporting import report_exception
from saq.remediation.interface import RemediationListener
from saq.remediation.types import RemediationAction, RemediationStatus, RemediationWorkItem

def create_remediation_work_item(remediation: Remediation) -> RemediationWorkItem:
    return RemediationWorkItem(
        id=remediation.id,
        action=RemediationAction(remediation.action),
        name=remediation.name,
        type=remediation.type,
        key=remediation.key,
        restore_key=remediation.restore_key)

class RemediationCollector:
    """Responsible for collecting remediation jobs from the database and sending them to the appropriate queues."""
    collector_thread: Thread

    def __init__(self, lock_timeout_seconds: int=300, delay_time_seconds: int=60):
        self.lock_timeout_seconds = lock_timeout_seconds
        self.delay_time_seconds = delay_time_seconds
        self.collector_startup_event = Event()
        self.shutdown_event = Event()

        # maps a remediator name to a RemediationListener instance
        self.listeners: dict[str, RemediationListener] = {}

    def start(self):
        self.collector_thread = Thread(target=self.collection_loop, name="Remediation Collector")
        self.collector_thread.start()

    def start_single_threaded(self):
        # execute the loop once and exit
        self.shutdown_event.set()
        self.collection_loop()

    def wait_for_start(self, timeout: float) -> bool:
        if not self.collector_startup_event.wait(timeout):
            logging.error("remediation collector thread did not start")
            return False

        return True

    def stop(self):
        self.shutdown_event.set()

    def wait(self):
        self.collector_thread.join()

    def register_remediation_listener(self, name: str, listener: RemediationListener):
        """Called to associate a remediation type with a listener.
        Any jobs collected for this type will be sent to this listener."""
        if name in self.listeners:
            raise ValueError(f"remediation listener {name} already registered")

        self.listeners[name] = listener

    def notify_remediation_listeners(self, remediation: RemediationWorkItem):
        """Called to queue a remediation for processing."""
        if remediation.name not in self.listeners:
            raise ValueError(f"remediation name {remediation.name} not registered")

        self.listeners[remediation.name].handle_remediation_request(remediation)

    def collect_work_items(self) -> list[RemediationWorkItem]:
        """Collects the remediation targets to process from the database."""
        lock_uuid = str(uuid4())

        query = get_db().query(Remediation)
        # only get remediations that are ...
        # ...for the work queues we are interested in
        query = query.filter(Remediation.name.in_(self.listeners.keys()))
        # ... not locked or that are locked but have timed out
        query = query.filter(or_(
            Remediation.lock == None, # noqa
            func.NOW() >= func.DATE_ADD(Remediation.lock_time, text(f"INTERVAL {self.lock_timeout_seconds} SECOND"))
        ))
        # ... not completed
        query = query.filter(Remediation.status != RemediationStatus.COMPLETED.value)
        # ... have been delayed and are now ready to be processed
        query = query.filter(or_(
            Remediation.update_time == None, # noqa
            func.NOW() >= func.DATE_ADD(Remediation.update_time, text(f"INTERVAL {self.delay_time_seconds} SECOND"))
        ))
        query = query.order_by(Remediation.insert_date.desc())

        remediation_objects = query.all()
        target_ids = [r.id for r in remediation_objects]

        # attempt to lock found targets
        update = Remediation.__table__.update()
        update = update.values(
            lock = lock_uuid,
            # must come from the database clock: the lock timeout is evaluated server-side against
            # NOW(), and a client-side datetime rounds up into a DATETIME(0) column
            lock_time = func.NOW(),
            status = RemediationStatus.IN_PROGRESS.value,
        )
        update = update.where(Remediation.id.in_(target_ids))
        get_db().execute(update)
        get_db().commit()

        # fetch successfully locked targets
        query = get_db().query(Remediation)
        query = query.filter(Remediation.lock == lock_uuid)
        query = query.order_by(Remediation.insert_date.desc())
        result = query.all()
        return [create_remediation_work_item(r) for r in result]

    def collection_loop(self):
        self.collector_startup_event.set()
        while True:
            try:
                for work_item in self.collect_work_items():
                    self.notify_remediation_listeners(work_item)
            except Exception as e:
                logging.error(f"error collecting remediations from database: {e}")
                report_exception()
            finally:
                try:
                    remove_all_sessions()
                except Exception as e:
                    logging.error(f"error removing database connection: {e}")
                    report_exception()

            if self.shutdown_event.is_set():
                break

            self.shutdown_event.wait(1)