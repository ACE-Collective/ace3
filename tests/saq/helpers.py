import copy
from contextlib import contextmanager
from datetime import datetime, timedelta
import logging
from multiprocessing import Manager, Pipe, Process, RLock
import multiprocessing.util
import os
import subprocess
import sys

import time
from typing import Union
import uuid


from saq.analysis.io_tracking import _disable_io_tracker, _enable_io_tracker
from saq.analysis.root import RootAnalysis, Submission
from saq.configuration import config as config_module
from saq.configuration.config import get_config
from saq.constants import (
    ANALYSIS_MODE_ANALYSIS,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_SIMULATED,
    F_FILE_NAME,
    F_FQDN,
    F_HOSTNAME,
    F_URL,
)
from saq.database.model import Alert, Workload, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, set_dispositions
from saq.engine.analysis_orchestrator import AnalysisOrchestrator
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.engine.worker import Worker
from saq.environment import ACE_MP_CONTEXT, get_base_dir, get_global_runtime_settings
from tests import unittest_session
from saq.util.uuid import get_storage_dir, workload_storage_dir

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

# expected values
EV_TEST_DATE = datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)

EV_ROOT_ANALYSIS_TOOL = 'test_tool'
EV_ROOT_ANALYSIS_TOOL_INSTANCE = 'test_tool_instance'
EV_ROOT_ANALYSIS_ALERT_TYPE = 'test_alert'
EV_ROOT_ANALYSIS_DESCRIPTION = 'This is only a test.'
EV_ROOT_ANALYSIS_EVENT_TIME = EV_TEST_DATE
EV_ROOT_ANALYSIS_NAME = 'test'
EV_ROOT_ANALYSIS_UUID = '14ca0ff2-ff7e-4fa1-a375-160dc072ab02'

IntegrationConfigurationSnapshot = tuple[dict, dict, bool]

def snapshot_integration_configurations() -> IntegrationConfigurationSnapshot:
    """Snapshots the process-global integration configuration registries.

    INTEGRATION_CONFIGURATIONS holds *mutable pydantic instances* handed out by
    get_config(<name>), so a test that writes a field on one of them (rather than replacing the
    entry) changes what every later test in the process sees. A dict() copy restores membership
    but not that field, so the values are deep copied here.
    """
    return (
        dict(config_module.REGISTERED_INTEGRATION_CONFIGURATIONS),
        {name: value.model_copy(deep=True)
         for name, value in config_module.INTEGRATION_CONFIGURATIONS.items()},
        config_module.CONFIG_RESOLVED,
    )

def restore_integration_configurations(snapshot: IntegrationConfigurationSnapshot):
    """Restores the registries captured by snapshot_integration_configurations()."""
    registered, resolved, resolved_flag = snapshot

    config_module.CONFIG_RESOLVED = resolved_flag

    # mutate in place: other modules hold references to these dict objects
    config_module.REGISTERED_INTEGRATION_CONFIGURATIONS.clear()
    config_module.REGISTERED_INTEGRATION_CONFIGURATIONS.update(registered)
    config_module.INTEGRATION_CONFIGURATIONS.clear()
    config_module.INTEGRATION_CONFIGURATIONS.update(resolved)

def create_root_analysis(tool=None, tool_instance=None, alert_type=None, desc=None, event_time=None,
                         action_counts=None, details=None, name=None, remediation=None, state=None,
                         uuid=None, location=None, storage_dir=None, company_name=None, company_id=None,
                         analysis_mode=None, queue=None, instructions=None):
    """Returns a default RootAnalysis object with expected values for testing."""
    return RootAnalysis(tool=tool if tool else EV_ROOT_ANALYSIS_TOOL,
                        tool_instance=tool_instance if tool_instance else EV_ROOT_ANALYSIS_TOOL_INSTANCE,
                        alert_type=alert_type if alert_type else EV_ROOT_ANALYSIS_ALERT_TYPE,
                        desc=desc if desc else EV_ROOT_ANALYSIS_DESCRIPTION,
                        event_time=event_time if event_time else EV_TEST_DATE,
                        action_counters=action_counts if action_counts else None,
                        details=details if details else None, 
                        name=name if name else EV_ROOT_ANALYSIS_NAME,
                        remediation=remediation if remediation else None,
                        state=state if state else None,
                        uuid=uuid if uuid else EV_ROOT_ANALYSIS_UUID,
                        location=location if location else None,
                        storage_dir=storage_dir if storage_dir else os.path.relpath(
                            workload_storage_dir(uuid if uuid else EV_ROOT_ANALYSIS_UUID),
                            start=get_base_dir()),
                        company_name=company_name if company_name else None,
                        company_id=company_id if company_id else None,
                        analysis_mode=analysis_mode if analysis_mode else 'test_groups',
                        queue=queue if queue else None,
                        instructions=instructions if instructions else None)

def validate_tree_integrity(root: RootAnalysis) -> list[str]:
    """Returns the list of structural problems in the analysis tree of root (empty list == healthy)."""
    issues: list[str] = []

    # every analysis on an observable points back at that observable
    for observable in root.all_observables:
        for analysis in observable.all_analysis:
            if analysis.observable is not observable:
                issues.append(f"Analysis {analysis} in observable {observable.uuid} has incorrect observable reference")

    # every observable referenced by an analysis is in the registry
    registry = root.analysis_tree_manager.observable_registry.store
    for analysis in root.all_analysis:
        for observable in analysis.observables:
            if observable.uuid not in registry:
                issues.append(f"Observable {observable.uuid} in analysis {analysis} not found in registry")

    return issues

def track_io(target_function):
    def wrapper(*args, **kwargs):
        try:
            _enable_io_tracker()
            return target_function(*args, **kwargs)
        finally:
            _disable_io_tracker()
    return wrapper

def add_fp_alert():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()

    root.add_observable_by_spec(F_FQDN, 'microsoft.com')
    root.add_observable_by_spec(F_URL, 'https://google.com')
    root.add_observable_by_spec(F_FILE_NAME, 'calc.exe')
    root.add_observable_by_spec(F_HOSTNAME, 'localhost')

    root.save()

    alert = ALERT(root)

    #alert = Alert(storage_dir=root.storage_dir)
    #alert.load()

    alert.disposition = DISPOSITION_FALSE_POSITIVE
    alert.disposition_time = datetime.now()

    alert.sync()

class WaitTimedOutError(Exception):
    pass

def run_python(code: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Runs code in a fresh interpreter from the base dir and fails the test if it fails. Import tests run
    this way because the test process has imported nearly everything before a test starts, which hides an
    import cycle or a heavy import."""
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=timeout)
    assert result.returncode == 0, result.stderr[-4000:]
    return result

def wait_for_condition(condition, timeout=5, delay=0.1):
    """Waits for condition to return True. 
        condition is checked every delay seconds until it return True or timeout seconds have elapsed."""
    time_limit = datetime.now() + timedelta(seconds=timeout)
    while True:
        if condition():
            return True

        if datetime.now() > time_limit:
            raise WaitTimedOutError()

        time.sleep(delay)

def log_count(text):
    """Returns the number of times the given text is seen in the logs."""
    with test_log_sync:
        return len([x for x in test_log_messages if text in x.getMessage()])

def wait_for_log_count(text, count, timeout=5):
    """Waits for text to occur count times in the logs before timeout seconds elapse."""
    def condition(e):
        return text in e.getMessage()

    return memory_log_handler.wait_for_log_entry(condition, timeout, count)

def search_log(text):
    return memory_log_handler.search(lambda log_record: text in log_record.getMessage())

def search_log_regex(regex):
    return memory_log_handler.search(lambda log_record: regex.search(log_record.getMessage()))

def search_log_condition(func):
    return memory_log_handler.search(func)

def start_api_server(remote_host=None, ssl_verification=None, listen_address=None, listen_port=None, ssl_cert=None, ssl_key=None) -> Process:
    """Starts the API server as a separate process."""
    api_server_process = ACE_MP_CONTEXT.Process(target=execute_api_server, args=(listen_address, listen_port, ssl_cert, ssl_key))
    api_server_process.start()

    if remote_host is None:
        remote_host = get_global_runtime_settings().api_prefix
    if ssl_verification is None:
        ssl_verification = get_config().SSL.ca_chain_path

    import ace_api

    result = None
    errors = []
    for x in range(5):
        try:
            result = ace_api.ping(remote_host=remote_host, ssl_verification=ssl_verification)
            break
        except Exception as e:
            errors.append(str(e))
            time.sleep(1)

    if result is None:
        for error in errors:
            logging.error(error)

        raise RuntimeError("unable to start api server")

    return api_server_process

def execute_api_server(listen_address=None, listen_port=None, ssl_cert=None, ssl_key=None):
    # Serve the v2 app at /api/v2, where nginx puts it on a node: `ace_api` builds every URL
    # as https://host/api/v2/...

    import aceapi_v2.application
    import uvicorn
    from fastapi import FastAPI

    root = FastAPI()
    root.mount('/api/v2', aceapi_v2.application.create_app())

    if listen_address is None:
        listen_address = get_config().api.listen_address
    if listen_port is None:
        listen_port = get_config().api.listen_port
    ssl_certfile = get_config().api.ssl_cert if ssl_cert is None else ssl_cert
    ssl_keyfile = get_config().api.ssl_key if ssl_key is None else ssl_key

    logging.info(f"starting api server on {listen_address} port {listen_port}")
    uvicorn.run(
        root,
        host=listen_address,
        port=int(listen_port),
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        log_level="warning",
    )

def stop_api_server(api_server_process: Process):
    """Stops the API server if it's running."""
    if api_server_process is None:
        logging.warning("api_server_process is None")
        return

    if not api_server_process.is_alive:
        logging.warning("api_server_process is not alive")
        return

    import signal
    logging.info("stopping API server on pid %s", api_server_process.pid)
    try:
        os.kill(api_server_process.pid, signal.SIGKILL)

        api_server_process.join()
    except Exception as e:
        logging.info("unable to stop api server: %s", e)

test_log_manager = None
test_log_sync = None
test_log_messages = None
memory_log_handler = None

# validating that certain things happened using logging is kind of janky
# so eventually this class goes away

class MemoryLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        # the pid in which the test_log_messages proxy is safe to use: this process, and a
        # forked child once multiprocessing's after-fork hooks have given it a connection of
        # its own. In between -- inside os.fork(), where os.register_at_fork child handlers run
        # (huggingface_hub closes its httpx client there, and httpcore logs the close) -- the
        # proxy still holds the parent's connection, and a child writing to it takes the
        # parent's reply: both processes then wait forever.
        self.proxy_pid = os.getpid()
        multiprocessing.util.register_after_fork(self, MemoryLogHandler._after_fork)

    def _after_fork(self):
        self.proxy_pid = os.getpid()

    def emit(self, record):
        # a record from inside the fork window cannot be delivered safely; dropping it is the
        # only option, and only fork-handler chatter is ever emitted there
        if os.getpid() != self.proxy_pid:
            return

        try:
            test_log_messages.append(self._picklable(record))
        except Exception as e:
            # next to this slot's unittest log rather than in the repository root
            with open(os.path.join(unittest_session.LOG_DIR, unittest_session.get_log_file_name("logging_issues")), "a") as fp:
                fp.write(f"*** ERROR: unable to append record {record}: {e}\n")

    @staticmethod
    def _picklable(record: logging.LogRecord) -> logging.LogRecord:
        """A copy of record the manager process can unpickle. The traceback in exc_info cannot
        be pickled, so it travels as text in exc_text instead; a test that needs exc_info
        itself uses caplog."""
        if not record.exc_info:
            return record

        record = copy.copy(record)
        if not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        record.exc_info = None
        return record

    def clear(self):
        with test_log_sync:
            del test_log_messages[:]

    def search(self, condition):
        """Searches and returns all log records for which condition(record) was True. Returns the list of LogRecord that matched."""

        result = []
        with test_log_sync:
            for message in test_log_messages:
                if condition(message):
                    result.append(message)

        return result

    def wait_for_log_entry(self, callback, timeout=5, count=1):
        """Waits for callback to return True count times before timeout seconds expire.
           callback takes a single LogRecord object as the parameter and returns a boolean."""
        
        # XXX this is a hack but on slower machines the tests are timing out because the system is slow
        if timeout < 15:
            timeout = 15 

        time_limit = datetime.now() + timedelta(seconds=timeout)

        current_index = 0
        current_count = 0

        while True:
            with test_log_sync:
                while current_index < len(test_log_messages):
                    if callback(test_log_messages[current_index]):
                        current_count += 1

                        if current_count == count:
                            return True

                    current_index += 1

            if datetime.now() >= time_limit:
                raise WaitTimedOutError()

            time.sleep(0.1)

def search_log(text):
    return memory_log_handler.search(lambda log_record: text in log_record.getMessage())

def search_log_regex(regex):
    return memory_log_handler.search(lambda log_record: regex.search(log_record.getMessage()))

def search_log_condition(func):
    return memory_log_handler.search(func)

def initialize_unittest_logging():
    # ACE is multi-process multi-threaded
    # so we use this special logging mechanism to keep a central repository of the log events generated
    # that the original process can access

    global test_log_manager
    global test_log_sync
    global test_log_messages
    global memory_log_handler

    test_log_sync = RLock()
    test_log_manager = Manager()
    #atexit.register(_atexit_callback)
    test_log_messages = test_log_manager.list()

    log_format = logging.Formatter(datefmt='%(asctime)s')

    memory_log_handler = MemoryLogHandler()
    memory_log_handler.setLevel(logging.DEBUG)
    memory_log_handler.setFormatter(log_format)
    logging.getLogger().addHandler(memory_log_handler)

def reset_unittest_logging():
    global test_log_manager
    global test_log_sync
    global test_log_messages
    global memory_log_handler

    memory_log_handler.clear()

def stop_unittest_logging():

    global test_log_manager
    global test_log_sync
    global test_log_messages
    global memory_log_handler

    if memory_log_handler is not None:
        logging.getLogger().removeHandler(memory_log_handler)

    test_log_manager = None
    test_log_sync = None
    test_log_messages = None
    memory_log_handler = None

@contextmanager
def unconfigured_logging():
    """The root logger as a process starts with it: no handlers and level WARNING. The handlers
    list is emptied and refilled in place, because pytest removes the capture handler it added
    from that list at the end of the test phase."""
    root_logger = logging.getLogger()
    handlers, level = root_logger.handlers[:], root_logger.level
    root_logger.handlers.clear()
    root_logger.setLevel(logging.WARNING)
    try:
        yield root_logger
    finally:
        root_logger.handlers[:] = handlers
        root_logger.setLevel(level)

# test comms pipe is used to communicate between test process and child processes
test_comms_p = None
test_comms_pid = None
test_comms_c = None

def open_test_comms():
    global test_comms_p
    global test_comms_pid
    global test_comms_c

    test_comms_p, test_comms_c = Pipe()
    test_comms_pid = os.getpid()
    
def close_test_comms():
    test_comms_p.close()
    test_comms_c.close()

def get_test_comm_pipe():
    # if we are the original process then we use the "parent" pipe
    # otherwise we use the "child" pipe
    if os.getpid() == test_comms_pid:
        return test_comms_p

    return test_comms_c

def send_test_message(message):
    get_test_comm_pipe().send(message)

def recv_test_message():
    return get_test_comm_pipe().recv()

def create_submission(**kwargs) -> Submission:
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=get_storage_dir(root_uuid),
        desc="test",
        analysis_mode=ANALYSIS_MODE_ANALYSIS,
        tool="test_tool",
        tool_instance="test_tool_instance",
        alert_type="test_type"
    )
    root.initialize_storage()
    return Submission(root, **kwargs)

def insert_alert():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.save()

    ALERT(root)

    alert = load_alert(root.uuid)
    assert alert.id is not None
    return alert

def make_simulated(alert: Alert) -> None:
    """Gives the alert the disposition SVS sets on a test-run alert (SIMULATED), through the
    system path, and drops the workload entry that queued, so a test sees only what the code
    under test schedules."""
    set_dispositions([alert.uuid], DISPOSITION_SIMULATED, get_config().global_settings.automation_user_id,
                     system=True)
    db = get_db()
    db.query(Workload).filter(Workload.uuid == alert.uuid).delete()
    db.commit()
    db.expire_all()


def workload_count(alert_uuid: str) -> int:
    """How many workload entries queue the alert for analysis."""
    db = get_db()
    db.expire_all()
    return db.query(Workload).filter(Workload.uuid == alert_uuid).count()


def insert_alert_with_detections(detections: list[dict], disposition: Union[str, None] = None):
    """Creates and syncs an alert carrying the given detections, then sets its disposition.

    Each detection is a dict with "description" and "signature_uuid", and optionally "fqdn": the
    value of the fqdn observable it sits on (the root when absent). Returns the loaded Alert."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    for detection in detections:
        node = root
        if detection.get("fqdn"):
            node = root.add_observable_by_spec(F_FQDN, detection["fqdn"])
        node.add_detection_point(detection["description"], signature_uuid=detection["signature_uuid"])
    root.save()
    ALERT(root)

    alert = load_alert(root.uuid)
    if disposition is not None:
        db = get_db()
        db.execute(Alert.__table__.update().where(Alert.id == alert.id).values(disposition=disposition))
        db.commit()
        db.expire_all()
        alert = load_alert(root.uuid)

    return alert

def wait_for_process(process: Process):
    process.join(10)
    if process.is_alive():
        # kill it before complaining. multiprocessing joins every non-daemon child at
        # interpreter exit with no timeout, so a process left running here turns this
        # failure into a hang that never reports it.
        process.kill()
        process.join(5)
        raise RuntimeError("engine did not stop")

def reset_s3_email_archive_bucket():
    try:
        from saq.storage.s3 import get_s3_client
    except Exception:
        logging.warning("boto3 not available, skipping s3 email archive bucket reset")
        return

    if get_config().s3 is None:
        logging.debug("s3 configuration not available, skipping s3 email archive bucket reset")
        return

    client = get_s3_client()
    bucket = get_config().email_archive.s3_bucket
    kwargs = {"Bucket": bucket}
    while True:
        response = client.list_objects_v2(**kwargs)
        for obj in response.get("Contents", []):
            client.delete_object(Bucket=bucket, Key=obj["Key"])
        if response.get("IsTruncated"):
            kwargs["ContinuationToken"] = response["NextContinuationToken"]
        else:
            break

def create_submission_file_manager(base_dir) -> "SubmissionFileManager":
    """Returns a SubmissionFileManager rooted at base_dir with all four directories created.

    Used by collector tests that need the staging directory (the durable submission queue) but
    do not want a full CollectorService.
    """
    from saq.collectors.submission_file_manager import SubmissionFileManager

    base_dir = str(base_dir)
    file_manager = SubmissionFileManager(
        incoming_dir=os.path.join(base_dir, "incoming"),
        persistence_dir=os.path.join(base_dir, "persistence"),
        staging_dir=os.path.join(base_dir, "staging"),
        staging_tmp_dir=os.path.join(base_dir, "staging.tmp"),
        error_dir=os.path.join(base_dir, "error"))
    file_manager.initialize_directories()
    return file_manager


def create_staged_submission(file_manager, key=None, group_value=None, group_assignments=None) -> str:
    """Builds a submission in the staging scratch directory and publishes it.

    Returns the root uuid.
    """
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        storage_dir=file_manager.get_staging_tmp_path(root_uuid),
        desc="test staged submission",
        analysis_mode=ANALYSIS_MODE_ANALYSIS,
        tool="test_tool",
        tool_instance="test_tool_instance",
        alert_type="test_type")
    root.initialize_storage()

    submission = Submission(root)
    if key is not None:
        submission.key = key
    if group_value is not None:
        submission.group_value = group_value
    if group_assignments is not None:
        submission.group_assignments = group_assignments

    submission.queued_time = time.time()
    file_manager.stage_submission(submission)
    return root_uuid

@contextmanager
def count_queries():
    """Collects every SQL statement executed inside the block, on any engine in this process.

    Use it to pin a view to a query count that does not grow with the number of rows it
    renders: run the view over two different sized data sets and compare the lengths."""
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(Engine, "before_cursor_execute", _record)
    try:
        yield statements
    finally:
        event.remove(Engine, "before_cursor_execute", _record)


def create_test_worker(name: str = "test") -> Worker:
    """A real Worker, built the way a single threaded engine builds it."""
    configuration_manager = ConfigurationManager(EngineConfiguration(single_threaded_mode=True))
    return Worker(name, configuration_manager, create_node_manager(configuration_manager))


def create_test_orchestrator() -> AnalysisOrchestrator:
    """A real AnalysisOrchestrator, built the way a single threaded engine worker builds it."""
    return create_test_worker().analysis_orchestrator


def audit_record(caplog: pytest.LogCaptureFixture, prefix: str) -> logging.LogRecord:
    """The one AUDIT record whose message starts with "AUDIT: <prefix>"."""
    (record,) = [r for r in caplog.records if r.getMessage().startswith(f"AUDIT: {prefix}")]
    return record


def audit_actor_of(record: logging.LogRecord) -> tuple:
    """(actor, actor_user_id, actor_key_id, auth_type) of a saq.logging.log_audit() record."""
    return record.actor, record.actor_user_id, record.actor_key_id, record.auth_type


def audit_actors(caplog: pytest.LogCaptureFixture, prefix: str) -> list[tuple]:
    """audit_actor_of() every AUDIT record whose message starts with "AUDIT: <prefix>", in order."""
    return [audit_actor_of(r) for r in caplog.records if r.getMessage().startswith(f"AUDIT: {prefix}")]
