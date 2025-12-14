from datetime import datetime, timedelta
import logging
from multiprocessing import Manager, Pipe, Process, RLock
import os
import secrets

import time
from typing import List, Union
import uuid


from saq.analysis.io_tracking import _disable_io_tracker, _enable_io_tracker
from saq.analysis.root import RootAnalysis, Submission
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, DISPOSITION_FALSE_POSITIVE, F_FILE, F_FILE_NAME, F_FQDN, F_HOSTNAME, F_URL
from saq.database.model import load_alert
from saq.database.util.alert import ALERT
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.modules.email import EmailAnalysis
from saq.util.uuid import get_storage_dir, workload_storage_dir

# expected values
EV_TEST_DATE = datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)

EV_ROOT_ANALYSIS_TOOL = 'test_tool'
EV_ROOT_ANALYSIS_TOOL_INSTANCE = 'test_tool_instance'
EV_ROOT_ANALYSIS_ALERT_TYPE = 'test_alert'
EV_ROOT_ANALYSIS_DESCRIPTION = 'This is only a test.'
EV_ROOT_ANALYSIS_EVENT_TIME = EV_TEST_DATE
EV_ROOT_ANALYSIS_NAME = 'test'
EV_ROOT_ANALYSIS_UUID = '14ca0ff2-ff7e-4fa1-a375-160dc072ab02'

class MockObservable:
    def __init__(self, type: str, observable_value: str, faqueue_hits: Union[int, None]):
        self.type = type
        self.value = observable_value
        self.all_analysis: List['MockAnalysis'] = []
        self.tags = []
        self.faqueue_hits = faqueue_hits

    def get_analysis(self, analysis_class) -> Union['MockAnalysis', None]:
        return next((a for a in self.all_analysis if isinstance(a, analysis_class)), None)

    def has_tag(self, tag_value):
        return True


class MockFileObservable(MockObservable):
    def __init__(self, type: str, observable_value: str, faqueue_hits: Union[int, None]):
        super().__init__(type, observable_value, faqueue_hits)
        self.path = observable_value
        self.md5_hash = secrets.token_hex(nbytes=16)
        self.sha1_hash = secrets.token_hex(nbytes=160)
        self.sha256_hash = secrets.token_hex(nbytes=256)
        self.size = 100
        self.mime_type = 'text/plain'


class MockAnalysis:
    pass

class MockEmailAnalysis(MockAnalysis, EmailAnalysis):
    @property
    def observables(self):
        return []

    @property
    def mail_from_address(self):
        return 'from@bad.com'

    @property
    def x_auth_id(self):
        return 'xauthid@bad.com'

    @property
    def x_original_sender(self):
        return 'xoriginalsender@bad.com'

    @property
    def x_sender(self):
        return 'xsender@bad.com'

    @property
    def x_sender_id(self):
        return 'xsenderid@bad.com'

    @property
    def mail_to_addresses(self):
        return ['to@company.com']

    @property
    def cc(self):
        return ['cc@company.com']

    @property
    def reply_to_address(self):
        return 'replyto@bad.com'

    @property
    def return_path(self):
        return 'returnpath@bad.com'

    @property
    def subject(self):
        return 'Subject'

    @property
    def originating_ip(self):
        return '192.168.1.1'

    @property
    def x_sender_ip(self):
        return '192.168.1.2'

    @property
    def user_agent(self):
        return 'User Agent'

    @property
    def x_mailer(self):
        return 'X Mailer'

    @property
    def message_id(self):
        return '<email@bad.com>'

    @property
    def attachments(self):
        return [MockFileObservable(F_FILE, 'attachment.jpg', None)]


class MockEvent:
    def __init__(self):
        self.uuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

        email_file_observable = MockFileObservable(F_FILE, 'email.rfc822', None)

        email_analysis = MockEmailAnalysis()
        email_file_observable.all_analysis.append(email_analysis)

        self.all_email_file_observables = [email_file_observable]
        self.all_file_observables = [MockFileObservable(F_FILE, 'test.exe', None)]
        self.all_sandbox_reports = [
            {
                'contacted_hosts': [
                    {
                        'ip': '192.168.1.99',
                        'port': '1332',
                        'protocol': 'TCP',
                        'location': 'US',
                        'associated_domains': []
                    },
                    {
                        'ip': '8.8.8.8',
                        'port': '53',
                        'protocol': 'UDP',
                        'location': 'US',
                        'associated_domains': []
                    },
                ],
                'created_services': [],
                'dns_requests': [
                    {
                        'request': 'test3.com',
                        'type': 'A',
                        'answer': '23.215.102.10',
                        'answer_type': ''
                    },
                    {
                        'request': 'ctldl.windowsupdate.com',
                        'type': 'A',
                        'answer': '23.37.124.8',
                        'answer_type': ''
                    },
                    {
                        'request': 'google.com',
                        'type': 'A',
                        'answer': '172.217.6.78',
                        'answer_type': ''
                    }
                ],
                'dropped_files': [
                    {
                        'filename': 'MSForms.exd',
                        'path': 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\VBE\\MSForms.exd',
                        'size': '147284',
                        'type': 'unknown',
                        'md5': '50db97ae80d573d9145a735e39717f84',
                        'sha1': '75438b1010eb5fd38949e530eea2585c87bd1cf9',
                        'sha256': 'bf08f9d40ace59aa596733f2371e0eaf74fa424de5ddbf9011aeb6d84b612ab5',
                        'sha512': '',
                        'ssdeep': ''
                    },
                    {
                        'filename': 'MSForms.exd',
                        'path': '%TEMP%\\VBE\\MSForms.exd',
                        'size': '147284',
                        'type': 'data',
                        'md5': 'e9240cda4d5e1fc3bafbf9a02904cb98',
                        'sha1': '617f88173d3d2e848c38b55906cf03c3989d76d0',
                        'sha256': 'f99a9f6e38a76415f0d95f894ebff36ab249c145e36427ee874a5d73d47e3d64',
                        'sha512': 'f72b84997cffa6a4113e3b2e11f84e925bb005a99cf77674409e0e7715f5f1b29b10b12b5f7875fa0a567103d6e14f5e0e0e3c5611311388e77d8416e9a0adb7',
                        'ssdeep': ''
                    }
                ],
                'filename': 'sample.xls',
                'http_requests': [
                    {
                        'host': 'domain2.com',
                        'port': '80',
                        'uri': '/index.php',
                        'url': 'http://domain2.com/index.php',
                        'method': 'GET',
                        'user_agent': 'User Agent'
                    },
                    {
                        'host': 'google.com',
                        'port': '80',
                        'uri': '/about',
                        'url': 'http://google.com/about',
                        'method': 'GET',
                        'user_agent': 'User Agent'
                    }
                ],
                'malware_family': '',
                'md5': 'c6f4b263a35cd192a77ecfaf25f44f0a',
                'memory_strings': [],
                'memory_urls': [],
                'mutexes': [
                    'asdf',
                    'abcd',
                    '1234',
                ],
                'process_tree_urls': [],
                'process_trees': [],
                'process_trees_decoded': [],
                'processes': [
                    {
                        'command': 'test.exe',
                        'decoded_command': 'test.exe',
                        'pid': '1',
                        'parent_pid': '0',
                        'urls': [
                            'http://domain3.com',
                            'http://test2.com/index',
                        ]
                    }
                ],
                'registry_keys': [
                    'HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\12.0\\Excel'
                ],
                'resolved_apis': [],
                'sandbox_urls': [],
                'sha1': 'b0ca80e9b0538d72660234556e1c7fa0469b803a',
                'sha256': '7b8cd5e6a4123d39378cf7fe2a1e262ecabcb815285243603025f76b0fc3d38f',
                'sha512': 'a3704171980cc64333c65c1bf03be0dc6e261e6957baafa012340cff7204c97a6ce88fb43814c07ae74d7b447edb18a1bc16d08f8d5f9c4ddab9175ac5acdcab',
                'ssdeep': '',
                'started_services': [],
                'strings_urls': [],
                'suricata_alerts': []
            }
        ]
        self.all_sandbox_samples = []
        self.all_urls = ['http://www.domain.com']
        self.all_observables_sorted = [
            MockObservable('fqdn', 'domain.com', 1000),
            MockObservable('fqdn', 'fastapi.tiangolo.com', 0),
            MockObservable('ipv4', '8.8.8.8', 1000),
            MockObservable('md5', 'c6f4b263a35cd192a77ecfaf25f44f0a', None),
            MockObservable('fqdn', 'ctldl.windowsupdate.com', 1000),
            MockObservable('fqdn', 'crl.microsoft.com', 1000),
            MockObservable('mutex', '1234', 1000),
            MockObservable('url', 'http://test2.com/index', 1000),
        ]
        self.all_fqdns = [
            'domain.com',
            'domain3.com',
            'fastapi.tiangolo.com',
            'google.com',
        ]

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
    api_server_process = Process(target=execute_api_server, args=(listen_address, listen_port, ssl_cert, ssl_key))
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

    # https://gist.github.com/rduplain/1705072
    # this is a bit weird because I want the urls to be the same as they
    # are configured for apache, where they are all starting with /api
    
    import aceapi

    app = aceapi.create_app(testing=True)
    from werkzeug.serving import run_simple
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    from flask import Flask
    app.config['DEBUG'] = True
    app.config['APPLICATION_ROOT'] = '/api'
    application = DispatcherMiddleware(Flask('dummy_app'), {
        app.config['APPLICATION_ROOT']: app,
    })

    if listen_address is None:
        listen_address = get_config().api.listen_address
    if listen_port is None:
        listen_port = get_config().api.listen_port
    ssl_context = (
        get_config().api.ssl_cert if ssl_cert is None else ssl_cert,
        get_config().api.ssl_key if ssl_key is None else ssl_key )

    # XXX really?
    #initialize_database()

    logging.info(f"starting api server on {listen_address} port {listen_port}")
    run_simple(listen_address, listen_port, application, ssl_context=ssl_context, use_reloader=False)

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
    def acquire(self):
        pass
        #if test_log_sync: # TODO fix me
            #if not test_log_sync.acquire(block=True, timeout=0.1):
                #sys.stderr.write("failed to acquire log sync\n")

    def release(self):
        pass

        #if test_log_sync: # TODO fix me
            #try:
                #test_log_sync.release()
            #except Exception as e:
                #sys.stderr.write(f"failed to release log sync: {e}\n")

    def createLock(self):
        pass

    def emit(self, record):
        try:
            test_log_messages.append(record)
        except Exception as e:
            with open("logging_issues.log", "a") as fp:
                fp.write(f"*** ERROR: unable to append record {record}: {e}\n")

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

def wait_for_process(process: Process):
    process.join(10)
    if process.is_alive():
        raise RuntimeError("engine did not stop")