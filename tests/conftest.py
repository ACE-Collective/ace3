
import logging
import os
import os.path
import shutil
import socket
import sys
import tempfile
import uuid

from requests import HTTPError

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config, get_config_value, set_config
from saq.constants import ANALYSIS_MODE_ANALYSIS, CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR, CONFIG_GLOBAL, CONFIG_GLOBAL_NODE, G_INSTANCE_TYPE, G_SAQ_NODE, G_SAQ_NODE_ID, G_TEMP_DIR, G_UNIT_TESTING, INSTANCE_TYPE_UNITTEST
from saq.crypto import set_encryption_password
from saq.database import get_db
from saq.database.pool import get_db_connection
from saq.database.util.automation_user import initialize_automation_user
from saq.database.util.user_management import add_user
from saq.email_archive import initialize_email_archive
from saq.engine.tracking import clear_all_tracking
from saq.environment import g, get_base_dir, get_data_dir, initialize_environment, set_g, set_node


import pytest
from saq.integration.integration_loader import get_valid_integration_dirs, load_integration_component_src
from saq.modules.context import AnalysisModuleContext
from saq.monitor import reset_emitter
from saq.permissions.user import add_user_permission
from saq.util.uuid import storage_dir_from_uuid
from tests.saq.helpers import reset_unittest_logging, start_api_server, stop_api_server, initialize_unittest_logging
from tests.saq.test_util import create_test_context

pytest.register_assert_rewrite("tests.saq.requests")

def needs_full_reset(request: pytest.FixtureRequest) -> bool:
    """Returns True if the given test request is an integration or system test, False otherwise."""
    for marker in [ "integration", "system" ]:
        if request.node.get_closest_marker(marker) is not None:
            return True

    return False

@pytest.fixture
def test_context() -> AnalysisModuleContext:
    return create_test_context()


@pytest.fixture(autouse=True, scope="session")
def global_setup(request):
    execute_global_setup()

    yield

    # clean up the temp dir
    shutil.rmtree(g(G_TEMP_DIR))

def execute_global_setup():

    # where is ACE?
    saq_home = os.getcwd()
    if 'SAQ_HOME' in os.environ:
        saq_home = os.environ['SAQ_HOME']

    # XXX get rid of this
    set_g(G_UNIT_TESTING, True)

    data_dir = os.path.join(saq_home, "data_unittest")
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)

    os.mkdir(data_dir)

    temp_dir = tempfile.mkdtemp()

    initialize_environment(
        saq_home=saq_home, 
        data_dir=str(data_dir),
        temp_dir=temp_dir,
        config_paths=[], 
        logging_config_path=os.path.join(get_base_dir(), "etc", "logging_configs", "unittest_logging.yaml"), 
        relative_dir=None)

    # clear the tracking
    clear_all_tracking()

    initialize_automation_user()
    initialize_email_archive()

    # set a fake encryption password
    set_encryption_password("test")

    set_g(G_SAQ_NODE, None)
    set_g(G_SAQ_NODE_ID, None)

    # what node is this?
    node = get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_NODE)
    if node == "AUTO":
        node = socket.getfqdn()

    set_node(node)

    # load the configuration first
    if g(G_INSTANCE_TYPE) != INSTANCE_TYPE_UNITTEST:
        raise Exception('*** CRITICAL ERROR ***: invalid instance_type setting in configuration for unit testing')

    # additional logging required for testing
    #initialize_unittest_logging()

    # XXX what is this for?
    # create a temporary storage directory
    test_dir = os.path.join(get_data_dir(), 'var', 'test')
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

    os.makedirs(test_dir)

    # ???

    #initialize_configuration(config_paths=[os.path.join(get_base_dir(), 'etc', 'unittest_logging.ini')])

    # work dir
    work_dir = os.path.join(get_data_dir(), "work_dir")
    os.mkdir(work_dir)
    get_config()[CONFIG_ENGINE][CONFIG_ENGINE_WORK_DIR] = work_dir

    initialize_unittest_logging()


@pytest.fixture(autouse=True, scope="function")
def global_function_setup(request):

    # clear work directory
    work_dir = get_config_value(CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR)
    assert os.path.exists(work_dir)
    shutil.rmtree(work_dir)
    os.mkdir(work_dir)

    # reset emitter to default state
    reset_emitter()

    # don't reset the database on tests marked as a unit test
    if needs_full_reset(request):
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM workload")
            cursor.execute("DELETE FROM observables")
            cursor.execute("DELETE FROM observable_mapping")
            cursor.execute("DELETE FROM tags")
            cursor.execute("INSERT INTO tags ( `id`, `name` ) VALUES ( 1, 'whitelisted' )")
            cursor.execute("DELETE FROM events")
            cursor.execute("DELETE FROM remediation")
            cursor.execute("DELETE FROM messages")
            cursor.execute("DELETE FROM persistence")
            cursor.execute("DELETE FROM persistence_source")
            cursor.execute("DELETE FROM company WHERE name != 'default'")
            #cursor.execute("DELETE FROM nodes WHERE is_local = 1")
            cursor.execute("DELETE FROM nodes")
            cursor.execute("UPDATE nodes SET is_primary = 0")
            cursor.execute("DELETE FROM locks")
            cursor.execute("DELETE FROM delayed_analysis")
            cursor.execute("DELETE FROM users")
            cursor.execute("DELETE FROM malware")
            cursor.execute("DELETE FROM `config`")
            cursor.execute("DELETE FROM incoming_workload")
            cursor.execute("DELETE FROM incoming_workload_type")
            cursor.execute("DELETE FROM work_distribution")
            cursor.execute("DELETE FROM work_distribution_groups")
            cursor.execute("DELETE FROM event_mapping")
            cursor.execute("DELETE FROM event_prevention_tool")
            cursor.execute("DELETE FROM event_remediation")
            cursor.execute("DELETE FROM event_risk_level")
            cursor.execute("DELETE FROM event_status")
            cursor.execute("DELETE FROM event_type")
            cursor.execute("DELETE FROM event_vector")
            cursor.execute("DELETE FROM events")
            cursor.execute("DELETE FROM campaign")
            cursor.execute("DELETE FROM comments")
            cursor.execute("DELETE FROM auth_group")
            cursor.execute("DELETE FROM auth_group_user")
            cursor.execute("DELETE FROM auth_permission_catalog")
            cursor.execute("DELETE FROM auth_user_permission")
            cursor.execute("DELETE FROM auth_group_permission")

            db.commit()

            user = add_user("unittest", "unittest@localhost", "unittest", "unittest")
            add_user_permission(user.id, "*", "*")
            UNITTEST_USER_ID = user.id

            #from app.models import User
            #user = User()
            #user.username = 'unittest'
            #user.email = 'unittest@localhost'
            #user.password = 'unittest'
            #cursor.execute("""
                #INSERT INTO users ( username, email, password_hash ) VALUES ( %s, %s, %s )""",
                #(user.username, user.email, user.password_hash))

            #db.commit()
            #db.refresh(user)

            # grant all permissions to the unittest user
            #add_user_permission(user.id, "*", "*")

        with get_db_connection("brocess") as db:
            cursor = db.cursor()
            cursor.execute("""DELETE FROM httplog""")
            cursor.execute("""DELETE FROM smtplog""")
            db.commit()
            # TODO instead of using harded values pull the limits from the config
            cursor.execute("""INSERT INTO httplog ( host, numconnections, firstconnectdate ) 
                        VALUES ( 'local', 1000, UNIX_TIMESTAMP(NOW()) ),
                                ( 'xyz', 1000, UNIX_TIMESTAMP(NOW()) ),
                                ( 'test1.local', 70, UNIX_TIMESTAMP(NOW()) ),
                                ( 'test2.local', 69, UNIX_TIMESTAMP(NOW()) )""")
            db.commit()

        with get_db_connection('email_archive') as db:
            c = db.cursor()
            c.execute("DELETE FROM archive")
            c.execute("DELETE FROM archive_index")
            c.execute("DELETE FROM archive_server")
            c.execute("DELETE FROM email_history")
            db.commit()

        execute_global_setup()

    # XXX we're initializing AND THEN we're resetting the database

    # remember the original sys.path
    original_sys_path = sys.path[:]

    # make a deep copy of the current configuration
    config_copy = get_config().copy()

    yield

    reset_unittest_logging()

    # restore the original configuration
    set_config(config_copy)

    # SQLAlchemy session management
    db_session = get_db()
    if db_session is not None:

        #
        # (09/24/2025) there's something weird going on here with SSL enabled
        # we end up with SSL sockets in an invalid state sometimes
        # so I've got these wrapped in try/except for now...
        #

        try:
            db_session.remove()
        except Exception as e:
            logging.error(f"error removing database session: {e}")

        try:
            db_session.close()
        except Exception as e:
            logging.error(f"error closing database session: {e}")

    from sqlalchemy.orm.session import close_all_sessions
    close_all_sessions()

    # restore the original sys.path
    sys.path = original_sys_path

@pytest.fixture
def test_client():
    from aceapi import create_app
    app = create_app(testing=True)
    app_context = app.test_request_context()                      
    app_context.push()                           
    client = app.test_client()

    yield client

@pytest.fixture
def root_analysis(tmpdir) -> RootAnalysis:
    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        tool="tool",
        tool_instance="tool_instance",
        alert_type="alert_type",
        desc="Test Alert",
        storage_dir=storage_dir_from_uuid(root_uuid),
        analysis_mode=ANALYSIS_MODE_ANALYSIS)
    root.initialize_storage()
    return root

@pytest.fixture
def api_server():
    api_server_process = start_api_server()
    yield
    stop_api_server(api_server_process)

@pytest.fixture
def mock_api_call(test_client, monkeypatch):
    import ace_api

    def mock_execute_api_call(command, 
                        method=ace_api.METHOD_GET, 
                        remote_host=None, 
                        ssl_verification=None, 
                        disable_ssl_verification=False,
                        api_key=None,
                        stream=False, 
                        data=None, 
                        files=None, 
                        params=None,
                        proxies=None,
                        timeout=None):

        if api_key is None:
            api_key = ace_api.default_api_key
            if api_key is None:
                api_key = os.environ.get("ICE_API_KEY", None)

        if method == ace_api.METHOD_GET:
            func = test_client.get
        elif method == ace_api.METHOD_PUT:
            func = test_client.put
        else:
            func = test_client.post

        kwargs = { }
        if params is not None:
            kwargs['query_string'] = params
        #if ssl_verification is not None:
            #kwargs['verify'] = ssl_verification
        #else:
            #kwargs['verify'] = False
        if data is not None:
            kwargs['data'] = data
        if files is not None:
            for (post_field, (file_name, fp)) in files:
                # is this a multi-value post field?
                if post_field in kwargs["data"]:
                    # turn this into a list if we haven't done so already
                    if not isinstance(kwargs["data"][post_field], list):
                        kwargs["data"][post_field] = [ kwargs["data"][post_field] ]
                    
                    # then append this to the list
                    kwargs["data"][post_field].append((fp, file_name, "application/octet-stream"))
                else:
                    # otherwise it's a single value
                    kwargs["data"][post_field] = (fp, file_name, "application/octet-stream")
            #kwargs['files'] = files
        #if proxies is not None:
            #kwargs['proxies'] = proxies
        if timeout is not None:
            kwargs['timeout'] = timeout
        if api_key is not None:
            kwargs['headers'] = { "x-ice-auth": api_key }

        response = func(command, **kwargs)

        if str(response.status_code)[0] != "2":
            raise HTTPError()

        class CustomResponse:
            def __init__(self, response):
                self.response = response

            def json(self):
                return self.response.json

            def iter_content(self, *args, **kwargs):
                yield self.response.data

            @property
            def status_code(self):
                return self.response.status_code

        #response.raise_for_status()
        return CustomResponse(response)

    monkeypatch.setattr(ace_api, "_execute_api_call", mock_execute_api_call)

#
# for integrations we need to update the PYTHONPATH
# but it needs to be done dynamically based on available integrations
# this hook runs before the tests are collected and updates the PYTHONPATH
# for all available (enabled) integrations
#
# NOTE the initialization routines also do this but they execute after tests are collected
#

def pytest_sessionstart(session):
    for dir_path in get_valid_integration_dirs():
        load_integration_component_src(dir_path)

