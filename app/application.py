import base64
import json
import logging
import os
from subprocess import PIPE, Popen
from typing import Optional
from flask import Flask
import urllib

from app.blueprints import register_blueprints

from app.integration import register_integration_blueprints
from saq.configuration.config import get_config
from flask_config import get_flask_config
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_executor import Executor # XXX what is this for?
from sqlalchemy import event

from saq.database.pool import set_db
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util.ui import get_tag_css_class, get_tag_level, human_readable_size

# TODO: find something else to use besides this LoginManager
login_manager = LoginManager()
# turning this off for now while I figure out how this works with load balancers
login_manager.session_protection = None
login_manager.login_view = 'auth.login'

#
# 01/25/2022 -- JWD - cannot get hexdump to return anything but None as a jinja filter
# so falling back to some external command execution
#

def hexdump_wrapper(data):
    p = Popen(['hexdump', '-C'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write(data)
    _stdout, _stderr = p.communicate()
    return _stdout.decode(errors='ignore')

# utility functions to encoding/decoding base64 to/from strings
def s64decode(s):
    return base64.b64decode(s + '===').decode('utf8', errors='replace')

def s64encode(s):
    return base64.b64encode(s.encode('utf8', errors='replace')).decode('ascii')

def b64escape(s):
    return base64.b64encode(urllib.parse.quote(s.encode('utf8', errors='replace')).encode('ascii')).decode('ascii')

def b64decode_wrapper(s):
    # sometimes base64 encoded data that tools send do not have the correct padding
    # this deals with that without breaking anything
    try:
        return base64.b64decode(f'{s}===')
    except:
        logging.error(f"Unable to b64decode: {s}")
        return b''

def btoa(b):
    return b.decode('ascii')

def dict_from_json_string(s):
    try:
        return json.loads(s)
    except Exception as e:
        logging.error(f"unable to convert {s} to JSON: {e}")
        return {}

def pprint_json_dict(d):
    return json.dumps(d, indent=4, sort_keys=True)

class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        # add SSL (if configured)
        options.update(get_flask_config(get_config().global_settings.instance_type).SQLALCHEMY_DATABASE_OPTIONS)
        SQLAlchemy.apply_driver_hacks(self, app, info, options)

def initialize_presenters():
    """Ensures that the appropriate presenters are registered for the current engine configuration."""
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.enums import EngineType

    configuration_manager = ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True))
    configuration_manager.load_modules()

    for analysis_module in configuration_manager.analysis_modules:
        # there isn't anythign to do here yet, but will soon
        pass

def create_app(testing: Optional[bool]=False):

    flask_app = Flask(__name__)
    flask_app.config.from_object(get_flask_config(get_config().global_settings.instance_type))

    # This ensures that any exceptions raised by background Flask-Executor tasks get raised
    flask_app.config['EXECUTOR_PROPAGATE_EXCEPTIONS'] = True
    
    get_flask_config(get_config().global_settings.instance_type).init_app(flask_app)

    login_manager.init_app(flask_app)

    db = CustomSQLAlchemy(engine_options=get_flask_config(get_global_runtime_settings().instance_type).SQLALCHEMY_DATABASE_OPTIONS)
    if not testing:
        # XXX hack: tests will create test contexts but the database pool is global
        # we don't want to change it because things like collectors *also* manage the connections
        set_db(db.session)

    db.init_app(flask_app)

    with flask_app.app_context():
        @event.listens_for(db.engine, 'checkin')
        def checkin(dbapi_connection, connection_record):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

        @event.listens_for(db.engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

    # XXX what is this for?
    executor = Executor()
    executor.init_app(flask_app)

    register_blueprints(flask_app)
    register_integration_blueprints(flask_app)

    @flask_app.context_processor
    def inject():
        return { "ACE_VERSION": os.environ.get("ACE_VERSION", "") }

    flask_app.jinja_env.filters['btoa'] = btoa
    flask_app.jinja_env.filters['b64decode'] = b64decode_wrapper
    flask_app.jinja_env.filters['b64encode'] = base64.b64encode
    flask_app.jinja_env.filters['s64decode'] = s64decode
    flask_app.jinja_env.filters['s64encode'] = s64encode
    flask_app.jinja_env.filters['b64escape'] = b64escape
    flask_app.jinja_env.filters['hexdump'] = hexdump_wrapper
    flask_app.jinja_env.filters['basename'] = os.path.basename
    flask_app.jinja_env.filters['human_readable_size'] = human_readable_size
    flask_app.jinja_env.filters['get_tag_css_class'] = get_tag_css_class
    flask_app.jinja_env.filters['get_tag_level'] = get_tag_level
    flask_app.jinja_env.filters['dict_from_json_string'] = dict_from_json_string
    flask_app.jinja_env.filters['pprint_json_dict'] = pprint_json_dict

    # add the "do" template command
    flask_app.jinja_env.add_extension('jinja2.ext.do')

    initialize_presenters()

    return flask_app