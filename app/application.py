import base64
import hashlib
import json
import logging
import os
from subprocess import PIPE, Popen
from typing import Optional
from flask import Flask
from markupsafe import Markup
from werkzeug.security import safe_join
import markdown
import urllib

from app.blueprints import register_blueprints

from app.integration import register_integration_blueprints
from app.user_preferences import get_alert_sections_preference, get_theme_preference
from saq.configuration.config import get_config
from flask_config import get_flask_config
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_executor import Executor # XXX what is this for?
from sqlalchemy import event

from saq.database.pool import remove_all_sessions, set_db
from saq.disposition import (
    get_disposition_css,
    get_dispositions,
    get_selectable_dispositions,
    is_frozen_disposition,
)
from saq.environment import get_global_runtime_settings
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util.relative_time import is_relative_time, resolve_date_range_for_display
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

class _ExternalLinksTreeprocessor(markdown.treeprocessors.Treeprocessor):
    """Add target="_blank" and rel="noopener noreferrer" to all links."""
    def run(self, root):
        for element in root.iter('a'):
            element.set('target', '_blank')
            element.set('rel', 'noopener noreferrer')

class _ExternalLinksExtension(markdown.Extension):
    def extendMarkdown(self, md):
        md.treeprocessors.register(_ExternalLinksTreeprocessor(md), 'external_links', 15)

def render_markdown(text):
    return Markup(markdown.markdown(text, extensions=["extra", _ExternalLinksExtension()]))

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

# (mode, bootstrap icon, label, tooltip) for the theme switchers in base.html and preferences.html
THEME_CHOICES = [
    ("system", "bi-circle-half", "System", "Follow the operating system's light or dark setting"),
    ("light", "bi-sun", "Light", "Dark text on a light background"),
    ("dark", "bi-moon-stars", "Dark", "Light text on a dark background"),
    ("jd", None, "\U0001F474 JD", "High-contrast light"),
    ("halloween", None, "\U0001F383 Halloween", "Pumpkin orange on midnight purple"),
]


def static_file_version(path: str) -> Optional[str]:
    """A short hash of a static file's contents, or None when it can't be read."""
    try:
        with open(path, "rb") as fp:
            return hashlib.file_digest(fp, "sha256").hexdigest()[:12]
    except OSError:
        # a reference to a missing file (a configured pivot link icon, say) just 404s
        # without the version, which is no worse than it was
        return None


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

    @flask_app.teardown_appcontext
    def _remove_all_sessions(exception):
        # release thread-local sessions for every registered engine, not just
        # the ace session that flask-sqlalchemy manages on its own
        remove_all_sessions()

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

    # every url_for() on a static endpoint gets ?v=<hash of the file>, so a release that changes
    # a file changes its URL and nginx can let browsers keep a versioned URL forever
    # (etc/nginx/conf.d). ACE_VERSION was not enough: a patch release keeps it, and every
    # reference had to remember to append it. Files don't change inside a running container,
    # so each is hashed once per process; the dev GUI (debug) rehashes when the mtime moves.
    static_versions: dict = {}

    @flask_app.url_defaults
    def add_static_version(endpoint: str, values: dict):
        if not (endpoint == "static" or endpoint.endswith(".static")) or "v" in values:
            return

        if endpoint == "static":
            folder = flask_app.static_folder
        else:
            blueprint = flask_app.blueprints.get(endpoint.rsplit(".", 1)[0])
            folder = blueprint.static_folder if blueprint else None

        filename = values.get("filename")
        path = safe_join(folder, filename) if folder and filename else None
        if path is None:
            return

        key = path
        if flask_app.debug:
            try:
                key = (path, os.stat(path).st_mtime_ns)
            except OSError:
                return  # missing file, see static_file_version

        if key not in static_versions:
            static_versions[key] = static_file_version(path)

        if static_versions[key]:
            values["v"] = static_versions[key]

    @flask_app.context_processor
    def inject():
        # the favicon notification-dot poll follows the alert management page's
        # auto-refresh cadence, but 0 there only disables the in-page refresh -- the
        # favicon indicator must keep working, so fall back to 30 seconds
        auto_refresh_seconds = get_config().gui.manage_auto_refresh_seconds
        return {
            "ACE_VERSION": os.environ.get("ACE_VERSION", ""),
            "FAVICON_POLL_SECONDS": auto_refresh_seconds if auto_refresh_seconds > 0 else 30,
        }

    @flask_app.context_processor
    def inject_theme():
        # a callable rather than a value, so fragments rendered without the page chrome never
        # pay for the preference lookup; memoized per render because core.html, the navbar
        # and the preferences page each ask (a top-level set in core.html is not visible
        # inside the blocks a child template overrides)
        cache = []

        def ui_theme() -> str:
            if not cache:
                cache.append(get_theme_preference().mode)
            return cache[0]

        return {"ui_theme": ui_theme, "THEME_CHOICES": THEME_CHOICES}

    @flask_app.context_processor
    def inject_alert_sections():
        # the analyst's choices for which alert page sections start open
        # (analysis/_alert_section.html): a callable, so only a page with sections reads the
        # preference, memoized per render because every section on the page asks
        cache = []

        def alert_sections() -> dict[str, bool]:
            if not cache:
                cache.append(get_alert_sections_preference().sections)
            return cache[0]

        return {"alert_sections": alert_sections}

    @flask_app.context_processor
    def inject_dispositions():
        # every page can render the disposition modals (base.html) and disposition badges.
        # `dispositions` is every configured disposition (filters, badges); the modals offer
        # only `selectable_dispositions`, the ones an analyst may set; an alert whose disposition
        # is_frozen_disposition (SIMULATED) can't be changed by hand at all.
        return {
            "dispositions": get_dispositions(),
            "selectable_dispositions": get_selectable_dispositions(),
            "disposition_css": get_disposition_css,
            "is_frozen_disposition": is_frozen_disposition,
        }

    @flask_app.context_processor
    def inject_permission_helpers():
        # Expose a template-callable permission check for gating nav links and admin tiles.
        # Uses the same synchronous enforcement path as the @require_permission decorator so nav
        # rendering does not pay a background-loop round-trip.
        from flask_login import current_user
        from saq.permissions.logic import user_has_permission

        def has_permission(major: str, minor: str) -> bool:
            if not current_user.is_authenticated:
                return False
            return user_has_permission(current_user.id, major, minor)

        return {"has_permission": has_permission}

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
    flask_app.jinja_env.filters['markdown'] = render_markdown
    # renders a date range filter value as the concrete window it currently means, so a
    # relative token like "-24h" is never opaque in the filter bar
    flask_app.jinja_env.filters['resolve_date_range'] = resolve_date_range_for_display
    # lets the filter editor render a stored value in the right mode on first paint
    flask_app.jinja_env.tests['relative_date'] = is_relative_time
    flask_app.jinja_env.filters['is_relative_date'] = is_relative_time

    # add the "do" template command
    flask_app.jinja_env.add_extension('jinja2.ext.do')

    initialize_presenters()

    return flask_app