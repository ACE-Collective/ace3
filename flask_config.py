# vim: sw=4:ts=4:et
# configuration settings for the GUI

from functools import lru_cache
from saq.configuration import get_config
from saq.constants import GUI_TABS, INSTANCE_TYPE_DEV, INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_QA, INSTANCE_TYPE_UNITTEST
from saq.util import abs_path

def _get_secret_key():
    result = get_config().gui.secret_key
    if result:
        return result

    import string
    import random
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(64))

class Config:
    def __init__(self):
        self.SECRET_KEY = _get_secret_key()
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False

        # Session cookie hardening. These were previously unset, leaving the behaviour to browser
        # defaults. The aceapi_v2 app authenticates browser requests with this same cookie, so these
        # attributes are part of its CSRF story too (see aceapi_v2/dependencies.py).
        #
        # SameSite=Lax rather than Strict: Strict would suppress the cookie when a user follows a
        # link into ACE from an external page (an alert link in chat, say) and they would appear
        # logged out. Lax still withholds the cookie from cross-site POSTs, which is the CSRF case.
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = True

        # flask-login's "remember me" cookie gets the same treatment
        self.REMEMBER_COOKIE_HTTPONLY = True
        self.REMEMBER_COOKIE_SAMESITE = "Lax"
        self.REMEMBER_COOKIE_SECURE = True

        self.INSTANCE_NAME = get_config().global_settings.instance_name

        # GUI configurations for base template use
        self.GUI_DISPLAY_METRICS = get_config().gui.display_metrics
        self.GUI_DISPLAY_EVENTS = get_config().gui.display_events
        self.AUTHENTICATION_ON = get_config().gui.authentication
        self.GOOGLE_ANALYTICS = get_config().gui.google_analytics

        # also see lib/saq/database.py:initialize_database
        ace_config = get_config().get_database_config("ace")
        if ace_config.unix_socket:
            self.SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@localhost/{database}?unix_socket={unix_socket}&charset=utf8mb4'.format(
                username=ace_config.username,
                password=ace_config.password,
                unix_socket=ace_config.unix_socket,
                database=ace_config.database)
        else:
            self.SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}?charset=utf8mb4'.format(
                username=ace_config.username,
                password=ace_config.password,
                hostname=ace_config.hostname,
                port=ace_config.port,
                database=ace_config.database)

        self.SQLALCHEMY_POOL_TIMEOUT = 30
        self.SQLALCHEMY_POOL_RECYCLE = 60 * 10 # 10 minute connection pool recycle

        # gets passed as **kwargs to create_engine call of SQLAlchemy
        # this is used by the non-flask applications to configure SQLAlchemy db connection
        self.SQLALCHEMY_DATABASE_OPTIONS = { 
            'pool_recycle': self.SQLALCHEMY_POOL_RECYCLE,
            'pool_timeout': self.SQLALCHEMY_POOL_TIMEOUT,
            'pool_size': 5,
            'connect_args': { 'init_command': 'SET NAMES utf8mb4' },
            'pool_pre_ping': True,
        }

        if ace_config.max_allowed_packet:
            self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['max_allowed_packet'] = ace_config.max_allowed_packet

        # are we using SSL for MySQL connections? (you should be)
        if not ace_config.unix_socket:
            if ace_config.ssl_ca or ace_config.ssl_cert or ace_config.ssl_key:
                ssl_options = { 'ca': abs_path(ace_config.ssl_ca) }
                if ace_config.ssl_cert:
                    ssl_options['cert'] = abs_path(ace_config.ssl_cert)
                if ace_config.ssl_key:
                    ssl_options['key'] = abs_path(ace_config.ssl_key)
                self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['ssl'] = ssl_options

    @property
    def GUI_TABS(self) -> list[str]:
        if get_config().gui.navigation_tabs.strip().lower() == "all":
            return GUI_TABS
        else:
            return get_config().gui.navigation_tabs

    @staticmethod
    def init_app(app):
        pass

class ProductionConfig(Config):
    
    def __init__(self):
        super().__init__()
        self.DEBUG = False
        self.TEMPLATES_AUTO_RELOAD = False

class DevelopmentConfig(Config):

    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TEMPLATES_AUTO_RELOAD = True

class UnitTestConfig(Config):

    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TEMPLATES_AUTO_RELOAD = True

@lru_cache
def get_flask_config(name: str) -> Config:
    # the keys for this dict match the instance_type config setting in global section of etc/saq.yaml
    if name == INSTANCE_TYPE_DEV:
        return DevelopmentConfig()
    elif name == INSTANCE_TYPE_PRODUCTION:
        return ProductionConfig()
    elif name == INSTANCE_TYPE_QA:
        return ProductionConfig()
    elif name == INSTANCE_TYPE_UNITTEST:
        return UnitTestConfig()
    else:
        raise ValueError("invalid instance type", name)
