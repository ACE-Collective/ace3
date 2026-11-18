# vim: sw=4:ts=4:et
# configuration settings for the GUI

from functools import lru_cache
from saq.configuration import get_config
from saq.constants import GUI_TABS, INSTANCE_TYPE_DEV, INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_QA, INSTANCE_TYPE_UNITTEST

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
