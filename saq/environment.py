# default installation directory for ACE)
from dataclasses import dataclass
from datetime import tzinfo
import locale
import logging
import os
import socket
import sys
import tempfile
from typing import Any, Optional, Type

import urllib

import pytz
import tzlocal

import ace_api
from saq.constants import (
    CONFIG_API,
    CONFIG_API_KEY,
    CONFIG_API_PREFIX,
    CONFIG_COLLECTION,
    CONFIG_COLLECTION_INCOMING_DIR,
    CONFIG_COLLECTION_PERSISTENCE_DIR,
    CONFIG_GLOBAL,
    CONFIG_GLOBAL_ANALYST_DATA_DIR,
    CONFIG_GLOBAL_COMPANY_ID,
    CONFIG_GLOBAL_COMPANY_NAME,
    CONFIG_GLOBAL_DATA_DIR,
    CONFIG_GLOBAL_ENABLE_SEMAPHORES,
    CONFIG_GLOBAL_ERROR_REPORTING_DIR,
    CONFIG_GLOBAL_EXECUTION_THREAD_LONG_TIMEOUT,
    CONFIG_GLOBAL_LOCAL_DOMAINS,
    CONFIG_GLOBAL_LOCK_TIMEOUT,
    CONFIG_GLOBAL_MAXIMUM_OBSERVABLE_COUNT,
    CONFIG_GLOBAL_NODE,
    CONFIG_GLOBAL_TEMP_DIR,
    CONFIG_GUI,
    CONFIG_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES,
    CONFIG_GLOBAL_INSTANCE_TYPE,
    CONFIG_GLOBAL_LOG_SQL,
    CONFIG_NETWORK_CONFIGURATION,
    CONFIG_NETWORK_CONFIGURATION_MANAGED_NETWORKS,
    CONFIG_SQLITE3,
    CONFIG_SQLITE3_TIMEOUT,
    CONFIG_SSL,
    CONFIG_SSL_CA_CHAIN_PATH,
    G_ANALYST_DATA_DIR,
    G_API_PREFIX,
    G_AUTOMATION_USER_ID,
    G_CA_CHAIN_PATH,
    G_COMPANY_ID,
    G_COMPANY_NAME,
    G_CONFIG,
    G_CONFIG_PATHS,
    G_DAEMON_DIR,
    G_DAEMON_MODE,
    G_DATA_DIR,
    G_DEFAULT_ENCODING,
    G_DUMP_TRACEBACKS,
    G_ECS_SOCKET_PATH,
    G_EMAIL_ARCHIVE_SERVER_ID,
    G_ENCRYPTION_INITIALIZED,
    G_ENCRYPTION_KEY,
    G_EXECUTION_THREAD_LONG_TIMEOUT,
    G_FORCED_ALERTS,
    G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES,
    G_INSTANCE_TYPE,
    G_LOCAL_DOMAINS,
    G_LOCAL_TIMEZONE,
    G_LOCK_TIMEOUT_SECONDS,
    G_LOG_DIRECTORY,
    G_LOG_LEVEL,
    G_MANAGED_NETWORKS,
    G_MODULE_STATS_DIR,
    G_NODE_COMPANIES,
    G_OBSERVABLE_LIMIT,
    G_OTHER_PROXIES,
    G_SAQ_HOME,
    G_SAQ_NODE,
    G_SAQ_NODE_ID,
    G_SAQ_RELATIVE_DIR,
    G_SEMAPHORES_ENABLED,
    G_SERVICES_DIR,
    G_SQLITE3_TIMEOUT,
    G_STATS_DIR,
    G_TEMP_DIR,
    G_UNIT_TESTING,
    INSTANCE_TYPE_DEV,
    INSTANCE_TYPE_PRODUCTION,
    INSTANCE_TYPE_QA,
    INSTANCE_TYPE_UNITTEST,
)


@dataclass
class GlobalEnvironmentSetting:
    name: str
    value: Any
    description: str


# global environment settings
GLOBAL_ENV = {
    G_SAQ_HOME: GlobalEnvironmentSetting(
        name=G_SAQ_HOME,
        value="/opt/ace",
        description="base installation directory of ace",
    ),
    #G_DB: GlobalEnvironmentSetting(
        #name=G_DB,
        #value=None,
        #description="The global SQLAlchemy database session context."),
    G_UNIT_TESTING: GlobalEnvironmentSetting(
        name=G_UNIT_TESTING,
        value="SAQ_UNIT_TESTING" in os.environ,
        description="set to True if we are operating in a testing environment",
    ),
    G_AUTOMATION_USER_ID: GlobalEnvironmentSetting(
        name=G_AUTOMATION_USER_ID,
        value=None,
        description='global user ID for the "automation" user',
    ),
    G_LOCAL_TIMEZONE: GlobalEnvironmentSetting(
        name=G_LOCAL_TIMEZONE,
        value=pytz.timezone(tzlocal.get_localzone_name()),
        description="local timezone for this system (should be UTC)",
    ),
    G_SAQ_NODE: GlobalEnvironmentSetting(
        name=G_SAQ_NODE, value=None, description="current engine node name"
    ),
    G_SAQ_NODE_ID: GlobalEnvironmentSetting(
        name=G_SAQ_NODE_ID, value=None, description="current engine node id"
    ),
    G_TEMP_DIR: GlobalEnvironmentSetting(
        name=G_TEMP_DIR,
        value=tempfile.gettempdir(),
        description="where ACE stores temporary files",
    ),
    G_ANALYST_DATA_DIR: GlobalEnvironmentSetting(
        name=G_ANALYST_DATA_DIR,
        value="/opt/ace/data/analyst",
        description="a directory controlled by the analysts that contains various data and configuration files",
    ),
    G_DATA_DIR: GlobalEnvironmentSetting(
        name=G_DATA_DIR,
        value="/opt/ace/data",
        description="where ACE stores most of it's data, including alert data",
    ),
    G_ENCRYPTION_KEY: GlobalEnvironmentSetting(
        name=G_ENCRYPTION_KEY,
        value=None,
        description="the private key password for encrypting/decrypting archive files",
    ),
    G_LOCK_TIMEOUT_SECONDS: GlobalEnvironmentSetting(
        name=G_LOCK_TIMEOUT_SECONDS,
        value=5 * 60,
        description="how long a lock can be held and not refreshed before it is considered expired",
    ),
    G_API_PREFIX: GlobalEnvironmentSetting(
        name=G_API_PREFIX,
        value=None,
        description="what prefix other systems use to communicate to the API server for this node",
    ),
    G_DEFAULT_ENCODING: GlobalEnvironmentSetting(
        name=G_DEFAULT_ENCODING,
        value=locale.getpreferredencoding(),
        description="what text encoding we're using",
    ),
    G_SAQ_RELATIVE_DIR: GlobalEnvironmentSetting(
        name=G_SAQ_RELATIVE_DIR, value=None, description=""
    ),
    G_CONFIG: GlobalEnvironmentSetting(
        name=G_CONFIG, value=None, description="global configuration"
    ),
    G_CONFIG_PATHS: GlobalEnvironmentSetting(
        name=G_CONFIG_PATHS, value=[], description=""
    ),
    G_SEMAPHORES_ENABLED: GlobalEnvironmentSetting(
        name=G_SEMAPHORES_ENABLED,
        value=True,
        description="Set to False to disable all network semaphores.",
    ),
    G_OTHER_PROXIES: GlobalEnvironmentSetting(
        name=G_OTHER_PROXIES, value={}, description=""
    ),
    G_MANAGED_NETWORKS: GlobalEnvironmentSetting(
        name=G_MANAGED_NETWORKS,
        value=[],
        description="list of iptools.IpRange objects defined in [network_configuration]",
    ),
    G_FORCED_ALERTS: GlobalEnvironmentSetting(
        name=G_FORCED_ALERTS,
        value=False,
        description="set this to True to force all anlaysis to result in an alert being generated",
    ),
    G_ENCRYPTION_INITIALIZED: GlobalEnvironmentSetting(
        name=G_ENCRYPTION_INITIALIZED, value=False, description=""
    ),
    G_LOG_LEVEL: GlobalEnvironmentSetting(
        name=G_LOG_LEVEL, value=logging.INFO, description="the global log level setting"
    ),
    G_LOG_DIRECTORY: GlobalEnvironmentSetting(
        name=G_LOG_DIRECTORY,
        value="logs",
        description="global logging directory (relative to DATA_DIR)",
    ),
    G_STATS_DIR: GlobalEnvironmentSetting(
        name=G_STATS_DIR,
        value="stats",
        description="directory containing statistical runtime info",
    ),
    G_MODULE_STATS_DIR: GlobalEnvironmentSetting(
        name=G_MODULE_STATS_DIR,
        value="stats/modules",
        description="directory containing module statistical runtime info",
    ),
    G_DAEMON_MODE: GlobalEnvironmentSetting(
        name=G_DAEMON_MODE, value=False, description="deprecated"
    ),
    G_DAEMON_DIR: GlobalEnvironmentSetting(
        name=G_DAEMON_DIR, value=None, description="deprecated"
    ),
    G_SERVICES_DIR: GlobalEnvironmentSetting(
        name=G_SERVICES_DIR,
        value=None,
        description="directory where files are stored for running services",
    ),
    G_CA_CHAIN_PATH: GlobalEnvironmentSetting(
        name=G_CA_CHAIN_PATH,
        value=None,
        description="path to the certifcate chain used by all SSL certs",
    ),
    G_INSTANCE_TYPE: GlobalEnvironmentSetting(
        name=G_INSTANCE_TYPE,
        value=INSTANCE_TYPE_DEV,
        description="what type of instance is this?",
    ),
    G_DUMP_TRACEBACKS: GlobalEnvironmentSetting(
        name=G_DUMP_TRACEBACKS,
        value=False,
        description="set to True to cause tracebacks to be dumped to standard output",
    ),
    G_EXECUTION_THREAD_LONG_TIMEOUT: GlobalEnvironmentSetting(
        name=G_EXECUTION_THREAD_LONG_TIMEOUT, value=None, description=""
    ),
    G_COMPANY_NAME: GlobalEnvironmentSetting(
        name=G_COMPANY_NAME, value=None, description="the company this node belongs to"
    ),
    G_COMPANY_ID: GlobalEnvironmentSetting(
        name=G_COMPANY_ID,
        value=None,
        description="the database id of the company this node belongs to",
    ),
    G_NODE_COMPANIES: GlobalEnvironmentSetting(
        name=G_NODE_COMPANIES,
        value=[],
        description="A list of company names and IDs this node will work for",
    ),
    G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES: GlobalEnvironmentSetting(
        name=G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES,
        value=[],
        description="list of observable types we want to exclude from whitelisting (via the GUI)",
    ),
    G_ECS_SOCKET_PATH: GlobalEnvironmentSetting(
        name=G_ECS_SOCKET_PATH,
        value=None,
        description="path to the unix socket for the optional encryption cache service",
    ),
    G_LOCAL_DOMAINS: GlobalEnvironmentSetting(
        name=G_LOCAL_DOMAINS, value=[], description=""
    ),
    G_SQLITE3_TIMEOUT: GlobalEnvironmentSetting(
        name=G_SQLITE3_TIMEOUT, value=None, description=""
    ),
    G_OBSERVABLE_LIMIT: GlobalEnvironmentSetting(
        name=G_OBSERVABLE_LIMIT, value=0, description=""
    ),
    G_EMAIL_ARCHIVE_SERVER_ID: GlobalEnvironmentSetting(
        name=G_EMAIL_ARCHIVE_SERVER_ID, value=None, description="archive server id for this server",
    ),
}

def g(name: str) -> str:
    return GLOBAL_ENV[name].value

def g_obj(name: str) -> GlobalEnvironmentSetting:
    """Returns the GlobalEnvironmentSetting object for this global setting."""
    return GLOBAL_ENV[name]

def g_type(name: str, _type: Type) -> Any:
    value = g(name)
    if value is None:
        return value

    if not isinstance(value, _type):
        logging.warning(
            "requested global configuration item %s as %s but type is %s",
            name,
            _type,
            type(value),
        )

    return value


def g_str(name: str) -> str:
    return g_type(name, str)


def g_int(name: str) -> int:
    return g_type(name, int)


def g_boolean(name: str) -> bool:
    return g_type(name, bool)


def g_list(name: str) -> list:
    return g_type(name, list)


def g_dict(name: str) -> dict:
    return g_type(name, dict)


def set_g(name: str, value: Any):
    # NOTE ran into issues logging here in old api_server-based end-to-end tests
    # once that is cleaned up we can log here again
    #if name in GLOBAL_ENV and GLOBAL_ENV[name].value != value:
        #logging.info("changing global variable %s from %s to %s", name, GLOBAL_ENV[name].value, value)
    #else:
        #logging.info("initializing global variable %s to %s", name, value)

    GLOBAL_ENV[name].value = value

#
# utility function aliases
#


def get_base_dir() -> str:
    return g(G_SAQ_HOME)

def get_temp_dir() -> str:
    return g(G_TEMP_DIR)

def initialize_base_dir(saq_home: Optional[str] = None):
    # optional override from the environment
    if "SAQ_HOME" in os.environ:
        set_g(G_SAQ_HOME, os.environ["SAQ_HOME"])

    # allow one to be passed in
    if saq_home:
        set_g(G_SAQ_HOME, saq_home)

    # make sure whatever it is set to actually exists
    if not os.path.isdir(get_base_dir()):
        raise RuntimeError("SAQ_HOME does not exist", get_base_dir())

    # make sure it's actually the root directory of ACE
    if not os.path.isdir(os.path.join(get_base_dir(), "saq")):
        raise RuntimeError(
            "SAQ_HOME does not appear to actually be the home directory for ACE (missing saq directory?)",
            get_base_dir(),
        )

def initialize_data_dir():
    """Initializes the data directory by creating all the sub directories needed.
    g(G_DATA_DIR) must be set prior to this call and the directory must already
    exist or an exception is raised."""

    from saq.configuration import get_config_value
    from saq.local_locking import get_lock_directory
    from saq.email_archive import get_email_archive_dir
    from saq.collectors.base_collector import get_collection_error_dir

    data_dir = get_data_dir()

    if not data_dir:
        raise RuntimeError("data directory not set")

    if not os.path.exists(data_dir):
        raise RuntimeError("data directory does not exist", data_dir)

    for dir_path in [
        os.path.join(data_dir, "logs"),
        get_lock_directory(),
        get_email_archive_dir(),
        os.path.join(data_dir, g(G_SAQ_NODE)),
        os.path.join(data_dir, "review", "rfc822"),
        os.path.join(data_dir, "review", "misc"),
        os.path.join(
            data_dir,
            get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ERROR_REPORTING_DIR, default="error_reports"),
        ),
        g(G_STATS_DIR),
        g(G_MODULE_STATS_DIR),
        os.path.join(g(G_STATS_DIR), "brocess"),  # get rid of this
        os.path.join(g(G_STATS_DIR), "metrics"),
        # XXX this should be done by the splunk module?
        os.path.join(get_data_dir(), get_config_value("splunk_logging", "splunk_log_dir")),
        os.path.join(get_data_dir(), get_config_value("splunk_logging", "splunk_log_dir"), "smtp"),
        g(G_TEMP_DIR),
        g(G_SERVICES_DIR),
        os.path.join(
            data_dir,
            get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_PERSISTENCE_DIR, default="var/collection/persistence"),
        ),
        os.path.join(
            data_dir,
            get_config_value(CONFIG_COLLECTION, CONFIG_COLLECTION_INCOMING_DIR, default="var/collection/incoming"),
        ),
        get_collection_error_dir(),
        g(G_DAEMON_DIR),
    ]:
        os.makedirs(dir_path, exist_ok=True)


def get_data_dir() -> str:
    return g(G_DATA_DIR)

def get_integration_dir() -> str:
    return os.path.join(get_base_dir(), "integrations")

def get_local_timezone() -> tzinfo:
    return g(G_LOCAL_TIMEZONE)

def set_node(name):
    """Sets the value for saq.SAQ_NODE. Typically this is auto-set using the local fqdn."""
    from saq.database import initialize_node
    
    if name != g(G_SAQ_NODE):
        set_g(G_SAQ_NODE, name)
        set_g(G_SAQ_NODE_ID, None)
        initialize_node()

def reset_node(name):
    """Clears any existing node settings and then applies the new settings."""
    set_g(G_SAQ_NODE, None)
    set_g(G_SAQ_NODE_ID, None)
    return set_node(name)

def initialize_environment(
    saq_home=None,
    data_dir=None,
    temp_dir=None,
    log_level=logging.INFO,
    config_paths=[],
    logging_config_path=None,
    relative_dir=None,
    encryption_password_plaintext=None,
    skip_initialize_automation_user=False,
    force_alerts=False,
):
    """Initializes all of ACE.
    
    Note that this gets re-called after every test so keep that in mind."""

    from saq.database import initialize_database, initialize_automation_user
    from saq.configuration import (
        get_config,
        get_config_value,
        get_config_value_as_boolean,
        get_config_value_as_int,
        get_config_value_as_list,
        initialize_configuration,
    )
    from saq.monitor import reset_emitter, enable_monitor_logging

    initialize_base_dir(saq_home=saq_home)

    set_g(G_ECS_SOCKET_PATH, os.path.join(get_base_dir(), ".ecs"))

    # XXX not sure we need this SAQ_RELATIVE_DIR anymore -- check it out
    # this system was originally designed to run out of /opt/saq
    # later we modified to run out of anywhere for command line correlation
    # when running the GUI in apache you have no control over the current working directory
    # so we specify what directory we'd *want* to be running out of here (even if we're not actually)
    # this only matters when loading alerts
    # this defaults to the current working directory
    if relative_dir:
        set_g(G_SAQ_RELATIVE_DIR, relative_dir)
    else:
        set_g(G_SAQ_RELATIVE_DIR, os.path.relpath(os.getcwd(), start=get_base_dir()))

    if g_boolean(G_UNIT_TESTING):
        # unit testing loads different configurations
        g_list(G_CONFIG_PATHS).append(os.path.join(get_base_dir(), "etc", "saq.unittest.default.yaml"))
    else:
        g_list(G_CONFIG_PATHS).append(os.path.join(get_base_dir(), "etc", "saq.yaml"))

    initialize_configuration()

    set_g(
        G_DATA_DIR,
        data_dir if data_dir else os.path.join(
            get_base_dir(), get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_DATA_DIR)
        ),
    )
    set_g(
        G_ANALYST_DATA_DIR,
        os.path.join(
            get_base_dir(),
            get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ANALYST_DATA_DIR),
        ),
    )
    set_g(
        G_TEMP_DIR,
        temp_dir if temp_dir else os.path.join(
            get_data_dir(), get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_TEMP_DIR)
        ),
    )
    set_g(G_DAEMON_DIR, os.path.join(get_data_dir(), "var", "daemon"))
    set_g(G_SERVICES_DIR, os.path.join(get_data_dir(), "var", "services"))
    set_g(G_COMPANY_NAME, get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_COMPANY_NAME))
    set_g(
        G_COMPANY_ID, get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_COMPANY_ID)
    )
    set_g(
        G_LOCAL_DOMAINS,
        get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS),
    )
    set_g(
        G_SQLITE3_TIMEOUT,
        get_config_value_as_int(CONFIG_SQLITE3, CONFIG_SQLITE3_TIMEOUT, default=5),
    )
    set_g(
        G_OBSERVABLE_LIMIT,
        get_config_value_as_int(
            CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_OBSERVABLE_COUNT, default=0
        ),
    )

    minutes, seconds = map(
        int, get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCK_TIMEOUT).split(":")
    )
    set_g(G_LOCK_TIMEOUT_SECONDS, (minutes * 60) + seconds)
    set_g(
        G_EXECUTION_THREAD_LONG_TIMEOUT,
        get_config_value_as_int(
            CONFIG_GLOBAL, CONFIG_GLOBAL_EXECUTION_THREAD_LONG_TIMEOUT
        ),
    )

    # user specified log level
    LOG_LEVEL = logging.INFO
    if log_level:
        LOG_LEVEL = log_level

    # make sure the logs directory exists
    set_g(G_LOG_DIRECTORY, os.path.join(get_data_dir(), "logs"))
    if not os.path.exists(g(G_LOG_DIRECTORY)):
        try:
            os.mkdir(g(G_LOG_DIRECTORY))
        except Exception as e:
            sys.stderr.write("unable to mkdir {}: {}\n".format(g(G_LOG_DIRECTORY), e))
            raise e

    # by default we log to the console
    if logging_config_path is None:
        logging_config_path = os.path.join(get_base_dir(), "etc", "console_logging.ini")

    from saq.logging import initialize_logging

    initialize_logging(
        logging_config_path,
        log_sql=get_config_value_as_boolean(
            CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL, False
        ),
    )  # this log file just gets some startup information

    # has the encryption password been set yet?
    from saq.crypto import initialize_encryption

    # TODO update this logic and deal with missing and invalid passwords
    initialize_encryption(encryption_password_plaintext=encryption_password_plaintext)

    set_g(
        G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES,
        set(
            get_config_value_as_list(
                CONFIG_GUI, CONFIG_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES
            )
        ),
    )

    # what node is this?
    node = get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_NODE)
    if node == "AUTO":
        node = socket.getfqdn()

    # configure prefix
    set_g(G_API_PREFIX, get_config_value(CONFIG_API, CONFIG_API_PREFIX))
    if g(G_API_PREFIX) == "AUTO":
        set_g(G_API_PREFIX, socket.getfqdn())

    set_node(node)

    logging.debug("node {} has api prefix {}".format(g(G_SAQ_NODE), g(G_API_PREFIX)))

    # what type of instance is this?
    set_g(G_INSTANCE_TYPE, get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_TYPE))
    if g(G_INSTANCE_TYPE) not in [
        INSTANCE_TYPE_PRODUCTION,
        INSTANCE_TYPE_QA,
        INSTANCE_TYPE_DEV,
        INSTANCE_TYPE_UNITTEST,
    ]:
        raise RuntimeError("invalid instance type", g(G_INSTANCE_TYPE))

    if g_boolean(G_FORCED_ALERTS):  # lol
        logging.warning(
            " ****************************************************************** "
        )
        logging.warning(
            " ****************************************************************** "
        )
        logging.warning(
            " **** WARNING **** ALL ANALYSIS RESULTS IN ALERTS **** WARNING **** "
        )
        logging.warning(
            " ****************************************************************** "
        )
        logging.warning(
            " ****************************************************************** "
        )

    # warn if timezone is not UTC
    # if time.strftime("%z") != "+0000":
    # logging.warning("Timezone is not UTC. All ACE systems in a cluster should be in UTC.")

    # we can globally disable semaphores with this flag
    set_g(
        G_SEMAPHORES_ENABLED,
        get_config_value_as_boolean(CONFIG_GLOBAL, CONFIG_GLOBAL_ENABLE_SEMAPHORES),
    )

    # some settings can be set to PROMPT
    # for section in CONFIG.sections():
    # for (name, value) in CONFIG.items(section):
    # if value == 'PROMPT':
    # CONFIG.set(section, name, getpass("Enter the value for {0}:{1}: ".format(section, name)))

    # make sure we've got the ca chain for SSL certs
    set_g(
        G_CA_CHAIN_PATH,
        os.path.join(
            get_base_dir(), get_config_value(CONFIG_SSL, CONFIG_SSL_CA_CHAIN_PATH)
        ),
    )
    ace_api.set_default_ssl_ca_path(g(G_CA_CHAIN_PATH))

    # set the api key if it's available
    if get_config_value(CONFIG_API, CONFIG_API_KEY):
        ace_api.set_default_api_key(get_config_value(CONFIG_API, CONFIG_API_KEY))

    if get_config_value(CONFIG_API, CONFIG_API_PREFIX):
        ace_api.set_default_remote_host(get_config_value(CONFIG_API, CONFIG_API_PREFIX))

    # initialize the database connection
    initialize_database()

    # Store validated list of companies this node can work with
    # Assume configued defaults are already valid
    # NODE_COMPANIES.append({'name': COMPANY_NAME, 'id': COMPANY_ID})
    # _secondary_company_ids = CONFIG['global'].get('secondary_company_ids', None)
    # if _secondary_company_ids is not None:
    # _secondary_company_ids = [int(_) for _ in _secondary_company_ids.split(',')]
    # from saq.database import get_db_connection
    # try:
    # with get_db_connection() as db:
    # c = db.cursor()
    # c.execute("SELECT name,id FROM company")
    # for row in c:
    # if row[1] in _secondary_company_ids:
    # NODE_COMPANIES.append({'name': row[0], 'id': row[1]})
    # except Exception as e:
    # logging.error(f"problem querying database {e}")

    # initialize fallback semaphores
    from saq.network_semaphore.fallback import initialize_fallback_semaphores

    initialize_fallback_semaphores()

    # XXX get rid of this
    # try:
    # maliciousdir = CONFIG.get("global", "malicious")
    # except:
    # maliciousdir = "malicious"

    set_g(G_STATS_DIR, os.path.join(get_data_dir(), "stats"))
    set_g(G_MODULE_STATS_DIR, os.path.join(g(G_STATS_DIR), "modules"))

    # make sure some key directories exists
    initialize_data_dir()

    # clear out any proxy environment variables if they exist
    for proxy_key in ["http_proxy", "https_proxy", "ftp_proxy"]:
        if proxy_key in os.environ:
            if os.environ[proxy_key] != "":
                logging.warning(
                    "removing proxy environment variable for {}".format(proxy_key)
                )
            del os.environ[proxy_key]
        if proxy_key.upper() in os.environ:
            if os.environ[proxy_key.upper()] != "":
                logging.warning(
                    "removing proxy environment variable for {}".format(proxy_key.upper())
                )
            del os.environ[proxy_key.upper()]

    # load any additional proxies specified in the config sections proxy_*
    for section in get_config().keys():
        if section.startswith("proxy_"):
            proxy_name = section[len("proxy_") :]
            g_dict(G_OTHER_PROXIES)[proxy_name] = {}
            for proxy_key in ["http", "https"]:
                if (
                    get_config_value(section, "host")
                    and get_config_value(section, "port")
                    and get_config_value(section, "transport")
                ):
                    if get_config_value(section, "user") and get_config_value(
                        section, "password"
                    ):
                        g_dict(G_OTHER_PROXIES)[proxy_name][proxy_key] = (
                            "{}://{}:{}@{}:{}".format(
                                get_config_value(section, "transport"),
                                urllib.parse.quote_plus(
                                    get_config_value(section, "user")
                                ),
                                urllib.parse.quote_plus(
                                    get_config_value(section, "password")
                                ),
                                get_config_value(section, "host"),
                                get_config_value(section, "port"),
                            )
                        )
                    else:
                        g_dict(G_OTHER_PROXIES)[proxy_name][proxy_key] = (
                            "{}://{}:{}".format(
                                get_config_value(section, "transport"),
                                get_config_value(section, "host"),
                                get_config_value(section, "port"),
                            )
                        )

    # load global constants
    import iptools

    # for cidr in CONFIG['network_configuration']['managed_networks'].split(','):
    for cidr in get_config_value_as_list(
        CONFIG_NETWORK_CONFIGURATION, CONFIG_NETWORK_CONFIGURATION_MANAGED_NETWORKS
    ):
        try:
            if cidr:
                g_list(G_MANAGED_NETWORKS).append(iptools.IpRange(cidr.strip()))
        except Exception as e:
            logging.error("invalid managed network {}: {}".format(cidr, str(e)))

    # are we running as a daemon?
    # if args:
    # DAEMON_MODE = args.daemon

    # make sure we've got the automation user set up
    # XXX move this to database initialization time
    if not skip_initialize_automation_user:
        initialize_automation_user()

    # initialize other systems
    # initialize_message_system()

    from saq.disposition import initialize_dispositions
    initialize_dispositions()

    from saq.email_archive import initialize_email_archive
    initialize_email_archive()

    from saq.monitor import initialize_monitoring
    initialize_monitoring()

    from saq.integration.integration_loader import load_integrations
    load_integrations()

    logging.debug("SAQ initialized")
