# default installation directory for ACE)
from datetime import tzinfo
import locale
import logging
import os
import socket
import tempfile
import time
from typing import Optional


from pydantic import BaseModel, Field
import pytz
import tzlocal

import ace_api
from saq.constants import (
    ENV_ACE_LOG_CONFIG_PATH,
    ENV_FLUENT_BIT_TAG,
    INSTANCE_TYPE_DEV,
    INSTANCE_TYPE_PRODUCTION,
    INSTANCE_TYPE_QA,
    INSTANCE_TYPE_UNITTEST,
)

class GlobalRuntimeSettings(BaseModel):
    analyst_data_dir: str = Field(default="/opt/ace/data/analyst", description="a directory controlled by the analysts that contains various data and configuration files")
    api_prefix: Optional[str] = Field(default=None, description="what prefix other systems use to communicate to the API server for this node")
    automation_user_id: Optional[int] = Field(default=None, description='global user ID for the "automation" user')
    ca_chain_path: Optional[str] = Field(default=None, description="path to the certifcate chain used by all SSL certs")
    company_id: Optional[int] = Field(default=None, description="the database id of the company this node belongs to")
    company_name: Optional[str] = Field(default=None, description="the company this node belongs to")
    data_dir: str = Field(default="/opt/ace/data", description="where ACE stores most of it's data, including alert data")
    default_encoding: str = Field(default_factory=locale.getpreferredencoding, description="what text encoding we're using")
    email_archive_server_id: Optional[int] = Field(default=None, description="archive server id for this server")
    encryption_initialized: bool = Field(default=False, description="")
    encryption_key: Optional[str] = Field(default=None, description="the private key password for encrypting/decrypting archive files")
    forced_alerts: bool = Field(default=False, description="set this to True to force all anlaysis to result in an alert being generated")
    gui_whitelist_excluded_observable_types: set[str] = Field(default_factory=set, description="list of observable types we want to exclude from whitelisting (via the GUI)")
    instance_type: str = Field(default=INSTANCE_TYPE_DEV, description="what type of instance is this?")
    integration_config_paths: list = Field(default_factory=list, description="list of integration configuration paths to be loaded by the integration loader")
    local_domains: list = Field(default_factory=list, description="")
    local_timezone_str: str = Field(default_factory=lambda: tzlocal.get_localzone_name(), description="local timezone for this system (should be UTC)")
    lock_timeout_seconds: int = Field(default=5 * 60, description="how long a lock can be held and not refreshed before it is considered expired")
    log_directory: str = Field(default="logs", description="global logging directory (relative to DATA_DIR)")
    managed_networks: list = Field(default_factory=list, description="list of iptools.IpRange objects defined in [network_configuration]")
    module_stats_dir: str = Field(default="stats/modules", description="directory containing module statistical runtime info")
    observable_limit: int = Field(default=0, description="")
    saq_home: str = Field(default="/opt/ace", description="base installation directory of ace")
    saq_node: Optional[str] = Field(default=None, description="current engine node name")
    saq_node_id: Optional[int] = Field(default=None, description="current engine node id")
    semaphores_enabled: bool = Field(default=True, description="Set to False to disable all network semaphores.")
    stats_dir: str = Field(default="stats", description="directory containing statistical runtime info")
    temp_dir: str = Field(default_factory=tempfile.gettempdir, description="where ACE stores temporary files")
    unit_testing: bool = Field(default_factory=lambda: "SAQ_UNIT_TESTING" in os.environ, description="set to True if we are operating in a testing environment")

    @property
    def local_timezone(self) -> tzinfo:
        return pytz.timezone(self.local_timezone_str)

GLOBAL_RUNTIME_SETTINGS = GlobalRuntimeSettings()

def get_global_runtime_settings() -> GlobalRuntimeSettings:
    return GLOBAL_RUNTIME_SETTINGS

#
# utility function aliases
#


def get_base_dir() -> str:
    return get_global_runtime_settings().saq_home

def get_temp_dir() -> str:
    return get_global_runtime_settings().temp_dir

def initialize_data_dir():
    """Initializes the data directory by creating all the sub directories needed.
    g(G_DATA_DIR) must be set prior to this call and the directory must already
    exist or an exception is raised."""

    from saq.configuration import get_config
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
        os.path.join(data_dir, get_global_runtime_settings().saq_node),
        os.path.join(data_dir, "review", "rfc822"),
        os.path.join(data_dir, "review", "misc"),
        os.path.join(
            data_dir,
            get_config().global_settings.error_reporting_dir,
        ),
        get_global_runtime_settings().stats_dir,
        get_global_runtime_settings().module_stats_dir,
        os.path.join(get_global_runtime_settings().stats_dir, "brocess"),  # get rid of this
        os.path.join(get_global_runtime_settings().stats_dir, "metrics"),
        # XXX this should be done by the splunk module?
        os.path.join(get_data_dir(), get_config().splunk_logging.splunk_log_dir),
        os.path.join(get_data_dir(), get_config().splunk_logging.splunk_log_dir, "smtp"),
        get_temp_dir(),
        os.path.join(
            data_dir,
            get_config().collection.persistence_dir,
        ),
        os.path.join(
            data_dir,
            get_config().collection.incoming_dir,
        ),
        get_collection_error_dir(),
    ]:
        os.makedirs(dir_path, exist_ok=True)


def get_data_dir() -> str:
    return get_global_runtime_settings().data_dir

def get_integration_dir() -> str:
    return os.path.join(get_base_dir(), "integrations")

def get_local_timezone() -> tzinfo:
    return get_global_runtime_settings().local_timezone

def set_node(name):
    """Sets the value for saq.SAQ_NODE. Typically this is auto-set using the local fqdn."""
    from saq.database import initialize_node
    
    if name != get_global_runtime_settings().saq_node:
        get_global_runtime_settings().saq_node = name
        get_global_runtime_settings().saq_node_id = None
        initialize_node()

def reset_node(name):
    """Clears any existing node settings and then applies the new settings."""
    get_global_runtime_settings().saq_node = None
    get_global_runtime_settings().saq_node_id = None
    return set_node(name)

def initialize_environment(
    saq_home=None,
    data_dir=None,
    temp_dir=None,
    config_paths=None,
    logging_config_path=None,
    relative_dir=None,
    encryption_password_plaintext=None,
    skip_initialize_automation_user=False,
    force_alerts=False,
):
    """Initializes ACE."""

    from saq.database import initialize_database, initialize_automation_user
    from saq.configuration import (
        get_config,
        initialize_configuration,
        resolve_configuration,
    )
    from saq.integration.integration_loader import load_integrations, initialize_integrations

    load_integrations()
    initialize_configuration(config_paths=config_paths)
    initialize_integrations()

    get_global_runtime_settings().data_dir = data_dir if data_dir else os.path.join(
        get_base_dir(), get_config().global_settings.data_dir
    )

    get_global_runtime_settings().analyst_data_dir = os.path.join(
        get_base_dir(),
        get_config().global_settings.analyst_data_dir,
    )

    # figure out where the tmp dir should be
    if not temp_dir:
        temp_dir = get_config().global_settings.tmp_dir or os.path.join(tempfile.gettempdir(), "ace")
        if os.path.isabs(temp_dir):
            temp_dir = os.path.join(get_base_dir(), temp_dir)

    get_global_runtime_settings().temp_dir = temp_dir
    get_global_runtime_settings().company_name = get_config().global_settings.company_name
    get_global_runtime_settings().company_id = get_config().global_settings.company_id
    get_global_runtime_settings().local_domains = get_config().global_settings.local_domains
    get_global_runtime_settings().observable_limit = get_config().global_settings.maximum_observable_count

    minutes, seconds = map(
        int, get_config().global_settings.lock_timeout.split(":")
    )
    get_global_runtime_settings().lock_timeout_seconds = (minutes * 60) + seconds

    # if the logging configuration path is not specified, see if it's set in the environment
    if logging_config_path is None:
        logging_config_path = os.environ.get(ENV_ACE_LOG_CONFIG_PATH)

    # if it's still not set, use the default console logging configuration
    if logging_config_path is None:
        logging_config_path = os.path.join(get_base_dir(), "etc", "logging_configs", "console_logging.yaml")

    from saq.logging import initialize_logging

    initialize_logging(
        logging_config_path,
        log_sql=get_config().global_settings.log_sql,
        # optional fluent-bit tag will set the tag for all log messages sent to fluent-bit
        fluent_bit_tag=os.environ.get(ENV_FLUENT_BIT_TAG),
    )  # this log file just gets some startup information

    # has the encryption password been set yet?
    from saq.crypto import initialize_encryption

    # TODO update this logic and deal with missing and invalid passwords
    initialize_encryption(encryption_password_plaintext=encryption_password_plaintext)

    # resolve any encrypted values that were referenced in the config
    resolve_configuration(get_config())

    get_global_runtime_settings().gui_whitelist_excluded_observable_types = set(get_config().gui.whitelist_excluded_observable_types)

    # what node is this?
    node = get_config().global_settings.node
    if node == "AUTO":
        node = socket.getfqdn()

    # configure prefix
    get_global_runtime_settings().api_prefix = get_config().api.prefix
    if get_global_runtime_settings().api_prefix == "AUTO":
        get_global_runtime_settings().api_prefix = socket.getfqdn()

    set_node(node)

    logging.debug("node {} has api prefix {}".format(get_global_runtime_settings().saq_node, get_global_runtime_settings().api_prefix))

    # what type of instance is this?
    get_global_runtime_settings().instance_type = get_config().global_settings.instance_type
    if get_global_runtime_settings().instance_type not in [
        INSTANCE_TYPE_PRODUCTION,
        INSTANCE_TYPE_QA,
        INSTANCE_TYPE_DEV,
        INSTANCE_TYPE_UNITTEST,
    ]:
        raise RuntimeError("invalid instance type", get_global_runtime_settings().instance_type)

    get_global_runtime_settings().forced_alerts = force_alerts

    if get_global_runtime_settings().forced_alerts:  # lol
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
    if time.strftime("%z") != "+0000":
        logging.warning("Timezone is not UTC. All ACE systems in a cluster should be in UTC.")

    # we can globally disable semaphores with this flag
    get_global_runtime_settings().semaphores_enabled = get_config().global_settings.enable_semaphores

    # some settings can be set to PROMPT
    # for section in CONFIG.sections():
    # for (name, value) in CONFIG.items(section):
    # if value == 'PROMPT':
    # CONFIG.set(section, name, getpass("Enter the value for {0}:{1}: ".format(section, name)))

    # make sure we've got the ca chain for SSL certs
    get_global_runtime_settings().ca_chain_path = os.path.join(
        get_base_dir(), get_config().SSL.ca_chain_path
    )

    ace_api.set_default_ssl_ca_path(get_global_runtime_settings().ca_chain_path)

    # set the api key if it's available
    if get_config().api.api_key:
        ace_api.set_default_api_key(get_config().api.api_key)

    if get_config().api.prefix:
        ace_api.set_default_remote_host(get_config().api.prefix)

    # initialize the database connection
    initialize_database()

    # initialize fallback semaphores
    from saq.network_semaphore.fallback import initialize_fallback_semaphores

    initialize_fallback_semaphores()

    get_global_runtime_settings().stats_dir = os.path.join(get_data_dir(), "stats")
    get_global_runtime_settings().module_stats_dir = os.path.join(get_global_runtime_settings().stats_dir, "modules")

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

    # load global constants
    import iptools

    # for cidr in CONFIG['network_configuration']['managed_networks'].split(','):
    for cidr in get_config().network_configuration.managed_networks:
        try:
            get_global_runtime_settings().managed_networks.append(iptools.IpRange(cidr.strip()))
        except Exception as e:
            logging.error("invalid managed network {}: {}".format(cidr, str(e)))

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

    from saq.phishkit import initialize_phishkit
    initialize_phishkit()

    logging.debug("SAQ initialized")
