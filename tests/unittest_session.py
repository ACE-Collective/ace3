# vim: sw=4:ts=4:et
#
# per-process ("slot") identity for the test suite
#
# under pytest-xdist every worker is its own pytest session, and several things a session
# uses are host-wide: the data directory, the API server port, the network semaphore port,
# the log file. each pytest process therefore gets a slot -- its xdist worker id (gw0, gw1,
# ...) or "main" when not running under xdist -- and everything per-process is derived from
# it here. the values reach the configuration through the same SAQ_UNITTEST_CONFIG_PATHS
# overlay that tests/unittest_database.py writes for the per-session database names.
#
# this module deliberately imports nothing from saq: it runs before the configuration is
# loaded, and bin/cleanup-unittest-databases.py imports it from outside a session.
#

import os
import re

import yaml

DATA_DIR_NAME = "data_unittest"
MAIN_SLOT = "main"
WORKER_ENV_VAR = "PYTEST_XDIST_WORKER"

API_BASE_PORT = 24443
NETWORK_SEMAPHORE_BASE_PORT = 53560

LOG_DIR = os.path.join("data", "logs")
LOGGING_CONFIG_PATH = os.path.join("etc", "logging_configs", "unittest_logging.yaml")

_SLOT_PATTERN = re.compile(r"^(main|gw\d+)$")


def get_project_root() -> str:
    return os.environ.get("SAQ_HOME", os.getcwd())


def get_slot() -> str:
    """Returns this process's slot: the xdist worker id, or "main" outside of xdist."""
    return os.environ.get(WORKER_ENV_VAR) or MAIN_SLOT


def get_slot_index() -> int:
    """Returns the number in the slot name (gw3 -> 3); main is 0."""
    slot = get_slot()
    if slot == MAIN_SLOT:
        return 0

    match = re.match(r"^gw(\d+)$", slot)
    if match is None:
        raise ValueError(f"unrecognized pytest-xdist worker id {slot!r}")

    return int(match.group(1))


def is_slot_name(name: str) -> bool:
    return _SLOT_PATTERN.match(name) is not None


def is_xdist_worker(config) -> bool:
    """True inside an xdist worker process (the controller and a plain pytest run are not)."""
    return hasattr(config, "workerinput")


def get_data_dir_root() -> str:
    """The directory that holds one data directory per slot."""
    return os.path.join(get_project_root(), DATA_DIR_NAME)


def get_session_data_dir() -> str:
    return os.path.join(get_data_dir_root(), get_slot())


def get_api_port() -> int:
    return API_BASE_PORT + get_slot_index()


def get_network_semaphore_port() -> int:
    return NETWORK_SEMAPHORE_BASE_PORT + get_slot_index()


def session_overrides() -> dict:
    """The configuration overlay that makes this slot's host-wide resources its own.

    Paths are relative to SAQ_HOME (which is also the working directory): global.data_dir is
    only the fallback when initialize_environment() is not handed a data_dir, storage.base_dir
    is resolved against SAQ_HOME by saq/storage/factory.py, and the network semaphore's
    stats_dir is used as-is by saq/network_semaphore/server.py."""
    slot = get_slot()
    relative_data_dir = os.path.join(DATA_DIR_NAME, slot)
    api_port = get_api_port()
    semaphore_port = get_network_semaphore_port()

    return {
        "global": {"data_dir": relative_data_dir},
        "storage": {"base_dir": os.path.join(relative_data_dir, "storage")},
        "api": {"listen_port": api_port, "prefix": f"localhost:{api_port}"},
        "service_network_semaphore": {
            "bind_port": semaphore_port,
            "remote_port": semaphore_port,
            "stats_dir": os.path.join(relative_data_dir, "var", "network_semaphore"),
        },
        "qdrant": {"collection_prefix": f"ace3-alerts-unittest-{slot}"},
    }


def get_log_file_name(stem: str) -> str:
    """Name of a per-slot log file in LOG_DIR, e.g. unittest-gw0.log."""
    return f"{stem}-{get_slot()}.log"


def write_logging_config(target_dir: str) -> str:
    """Writes a copy of the unittest logging configuration that logs to this slot's own file.

    The file handler keeps logging into data/logs, which is deliberately outside the data
    directory the suite wipes before every integration test. Returns the path written."""
    with open(os.path.join(get_project_root(), LOGGING_CONFIG_PATH), "r") as fp:
        logging_config = yaml.safe_load(fp)

    file_handler = logging_config["handlers"]["file"]
    file_handler["log_dir"] = LOG_DIR
    file_handler["filename_format"] = get_log_file_name("unittest")

    # CustomFileHandler opens the file without creating the directory
    os.makedirs(os.path.join(get_project_root(), LOG_DIR), exist_ok=True)

    target_path = os.path.join(target_dir, "unittest_logging.yaml")
    with open(target_path, "w") as fp:
        yaml.safe_dump(logging_config, fp, default_flow_style=False)

    return target_path
