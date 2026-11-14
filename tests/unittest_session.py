# vim: sw=4:ts=4:et
#
# per-process ("slot") identity for the test suite
#
# under pytest-xdist every worker is its own pytest session, and several things a session
# uses are host-wide: the data directory, the API server port, the network semaphore port,
# the Qdrant collections, the log file. each pytest process therefore gets a slot -- its xdist
# worker id (gw0, gw1, ...) or "main" when not running under xdist -- and everything
# per-process is derived from it here, together with what keeps one run's slots apart from
# another's: the checkout's path (data directory, Qdrant collections; the log file is inside
# the checkout) and the port block the run claimed (tests/session_lock.py). the values reach
# the configuration through the same SAQ_UNITTEST_CONFIG_PATHS overlay that
# tests/unittest_database.py writes for the per-session database names.
#
# this module deliberately imports nothing from saq: it runs before the configuration is
# loaded, and bin/cleanup-unittest-databases.py imports it from outside a session.
#

import hashlib
import os
import re
import select
import threading

import yaml

# not /tmp, which is a noexec tmpfs in the dev container
DATA_DIR_BASE = "/var/tmp/ace-unittest"
MAIN_SLOT = "main"
WORKER_ENV_VAR = "PYTEST_XDIST_WORKER"

API_BASE_PORT = 24443
NETWORK_SEMAPHORE_BASE_PORT = 53560

# a run's ports are base + block * PORT_BLOCK_SIZE + slot index, so PORT_BLOCK_SIZE is also the
# most xdist workers a run can have. 64 blocks keep the ports below 28539 and 57656.
PORT_BLOCK_SIZE = 64
PORT_BLOCK_COUNT = 64
# the block the run's controller claimed, inherited by its xdist workers
PORT_BLOCK_ENV_VAR = "ACE_UNITTEST_PORT_BLOCK"

LOG_DIR = os.path.join("data", "logs")
LOGGING_CONFIG_PATH = os.path.join("etc", "logging_configs", "unittest_logging.yaml")


def get_project_root() -> str:
    return os.environ.get("SAQ_HOME", os.getcwd())


def exit_with(pid: int) -> None:
    """Ends this process when process pid exits, however that process exits.

    The log collector's Manager server (tests/saq/helpers.py) runs this as its initializer, so
    that it does not outlive a pytest process that was SIGKILLed: no finalizer of that process
    runs to stop it, and an orphaned server keeps every record it holds. It is here rather than
    in tests/saq/helpers.py because the server, started by the forkserver, imports the module of
    its initializer, and this one imports nothing from saq."""
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        os._exit(1)

    def wait_for_exit():
        # bounded by the life of process pid: its pidfd turns readable when it exits
        select.select([pidfd], [], [])
        os._exit(0)

    threading.Thread(target=wait_for_exit, name=f"exit-with-{pid}", daemon=True).start()


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


def is_xdist_worker(config) -> bool:
    """True inside an xdist worker process (the controller and a plain pytest run are not)."""
    return hasattr(config, "workerinput")


def get_data_dir_root() -> str:
    """The directory that holds one data directory per slot.

    It is outside the checkout, in the container's own filesystem: the checkout is a bind
    mount from the host, where every mkdir and unlink is a round trip out of the VM, and the
    suite deletes and recreates a data directory before every integration test. One per
    checkout, named by a hash of its path, so two checkouts never share one."""
    return os.path.join(DATA_DIR_BASE, get_checkout_hash())


def get_checkout_hash() -> str:
    """Names what belongs to this checkout in resources other checkouts share."""
    checkout = os.path.realpath(get_project_root())
    return hashlib.sha256(checkout.encode()).hexdigest()[:12]


def get_session_data_dir() -> str:
    return os.path.join(get_data_dir_root(), get_slot())


def get_port_block() -> int:
    value = os.environ.get(PORT_BLOCK_ENV_VAR)
    if value is None:
        raise RuntimeError(f"{PORT_BLOCK_ENV_VAR} is not set: the run claims its port block in "
                           "pytest_configure (tests/session_lock.py), before its xdist workers start")

    return int(value)


def get_port_offset() -> int:
    index = get_slot_index()
    if index >= PORT_BLOCK_SIZE:
        raise ValueError(f"slot {get_slot()} does not fit in a port block of {PORT_BLOCK_SIZE} "
                         f"slots: run with at most {PORT_BLOCK_SIZE} xdist workers")

    return get_port_block() * PORT_BLOCK_SIZE + index


def get_api_port() -> int:
    return API_BASE_PORT + get_port_offset()


def get_network_semaphore_port() -> int:
    return NETWORK_SEMAPHORE_BASE_PORT + get_port_offset()


def session_overrides() -> dict:
    """The configuration overlay that makes this slot's host-wide resources its own.

    Paths are absolute: global.data_dir is only the fallback when initialize_environment() is
    not handed a data_dir, storage.base_dir is joined to SAQ_HOME by saq/storage/factory.py
    (which keeps an absolute path), and the network semaphore's stats_dir is used as-is by
    saq/network_semaphore/server.py."""
    slot = get_slot()
    data_dir = get_session_data_dir()
    api_port = get_api_port()
    semaphore_port = get_network_semaphore_port()

    return {
        "global": {"data_dir": data_dir},
        "storage": {"base_dir": os.path.join(data_dir, "storage")},
        "api": {"listen_port": api_port, "prefix": f"localhost:{api_port}"},
        "service_network_semaphore": {
            "bind_port": semaphore_port,
            "remote_port": semaphore_port,
            "stats_dir": os.path.join(data_dir, "var", "network_semaphore"),
        },
        # the stack's Qdrant is shared by every checkout
        "qdrant": {"collection_prefix": f"ace3-alerts-unittest-{get_checkout_hash()}-{slot}"},
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
