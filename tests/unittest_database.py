# vim: sw=4:ts=4:et
#
# per-session unittest databases
#
# every pytest session gets its own brand new set of ACE databases (ace, brocess, email
# archive and analysis result cache), created empty, migrated to the head of each alembic
# chain, seeded with the handful of reference rows the suite expects to already exist, and
# dropped again when the session ends. the names carry a random token
# (ace-unittest-1f2e3d4c, brocess-unittest-1f2e3d4c, ...) so that concurrent sessions --
# the pytest-xdist workers this is groundwork for -- never share a database.
#
# the config is pointed at them through SAQ_UNITTEST_CONFIG_PATHS: an overlay YAML file
# that the loader merges right after etc/saq.unittest.default.yaml (see
# saq/configuration/loader.py). it has to be an overlay because everything else the loader
# accepts is merged *before* the unittest defaults and would be overridden by them.
#
# leaks: a session that dies without cleaning up (SIGKILL, container went away) leaves its
# databases behind. every session records what it created in $SAQ_HOME/.pytest-databases/
# *before* creating anything, and the next session drops whatever it finds there that is not
# its own. that is safe because sessions are serialized by tests/session_lock.py: while
# this session holds .pytest-running no other session sharing this checkout can be alive,
# so every other registry entry belongs to a dead one. bin/cleanup-unittest-databases.py
# does the same thing from outside a session.
#
# all of the administrative work here (CREATE/DROP DATABASE, GRANT, migrations) runs as the
# database superuser -- see saq/database/admin.py for where those credentials come from.
# the tests themselves keep connecting as the ordinary ace-user, with the same DML-only
# grants it has in production, so that the suite runs with production privileges.
#

import datetime
import json
import logging
import os
import socket
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from typing import Optional

import pymysql
import yaml
from sqlalchemy.orm.session import close_all_sessions

from saq.database import pool
from saq.database.admin import get_database_host, superuser_connection
from saq.database.seed import seed_unittest

REGISTRY_DIRNAME = ".pytest-databases"
OVERLAY_ENV_VAR = "SAQ_UNITTEST_CONFIG_PATHS"
UNITTEST_CONFIG_PATH = os.path.join("etc", "saq.unittest.default.yaml")
UPGRADE_SCRIPT = os.path.join("bin", "upgrade_databases.py")

# how long a DROP DATABASE is allowed to wait for a metadata lock before we start killing
# the connections that hold it. the server default is a year.
LOCK_WAIT_TIMEOUT = 15
UPGRADE_TIMEOUT = 600

GRANT_PRIVILEGES = "SELECT, INSERT, UPDATE, DELETE"
DATABASE_CHARSET = "utf8mb4"
DATABASE_COLLATION = "utf8mb4_unicode_520_ci"

# the config sections we provision, and the option bin/upgrade_databases.py takes for each
DATABASE_SECTIONS: dict[str, str] = {
    "database_ace": "--ace",
    "database_brocess": "--brocess",
    "database_email_archive": "--email-archive",
    "database_analysis_result_cache": "--cache",
}

# every provisioned name looks like <base>-<8 hex chars>. this is the SQL LIKE pattern for
# that (exactly eight single-character wildcards), used to find orphans without ever
# matching the static ace-unittest / ace-unittest-2 / amc-unittest databases.
ORPHAN_LIKE_PATTERN = "%-unittest-________"

MYSQL_ER_LOCK_WAIT_TIMEOUT = 1205


class UnittestDatabaseError(Exception):
    """Raised when the per-session databases cannot be provisioned or dropped."""
    pass


@dataclass
class ProvisionedDatabases:
    """What one pytest session created."""
    token: str
    # config section (database_ace, ...) -> actual database name (ace-unittest-<token>)
    databases: dict[str, str]
    # the ordinary database user that is granted access to them
    grantee: str
    registry_path: str
    overlay_path: str
    # set once the overlay has been written and SAQ_UNITTEST_CONFIG_PATHS points at it
    active: bool = field(default=False)

    @property
    def names(self) -> list[str]:
        return list(self.databases.values())

    @property
    def ace_database(self) -> str:
        return self.databases["database_ace"]


# what this process provisioned, if anything. kept here as well as on disk so that
# drop_current() still works if the registry directory was deleted out from under us.
_CURRENT: Optional[ProvisionedDatabases] = None


def get_project_root() -> str:
    return os.environ.get("SAQ_HOME", os.getcwd())


def get_registry_dir() -> str:
    """Returns the directory the registry records live in, creating it if needed.

    Deliberately outside of data_unittest/ -- that directory is deleted before every
    integration test."""
    path = os.path.join(get_project_root(), REGISTRY_DIRNAME)
    os.makedirs(path, exist_ok=True)
    return path


def get_current() -> Optional[ProvisionedDatabases]:
    return _CURRENT


def generate_token() -> str:
    return uuid.uuid4().hex[:8]


def _load_unittest_database_settings() -> dict[str, dict[str, str]]:
    """Reads the database sections of etc/saq.unittest.default.yaml.

    Returns section -> {"database": base name, "username": grantee}. This is read as plain
    YAML because provisioning has to happen before the configuration is loaded: the
    configuration is what gets pointed at the result."""
    path = os.path.join(get_project_root(), UNITTEST_CONFIG_PATH)
    with open(path, "r") as fp:
        raw = yaml.safe_load(fp)

    result = {}
    for section in DATABASE_SECTIONS:
        settings = raw.get(section)
        if not isinstance(settings, dict) or not settings.get("database") or not settings.get("username"):
            raise UnittestDatabaseError(f"{path} is missing the database or username setting in the {section} section")

        result[section] = {"database": settings["database"], "username": settings["username"]}

    usernames = {settings["username"] for settings in result.values()}
    if len(usernames) != 1:
        raise UnittestDatabaseError(f"{path} uses more than one database username ({', '.join(sorted(usernames))}); expected one")

    return result


def _registry_paths(token: str) -> tuple[str, str]:
    registry_dir = get_registry_dir()
    return os.path.join(registry_dir, f"{token}.json"), os.path.join(registry_dir, f"{token}.yaml")


def _write_registry_record(provisioned: ProvisionedDatabases) -> None:
    with open(provisioned.registry_path, "w") as fp:
        json.dump({
            "token": provisioned.token,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "started": datetime.datetime.now().isoformat(),
            "argv": sys.argv,
            "grantee": provisioned.grantee,
            "databases": provisioned.databases,
        }, fp, indent=4)


def _write_overlay(provisioned: ProvisionedDatabases) -> None:
    overlay = {section: {"database": name} for section, name in provisioned.databases.items()}
    with open(provisioned.overlay_path, "w") as fp:
        yaml.safe_dump(overlay, fp, default_flow_style=False)


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _grantee_hosts(cursor, grantee: str) -> list[str]:
    """Returns every host the grantee account exists for.

    MySQL refuses a GRANT to a user@host that does not exist, so the host part cannot be
    assumed to be '%'."""
    cursor.execute("SELECT host FROM mysql.user WHERE user = %s", (grantee,))
    return [row[0] for row in cursor.fetchall()]


def _create_databases(provisioned: ProvisionedDatabases) -> None:
    with superuser_connection() as db:
        cursor = db.cursor()
        hosts = _grantee_hosts(cursor, provisioned.grantee)
        if not hosts:
            raise UnittestDatabaseError(f"database user {provisioned.grantee} does not exist on {get_database_host()}")

        for name in provisioned.names:
            cursor.execute(f"CREATE DATABASE `{name}` CHARACTER SET {DATABASE_CHARSET} COLLATE {DATABASE_COLLATION}")
            for host in hosts:
                cursor.execute(f"GRANT {GRANT_PRIVILEGES} ON `{name}`.* TO %s@%s", (provisioned.grantee, host))

        cursor.execute("FLUSH PRIVILEGES")


def _upgrade_databases(provisioned: ProvisionedDatabases) -> None:
    """Migrates every provisioned database to the head of its alembic chain.

    This runs in a subprocess because the repository's alembic/ directory shadows the
    installed alembic package for any process with the project root on sys.path, which
    pytest is. bin/upgrade_databases.py does all four chains in one interpreter."""
    project_root = get_project_root()
    command = [sys.executable, os.path.join(project_root, UPGRADE_SCRIPT)]
    for section, option in DATABASE_SECTIONS.items():
        command.extend([option, provisioned.databases[section]])

    result = subprocess.run(command, cwd=project_root, capture_output=True, text=True, timeout=UPGRADE_TIMEOUT)
    if result.returncode != 0:
        raise UnittestDatabaseError(
            f"database migration failed (exit code {result.returncode}):\n"
            f"command: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}")

    logging.debug("database migration output: %s", result.stdout)


def provision() -> ProvisionedDatabases:
    """Creates, migrates and seeds a fresh set of databases and points the config at them.

    Must be called while the session lock (tests/session_lock.py) is held and before
    initialize_environment(): the configuration, connection pools and SQLAlchemy engines all
    read the database names on first use and cache them. Raises UnittestDatabaseError with
    an explanation of what is required if it cannot be done; nothing is left behind in
    that case."""
    global _CURRENT

    if _CURRENT is not None:
        raise UnittestDatabaseError(f"unittest databases already provisioned (token {_CURRENT.token})")

    # anything a previous session left behind goes first
    sweep_stale()

    settings = _load_unittest_database_settings()
    token = generate_token()
    registry_path, overlay_path = _registry_paths(token)

    provisioned = ProvisionedDatabases(
        token=token,
        databases={section: f"{values['database']}-{token}" for section, values in settings.items()},
        grantee=next(iter(settings.values()))["username"],
        registry_path=registry_path,
        overlay_path=overlay_path)

    # the record goes on disk before the first CREATE DATABASE so that a session killed at
    # any point after this is still cleaned up by the next one
    _write_registry_record(provisioned)
    _CURRENT = provisioned

    try:
        logging.info("provisioning unittest databases %s", ", ".join(provisioned.names))
        _create_databases(provisioned)
        _upgrade_databases(provisioned)
        seed_unittest(provisioned.ace_database)
        _write_overlay(provisioned)
        os.environ[OVERLAY_ENV_VAR] = provisioned.overlay_path
        provisioned.active = True
    except Exception as e:
        try:
            drop_current()
        except Exception as drop_error:
            # the original error is the one worth reporting; whatever was created stays
            # recorded on disk for the next session (or the cleanup script) to drop
            logging.warning("unable to drop partially provisioned unittest databases: %s", drop_error)

        raise UnittestDatabaseError(
            f"unable to provision unittest databases on {get_database_host()}: {e}\n"
            "provisioning runs as the database superuser (see saq/database/admin.py): "
            "ACE_SUPERUSER_DB_USER_PASSWORD or /auth/passwords/ace-superuser must hold its "
            "password and ACE_DB_HOST must name the primary database server") from e

    return provisioned


def _close_local_connections() -> None:
    """Closes every database connection this process holds.

    DROP DATABASE waits for an exclusive metadata lock on every table in the schema, and
    any connection sitting in an open transaction that touched one holds a shared lock
    until it ends. So everything goes: the scoped sessions, the SQLAlchemy engines behind
    them, the async engine on the background loop and the raw pymysql pools."""
    pool.remove_all_sessions()
    close_all_sessions()

    # importing aceapi_v2 pulls the whole FastAPI application in through the package
    # __init__, so only shut the background loop down if something already started it
    sync_module = sys.modules.get("aceapi_v2.sync")
    if sync_module is not None:
        try:
            sync_module.shutdown_loop()
        except Exception as e:
            logging.warning("unable to shut down the aceapi_v2 background loop: %s", e)

    with pool._db_sessions_lock:
        engines = list(pool._db_engines)

    for engine in engines:
        try:
            engine.dispose()
        except Exception as e:
            logging.warning("unable to dispose database engine: %s", e)

    pool.reset_pools()


def _kill_connections(cursor, grantee: str, name: str) -> int:
    """Kills every connection the grantee has open to the given database. Returns how many."""
    cursor.execute(
        "SELECT PROCESSLIST_ID FROM performance_schema.threads "
        "WHERE PROCESSLIST_USER = %s AND PROCESSLIST_DB = %s AND PROCESSLIST_ID IS NOT NULL",
        (grantee, name))
    ids = [row[0] for row in cursor.fetchall()]
    for connection_id in ids:
        try:
            cursor.execute(f"KILL {int(connection_id)}")
        except pymysql.err.MySQLError as e:
            logging.debug("unable to kill connection %s: %s", connection_id, e)

    return len(ids)


def _drop_databases(names: list[str], grantee: Optional[str]) -> None:
    """Revokes the grantee's access to and drops each of the given databases.

    DROP DATABASE does not remove grant rows, so the REVOKE has to be explicit. A DROP that
    times out on a metadata lock kills the grantee's connections to that database and tries
    once more."""
    with superuser_connection() as db:
        cursor = db.cursor()
        cursor.execute(f"SET SESSION lock_wait_timeout = {LOCK_WAIT_TIMEOUT}")
        hosts = _grantee_hosts(cursor, grantee) if grantee else []

        for name in names:
            for host in hosts:
                try:
                    cursor.execute(f"REVOKE {GRANT_PRIVILEGES} ON `{name}`.* FROM %s@%s", (grantee, host))
                except pymysql.err.MySQLError as e:
                    # nothing was granted (provisioning died early) -- fine
                    logging.debug("unable to revoke %s on %s: %s", grantee, name, e)

            try:
                cursor.execute(f"DROP DATABASE IF EXISTS `{name}`")
            except pymysql.err.OperationalError as e:
                if e.args[0] != MYSQL_ER_LOCK_WAIT_TIMEOUT or not grantee:
                    raise

                killed = _kill_connections(cursor, grantee, name)
                logging.warning("DROP DATABASE %s timed out waiting for a lock; killed %s connection(s) and retrying", name, killed)
                cursor.execute(f"DROP DATABASE IF EXISTS `{name}`")

            logging.info("dropped unittest database %s", name)

        if hosts:
            cursor.execute("FLUSH PRIVILEGES")


def drop_current() -> None:
    """Drops whatever this process provisioned. Safe to call more than once."""
    global _CURRENT

    provisioned = _CURRENT
    if provisioned is None:
        return

    try:
        _close_local_connections()
        _drop_databases(provisioned.names, provisioned.grantee)
    except Exception:
        # the registry record only goes away once the databases are gone: the next session
        # (or bin/cleanup-unittest-databases.py) needs to find it
        logging.warning("unable to drop unittest databases %s; leaving %s in place for the next session",
                        ", ".join(provisioned.names), provisioned.registry_path)
        raise
    finally:
        _CURRENT = None
        if provisioned.active and os.environ.get(OVERLAY_ENV_VAR) == provisioned.overlay_path:
            del os.environ[OVERLAY_ENV_VAR]

    _remove_quietly(provisioned.overlay_path)
    _remove_quietly(provisioned.registry_path)


def _read_registry_record(path: str) -> Optional[dict]:
    """Returns the registry record at the given path, or None if it cannot be read.

    A session can be killed part way through writing it, so anything here can fail."""
    try:
        with open(path, "r") as fp:
            record = json.load(fp)
    except (OSError, ValueError):
        return None

    if not isinstance(record, dict) or not isinstance(record.get("databases"), dict):
        return None

    return record


def list_registered() -> list[dict]:
    """Returns every registry record on disk (with the path it was read from as "path")."""
    registry_dir = get_registry_dir()
    result = []
    for file_name in sorted(os.listdir(registry_dir)):
        if not file_name.endswith(".json"):
            continue

        path = os.path.join(registry_dir, file_name)
        record = _read_registry_record(path)
        if record is None:
            logging.warning("unreadable unittest database registry record %s (remove it by hand)", path)
            continue

        record["path"] = path
        result.append(record)

    return result


def drop_registered(record: dict) -> None:
    """Drops the databases named by a registry record and removes the record."""
    names = list(record["databases"].values())
    logging.warning("dropping unittest databases left behind by pid %s on %s (started %s): %s",
                    record.get("pid"), record.get("hostname"), record.get("started"), ", ".join(names))
    _drop_databases(names, record.get("grantee"))
    path = record["path"]
    _remove_quietly(path)
    _remove_quietly(os.path.splitext(path)[0] + ".yaml")


def sweep_stale() -> list[str]:
    """Drops every registered set of databases other than this process's own.

    Only call this while the session lock is held (provision() does): the lock is what
    makes every other registry entry provably stale. Returns the names dropped. A record
    that cannot be dropped is logged and left in place for the next attempt."""
    dropped = []
    for record in list_registered():
        if _CURRENT is not None and record.get("token") == _CURRENT.token:
            continue

        try:
            drop_registered(record)
            dropped.extend(record["databases"].values())
        except Exception as e:
            logging.error("unable to drop stale unittest databases recorded in %s: %s", record["path"], e)

    return dropped


def find_orphans() -> list[tuple[str, int]]:
    """Returns (name, live connection count) for every database that looks like one of
    ours but has no registry record.

    A registry record can be deleted by hand, and a second checkout of the repository
    pointed at the same server keeps its own registry that this one cannot see -- which
    is what the connection count is for."""
    registered = set()
    for record in list_registered():
        registered.update(record["databases"].values())

    with superuser_connection() as db:
        cursor = db.cursor()
        cursor.execute("SHOW DATABASES LIKE %s", (ORPHAN_LIKE_PATTERN,))
        candidates = [row[0] for row in cursor.fetchall() if row[0] not in registered]

        result = []
        for name in candidates:
            cursor.execute("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_DB = %s", (name,))
            result.append((name, int(cursor.fetchone()[0])))

    return result
