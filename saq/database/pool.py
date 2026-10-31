import collections
from contextlib import contextmanager
from datetime import datetime
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Callable
import warnings
import weakref

import pymysql

from saq.configuration.config import get_config
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DB_POOL_AVAILABLE_COUNT, MONITOR_DB_POOL_IN_USE_COUNT, MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path, create_timedelta

if TYPE_CHECKING:
    from sqlalchemy import Engine
    from sqlalchemy.orm.scoping import scoped_session

# SQLAlchemy is imported only where an engine or a session is built: every process imports this module for its
# raw connections (node registration, the email archive), and only the ones that query through the ORM need it

# every pool in this module, the SQLAlchemy engines' and the raw one, keeps POOL_SIZE idle connections for reuse
# and closes the rest as they come back. a SQLAlchemy engine makes a caller wait once POOL_SIZE + POOL_MAX_OVERFLOW
# are checked out; the raw pool opens more past that point, because callers nest get_db_connection() and would
# deadlock waiting on themselves, and warns instead.
# the raw pool opens a connection only when every open one is checked out, and retires each one max_connection_lifetime
# after it opened it, so it holds no more than the most it had in use over that time. it logs that number once
# per max_connection_lifetime (_database_pool._rotate_window), which is what to look at before changing POOL_SIZE
POOL_SIZE = 5
POOL_MAX_OVERFLOW = 10

# registry of SQLAlchemy ORM scoped sessions keyed by database config name, each created
# (with its own engine) on its first get_db() request
_db_sessions: dict[str, "scoped_session"] = {}
_db_sessions_lock = threading.RLock()

# every SQLAlchemy engine this module creates, so that reset_database_after_fork() can
# find them all. guarded by _db_sessions_lock along with _db_sessions
_db_engines: set["Engine"] = set()

# every DBAPI connection opened in this process, tagged with the pid that opened it, so
# that a forked child can neutralise the ones it inherited before anything touches them.
# a WeakSet, so tracking a connection never keeps it alive
_tracked_connections: weakref.WeakSet = weakref.WeakSet()
# an RLock: _before_fork() already holds it when reset_database_after_fork() re-takes it
_tracked_connections_lock = threading.RLock()

def _track_connection(connection):
    """Records a newly opened DBAPI connection and the pid that opened it."""
    try:
        connection._ace_pid = os.getpid()
        with _tracked_connections_lock:
            _tracked_connections.add(connection)
    except Exception as e:
        logging.debug("unable to track database connection: %s", e)

def get_db(name: str = "ace") -> "scoped_session":
    """returns the SQLAlchemy scoped session for the named database

    get_db() with no argument returns the "ace" session
    sessions are created lazily (each with its own engine) on first request."""
    if name is None:
        name = "ace"

    with _db_sessions_lock:
        session = _db_sessions.get(name)
        if session is not None:
            return session

        session = _db_sessions[name] = _new_session(_create_engine_for(name))
        logging.debug("created new scoped session for database %s", name)
        return session

def _new_session(engine) -> "scoped_session":
    from sqlalchemy.orm.scoping import scoped_session
    from sqlalchemy.orm.session import sessionmaker

    return scoped_session(sessionmaker(bind=engine))

def _log_pool_issue(message: str, e: Exception):
    """Log a connection-pool problem at a level that matches whether we expected it.

    While shutting down these are routine -- the database container is stopping at the
    same time as this one, so every pooled connection fails to roll back on its way out.
    remove_all_sessions() runs in the finally of most of ACE's hot loops, so at WARNING
    this produced several lines per connection per loop iteration per process, which is a
    large part of what made shutdown look like a failure.
    """
    from saq.shutdown import is_shutting_down

    if is_shutting_down():
        logging.debug("%s (shutting down): %s", message, e)
    else:
        logging.warning("%s: %s", message, e)


def remove_all_sessions():
    """remove() every registered scoped session

    Call at request/loop boundaries so any partial transaction state on the
    thread-local session is discarded before the next unit of work.
    """
    with _db_sessions_lock:
        for name, session in list(_db_sessions.items()):
            if session is None:
                continue
            try:
                session.remove()
            except Exception as e:
                logging.warning("error removing %s session: %s", name, e)

class _database_pool:
    def __init__(self, name):
        # the name of the database this is a pool for
        self.name = name
        # all the database connections that are available
        self.available = collections.deque()
        # all the database connections that are currently in use
        self.in_use = collections.deque()
        # the thread and process that created the pool
        self.tid = threading.get_ident()
        self.pid = os.getpid()
        # lock used to make changes to the queues
        self.lock = threading.RLock()
        # the most connections this pool has had open at once past the soft cap, so that it warns once per new peak
        self.peak_over_cap = 0

        self.database_config = get_config().get_database_config(name)
        # how often the pool logs what it used: connections do not outlive this, so nor does what the pool holds
        self.window = create_timedelta(self.database_config.max_connection_lifetime)
        self._reset_window(datetime.now())

        kwargs: dict[str, Any] = {
            'database': self.database_config.database,
            'user': self.database_config.username,
            'password': self.database_config.password,
            'charset': 'utf8mb4',
        }

        if self.database_config.max_allowed_packet:
            kwargs['max_allowed_packet'] = self.database_config.max_allowed_packet

        if self.database_config.hostname:
            kwargs['host'] = self.database_config.hostname

        if self.database_config.port:
            kwargs['port'] = self.database_config.port

        if self.database_config.unix_socket:
            kwargs['unix_socket'] = self.database_config.unix_socket

        kwargs['init_command'] = 'SET NAMES utf8mb4'

        if self.database_config.ssl_ca or self.database_config.ssl_key or self.database_config.ssl_cert:
            kwargs['ssl'] = {}

            if self.database_config.ssl_ca:
                path = abs_path(self.database_config.ssl_ca)
                if not os.path.exists(path):
                    logging.error("ssl_ca file {} does not exist (specified in {})".format(path, self.database_config.name))
                else:
                    kwargs['ssl']['ca'] = path

            if self.database_config.ssl_key:
                path = abs_path(self.database_config.ssl_key)
                if not os.path.exists(path):
                    logging.error("ssl_key file {} does not exist (specified in {})".format(path, self.database_config.name))
                else:
                    kwargs['ssl']['key'] = path

            if self.database_config.ssl_cert:
                path = abs_path(self.database_config.ssl_cert)
                if not os.path.exists(path):
                    logging.error("ssl_cert file {} does not exist (specified in {})".format(path, self.database_config.name))
                else:
                    kwargs['ssl']['cert'] = path

        self.kwargs = kwargs

    def close(self):
        with self.lock:
            for connection in self.available:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            for connection in self.in_use:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            self.available.clear()
            self.in_use.clear()
            self.peak_over_cap = 0
            self._reset_window(datetime.now())
            self.emit_monitors()

    def _reset_window(self, now: datetime):
        """Starts counting what the pool uses over the next window. Called with the lock held."""
        self.window_start = now
        self.window_peak = len(self.in_use)
        self.checkouts = 0
        self.opened = 0
        self.closed_expired = 0
        self.closed_idle = 0
        self.closed_broken = 0

    def _rotate_window(self, now: datetime):
        """Logs what the pool used over the window that has ended, if it has, and starts the next one. Checked on
        every checkout and return rather than by a thread, so a pool nobody uses logs nothing. Called with the lock
        held."""
        if now - self.window_start < self.window:
            return

        summary = {
            "database": self.name,
            "window_seconds": int((now - self.window_start).total_seconds()),
            "peak_in_use": self.window_peak,
            "idle": len(self.available),
            "checkouts": self.checkouts,
            "opened": self.opened,
            "closed_expired": self.closed_expired,
            "closed_idle": self.closed_idle,
            "closed_broken": self.closed_broken,
        }
        self._reset_window(now)
        logging.info(
            f"database pool {self.name} in pid {self.pid} over the last {summary['window_seconds']}s: "
            f"at most {summary['peak_in_use']} connections in use, {summary['idle']} idle now, "
            f"{summary['checkouts']} checkouts, {summary['opened']} opened, "
            f"{summary['closed_expired']} closed past their lifetime, {summary['closed_idle']} closed as idle, "
            f"{summary['closed_broken']} closed as broken",
            extra=summary)

    def get_connection(self):
        connection = None
        with self.lock:
            self._rotate_window(datetime.now())
            self.checkouts += 1
            try:
                connection = self.available.pop()

                # 8/5/2022 
                # make sure the connection is good before we move forward

                try:
                    connection.rollback()
                except Exception as e:
                    # if we can't rollback then toss this connection and get a new one
                    _log_pool_issue("unable to rollback connection on get_connection", e)
                    self.close_connection(connection)
                    self.closed_broken += 1
                    connection = self.open_new_connection()

                # drop old connections
                if datetime.now() >= connection.termination_date: # termination_date is a property we add in open_new_connection()
                    logging.info(f"terminating old connection {connection}")
                    self.close_connection(connection)
                    self.closed_expired += 1
                    connection = self.open_new_connection()
            except IndexError:
                connection = self.open_new_connection()

            self.in_use.append(connection)
            self.window_peak = max(self.window_peak, len(self.in_use))
            connection.acquired = datetime.now()
            self._warn_past_soft_cap()
            self.emit_monitors()

        return connection

    def _warn_past_soft_cap(self):
        """Warns when the pool has more connections open than a SQLAlchemy engine would allow, once per new peak.
        The connection is opened anyway (see POOL_MAX_OVERFLOW). Called with the lock held."""
        soft_cap = POOL_SIZE + POOL_MAX_OVERFLOW
        open_connections = len(self.in_use) + len(self.available)
        if open_connections > max(soft_cap, self.peak_over_cap):
            self.peak_over_cap = open_connections
            logging.warning(
                f"{open_connections} connections open to database {self.name} in pid {self.pid}, "
                f"past the soft cap of {soft_cap}",
                extra={"database": self.name, "open_connections": open_connections, "soft_cap": soft_cap})

    def return_connection(self, connection):
        if connection is None:
            return

        try:
            connection.rollback()
        except Exception as e:
            _log_pool_issue(f"unable to rollback connection {connection} on return to pool", e)
            self.destroy_connection(connection)
            return

        now = datetime.now()
        with self.lock:
            self._rotate_window(now)
            self.in_use.remove(connection)
            self.available.append(connection)
            # the pool reuses the connection returned last, so one under it is never checked out for get_connection()
            # to retire: every expired one is retired here, and only POOL_SIZE are kept
            expired = [c for c in self.available if now >= c.termination_date]
            for c in expired:
                self.available.remove(c)
            excess = []
            while len(self.available) > POOL_SIZE:
                excess.append(self.available.popleft())
            self.closed_expired += len(expired)
            self.closed_idle += len(excess)
            self.emit_monitors()

        # outside the lock, because closing a connection writes to the server
        for c in expired:
            logging.info(f"terminating old connection {c}")
            self.close_connection(c)

        if excess:
            logging.debug(f"closing {len(excess)} idle connections to {self.name} past the pool size of {POOL_SIZE}")
            for c in excess:
                self.close_connection(c)

    def close_connection(self, connection):
        try:
            connection.close()
        except Exception as e:
            logging.warning(f"unable to close database connection: {e} connection {connection}")

    def destroy_connection(self, connection):
        self.close_connection(connection)

        with self.lock:
            try:
                self.in_use.remove(connection)
                self.closed_broken += 1
                self.emit_monitors()
            except ValueError:
                logging.warning(f"attempted to remove missing database connection {connection}")

    def open_new_connection(self):
        connection = pymysql.connect(**self.kwargs)
        _track_connection(connection)
        cursor = connection.cursor()
        cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
        cursor.close()
        connection.commit()
        # get_connection() opens connections, with the lock held
        self.opened += 1

        # keep track of when this connection should be invalidated
        setattr(connection,
                'termination_date',
                datetime.now() + create_timedelta(self.database_config.max_connection_lifetime))

        logging.debug(f"got new database connection to {self.name} ({len(self.in_use)} existing connections)")
        return connection

    def start(self):
        pass

    def stop(self):
        """Close every connection this pool owns.

        Called on the way out so the database sees connections closed rather than
        dropped. A connection that is merely abandoned leaves its transaction open on
        the server until the server times it out, which is what left locks and row
        locks lingering after a node went away.
        """
        self.clear()

    def clear(self):
        with self.lock:
            for c in self.available:
                try:
                    c.close()
                except Exception as e:
                    _log_pool_issue("unable to close database connection", e)

            self.available.clear()

            for c in self.in_use:
                try:
                    c.close()
                except Exception as e:
                    _log_pool_issue("unable to close database connection", e)

            self.in_use.clear()
            self.peak_over_cap = 0
            self._reset_window(datetime.now())
            self.emit_monitors()

    @property
    def available_count(self):
        with self.lock:
            return len(self.available)

    @property
    def in_use_count(self):
        with self.lock:
            return len(self.in_use)

    def emit_monitors(self):
        emit_monitor(MONITOR_DB_POOL_AVAILABLE_COUNT, self.available_count)
        emit_monitor(MONITOR_DB_POOL_IN_USE_COUNT, self.in_use_count)

# the global queue of database connections available for use
_global_db_pools = {} # key = database name, value = _database_pool
_global_db_pools_lock = threading.RLock()

def get_pool(name='ace'):
    if name is None:
        name = 'ace'

    with _global_db_pools_lock:
        try:
            result = _global_db_pools[name]
        except KeyError:
            result =_global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name}")

        # if the pool was created on another process then we just creat another pool to use
        # and ignore the old one (which may be used by the previous process)
        if result.pid != os.getpid():
            result.close() # closes the sockets without killing the database connections
            result = _global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name} under pid {result.pid}")

        return result

def reset_pools():
    for name, pool in _global_db_pools.items():
        pool.clear()

    _global_db_pools.clear()

@contextmanager
def get_db_connection(name='ace'):
    if name is None:
        name = 'ace'

    connection = None
    try:
        connection = get_pool(name).get_connection()
        yield connection
    finally:
        get_pool(name).return_connection(connection)

def execute_with_db_cursor(db_name: str, target: Callable, *args, **kwargs):
    """Execute the given target function with a database connection and cursor.
    The target is called with any additional parameters passed in."""
    with get_db_connection(name=db_name) as db:
        cursor = db.cursor()
        return target(db, cursor, *args, **kwargs)

def _attach_engine_listeners(engine):
    """attaches the pool-monitoring and fork-safety event listeners to an engine

    the checkout listener's pid check is the backstop that keeps a connection record
    created in a parent process from being reused after a fork. it is only a backstop:
    it cannot see a connection that was already checked out when the fork happened, and
    pool_pre_ping writes to the socket before it ever runs. reset_database_after_fork()
    is what actually keeps the two processes apart."""
    from sqlalchemy import event
    from sqlalchemy.exc import DisconnectionError

    with _db_sessions_lock:
        _db_engines.add(engine)
        register_sql_timing_listeners()

    @event.listens_for(engine, 'connect')
    def connect(dbapi_connection, connection_record):
        connection_record.info['pid'] = os.getpid()
        _track_connection(dbapi_connection)

    @event.listens_for(engine, 'checkin')
    def checkin(dbapi_connection, connection_record):
        emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, engine.pool.status())

    @event.listens_for(engine, 'checkout')
    def checkout(dbapi_connection, connection_record, connection_proxy):
        emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, engine.pool.status())

        pid = os.getpid()
        if connection_record.info['pid'] != pid:
            connection_record.dbapi_connection = connection_proxy.dbapi_connection = None
            message = f"connection record belongs to pid {connection_record.info['pid']} attempting to check out in pid {pid}"
            logging.debug(message)
            raise DisconnectionError(message)


def _log_sql_exec_times() -> bool:
    """Whether query timing is enabled.

    These listeners are registered on the Engine class, so they fire for *every* engine in
    the process, including ones created before the configuration is loaded (the test suite
    seeds its per-session databases that way). No configuration means no timing."""
    config = get_config()
    return config is not None and config.global_settings.log_sql_exec_times


def register_sql_timing_listeners():
    """Registers the query timing listeners on the Engine class, once per process.

    Called for every engine ACE builds (here, and the API's async engines in aceapi_v2.database) rather
    than when this module is imported, which would import SQLAlchemy into every process."""
    from sqlalchemy import Engine, event

    with _db_sessions_lock:
        if not event.contains(Engine, "before_cursor_execute", _before_cursor_execute):
            event.listen(Engine, "before_cursor_execute", _before_cursor_execute)
            event.listen(Engine, "after_cursor_execute", _after_cursor_execute)


def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if _log_sql_exec_times():
        context._query_start_time = time.time()
        logging.debug("START QUERY {} ({})".format(statement, parameters))


def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if _log_sql_exec_times():
        total = time.time() - context._query_start_time
        logging.debug("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))


def _build_database_url(database_config) -> str:
    """builds a SQLAlchemy connection URL for the given database config"""
    if database_config.unix_socket:
        return "mysql+pymysql://{username}:{password}@localhost/{database}?unix_socket={unix_socket}&charset=utf8mb4".format(
            username=database_config.username,
            password=database_config.password,
            unix_socket=database_config.unix_socket,
            database=database_config.database)

    return "mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}?charset=utf8mb4".format(
        username=database_config.username,
        password=database_config.password,
        hostname=database_config.hostname,
        port=database_config.port,
        database=database_config.database)


def _build_engine_options(database_config) -> dict:
    """builds the create_engine kwargs for the given database config"""
    options: dict[str, Any] = {
        "pool_recycle": 60 * 10,  # 10 minute connection pool recycle
        "pool_timeout": 30,
        "pool_size": POOL_SIZE,
        "max_overflow": POOL_MAX_OVERFLOW,
        "connect_args": {"init_command": "SET NAMES utf8mb4"},
        "pool_pre_ping": True,
    }

    if database_config.max_allowed_packet:
        options["connect_args"]["max_allowed_packet"] = database_config.max_allowed_packet

    if not database_config.unix_socket:
        if database_config.ssl_ca or database_config.ssl_cert or database_config.ssl_key:
            ssl_options = {}
            if database_config.ssl_ca:
                ssl_options["ca"] = abs_path(database_config.ssl_ca)
            if database_config.ssl_cert:
                ssl_options["cert"] = abs_path(database_config.ssl_cert)
            if database_config.ssl_key:
                ssl_options["key"] = abs_path(database_config.ssl_key)
            options["connect_args"]["ssl"] = ssl_options

    return options


def _create_engine_for(name: str):
    """creates a SQLAlchemy engine for the named database config"""
    from sqlalchemy import create_engine

    database_config = get_config().get_database_config(name)
    engine = create_engine(
        _build_database_url(database_config),
        isolation_level="READ COMMITTED",
        **_build_engine_options(database_config))
    _attach_engine_listeners(engine)
    return engine


def initialize_database():
    """Prepares the database connections. get_db() creates the "ace" session on first use: building it
    imports SQLAlchemy, which a process that never queries through the ORM does not need."""

    # see https://github.com/PyMySQL/PyMySQL/issues/644
    # /usr/local/lib/python3.6/dist-packages/pymysql/cursors.py:170: Warning: (1300, "Invalid utf8mb4 character string: '800363'")
    warnings.filterwarnings(action='ignore', message='.*Invalid utf8mb4 character string.*')

    with _db_sessions_lock:
        if "ace" in _db_sessions:
            # if you call this a second time it just closes all the sessions
            # this (currently) happens in unit testing
            from sqlalchemy.orm.session import close_all_sessions
            close_all_sessions()

# ----------------------------------------------------------------------
# fork safety
# ----------------------------------------------------------------------

# the sockets and read buffers taken off inherited connections in a forked child, kept for the life of
# the process so that nothing inherited is ever freed there: freeing a read buffer closes it, and freeing
# a TLS socket that was never shut down has OpenSSL take its context's lock (see reset_database_after_fork)
_abandoned_after_fork = []


def _write_stderr(message: str):
    # os.write, not sys.stderr: a thread that does not exist in a forked child can hold its buffer lock
    try:
        os.write(2, message.encode(errors="replace"))
    except OSError:
        pass  # there is nowhere left to say it


def reset_database_after_fork():
    """Drop every database connection inherited from the parent process.

    ACE_MP_CONTEXT is the fork context, so a child starts life holding open copies of
    the parent's MySQL sockets. If it uses one, both processes end up reading and
    writing the same TLS stream and the record layer desynchronises -- which surfaces in
    whichever process touches it next as::

        [SSL: RECORD_LAYER_FAILURE] ... Lost connection to MySQL server during query

    The checkout listener in _attach_engine_listeners() is not enough on its own. It
    fires on checkout, and by then the socket has already been written to: pool_pre_ping
    pings the inherited connection first, and a scoped_session is keyed by thread ident,
    which a forked child's main thread inherits -- so a session that held an open
    transaction across the fork hands the child a connection that was never checked out
    in it at all.

    Nothing here sends a byte to the server, and that is the whole point. A graceful
    close writes COM_QUIT, and a checkin writes a ROLLBACK, down a connection the parent
    is still using -- which is the damage this exists to prevent. So:

    Each inherited connection is left the way _force_close() leaves one, with no socket and
    no read buffer, and this process's copy of the socket's file descriptor is closed. That
    is all: the parent still holds its own descriptor for the same socket, so the connection
    stays up and the server is told nothing. This is the same reasoning _database_pool.close()
    already documents. It has to happen first, before the connections become unreachable, so
    that a close on the way out (garbage collection, or invalidating the record) is a no-op.

    engine.dispose(close=False) is then SQLAlchemy's documented after-fork call: it swaps
    in a fresh pool and abandons the inherited one rather than closing it. The abandoned pool
    is then set not to reset what is checked in to it. A connection that was checked out at
    the fork (a session holding an open transaction) is checked in to it when the child
    garbage collects it, and SQLAlchemy's _finalize_fairy would reset it with a ROLLBACK.
    pymysql refuses that before writing a byte, since there is no socket, but SQLAlchemy logs
    it at ERROR ("Exception during reset or similar"), which reads as a database failure.
    registry.clear() drops the inherited Session objects the same way -- unlike
    remove_all_sessions(), which calls Session.close() and would check a connection back
    into the pool with a rollback on the way.

    Nothing here may use the logging module either, which is why the diagnostics below go
    straight to file descriptor 2. os.register_at_fork child handlers run inside os.fork(), before
    multiprocessing's _bootstrap calls util._run_after_forkers() -- so at this point every
    fork-aware thread-local still holds the object the child inherited from the parent. A
    root handler that talks to another process is then used over the *parent's* connection:
    the unit test MemoryLogHandler writes every record into a SyncManager list, and two
    processes on one stream socket desynchronise it exactly the way two processes on one
    MySQL socket do. Both sides block forever on a reply that was never sent.

    This runs in every fork that runs Python in the child: os.fork(), the fork context
    ACE_MP_CONTEXT is, and a subprocess started with a preexec_fn, which forks the same way
    and runs this before it execs. Only the forking thread exists in that child, so nothing
    here may take a lock another thread of the parent can hold at the fork: that lock is never
    released, and the child waits for ever, before it ever execs. That rules out closing or
    freeing an inherited read buffer, whose lock a thread waiting for a query reply holds (the
    engine's lock keepalive thread is one every few seconds): _force_close() does both, and so
    does pymysql's __del__. A buffer whose lock is held stays referenced by the stack of the thread
    that held it, which the child keeps and never runs, but the sockets and buffers are also kept
    in _abandoned_after_fork, so that nothing inherited is freed here at all (freeing a TLS socket
    has OpenSSL take a lock as well), and the socket's descriptor is closed with os.close once
    detach() has taken it from the socket object. It also rules out writing through sys.stderr, whose buffer lock any thread
    writing to stderr holds. Other code that runs in such a child (other libraries' at-fork
    hooks, a preexec_fn itself) has the same problem, so a process that runs other threads
    still must not start a subprocess with a preexec_fn; `setpriv --pdeathsig` gives a
    parent-death signal without one (aceapi_v2/cli/service.py).
    """
    pid = os.getpid()

    with _tracked_connections_lock:
        inherited = [c for c in _tracked_connections if getattr(c, "_ace_pid", pid) != pid]
        for connection in inherited:
            _tracked_connections.discard(connection)

    for connection in inherited:
        try:
            sock, rfile = connection._sock, connection._rfile
            connection._sock = connection._rfile = None
            _abandoned_after_fork.append((sock, rfile))
            if sock is not None:
                os.close(sock.detach())
        except Exception as e:
            _write_stderr(f"WARNING: unable to close inherited connection after fork: {e}\n")

    for engine in list(_db_engines):
        try:
            # local, like every SQLAlchemy import here; an engine exists, so this only reads sys.modules
            from sqlalchemy.pool.base import reset_none

            inherited_pool = engine.pool
            engine.dispose(close=False)
            # only once it has been swapped out: recreate() copies this setting into the new pool, which must
            # keep rolling back. _ConnectionFairy._reset reads this private attribute; test_pool_fork.py pins it
            inherited_pool._reset_on_return = reset_none
        except Exception as e:
            _write_stderr(f"WARNING: unable to dispose inherited engine after fork: {e}\n")

    for name, session in list(_db_sessions.items()):
        if session is None:
            continue

        try:
            session.registry.clear()
        except Exception as e:
            _write_stderr(f"WARNING: unable to clear inherited {name} session after fork: {e}\n")

    # the raw pymysql pools go the same way. get_pool() would rebuild them lazily on its
    # own pid check, but dropping them here means an inherited connection is never even
    # a candidate.
    _global_db_pools.clear()

    _write_stderr(f"NOTICE: reset {len(inherited)} inherited database connections in pid {pid}\n")


def _before_fork():
    # take every registry lock across the fork. only the forking thread survives into the
    # child, so a lock another thread held at that moment would never be released there --
    # the child would deadlock on the first database call. holding them here means they are
    # ours to release on both sides.
    _db_sessions_lock.acquire()
    _global_db_pools_lock.acquire()
    _tracked_connections_lock.acquire()


def _release_fork_locks():
    _tracked_connections_lock.release()
    _global_db_pools_lock.release()
    _db_sessions_lock.release()


def _after_fork_in_parent():
    _release_fork_locks()


def _after_fork_in_child():
    try:
        reset_database_after_fork()
    finally:
        _release_fork_locks()


# registered once, at import, rather than called from each fork target. ACE forks the
# engine controller, every analysis worker and every search index worker, and a barrier
# that has to be remembered at the call site is one that eventually is not.
os.register_at_fork(
    before=_before_fork,
    after_in_parent=_after_fork_in_parent,
    after_in_child=_after_fork_in_child,
)
