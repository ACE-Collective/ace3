from contextlib import contextmanager
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Callable
import warnings
import weakref

from saq.configuration.config import get_config
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DB_POOL_AVAILABLE_COUNT, MONITOR_DB_POOL_IN_USE_COUNT, MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path, create_timedelta

if TYPE_CHECKING:
    from sqlalchemy import URL, Engine
    from sqlalchemy.orm.scoping import scoped_session

# SQLAlchemy is imported only where an engine or a session is built, never when this module is. Cursor code
# builds the engine, which loads SQLAlchemy's core; only get_db() builds a session, which loads the ORM

# registry of SQLAlchemy ORM scoped sessions keyed by database config name, each created on
# its first get_db() request, over that database's engine in _db_engine_by_name
_db_sessions: dict[str, "scoped_session"] = {}
_db_sessions_lock = threading.RLock()

# every SQLAlchemy engine this module creates, so that reset_database_after_fork() can
# find them all. guarded by _db_sessions_lock along with _db_sessions
_db_engines: set["Engine"] = set()

# the engine for each database config name, behind both its session and get_db_connection(),
# so cursor code and the ORM share one bounded pool per database instead of each holding
# connections of its own
_db_engine_by_name: dict[str, "Engine"] = {}

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
    sessions are created lazily on first request, over the engine get_db_connection() uses."""
    if name is None:
        name = "ace"

    with _db_sessions_lock:
        session = _db_sessions.get(name)
        if session is not None:
            return session

        session = _db_sessions[name] = _new_session(_get_engine(name))
        logging.debug("created new scoped session for database %s", name)
        return session

def _new_session(engine) -> "scoped_session":
    from sqlalchemy.orm.scoping import scoped_session
    from sqlalchemy.orm.session import sessionmaker

    return scoped_session(sessionmaker(bind=engine))


class _QuietDuringShutdown(logging.Filter):
    """Drops a connection pool's errors to DEBUG while the process is shutting down.

    While shutting down these are routine -- the database container is stopping at the
    same time as this one, so every pooled connection fails to roll back on its way back
    into the pool, which SQLAlchemy logs at ERROR with a traceback ("Exception during reset
    or similar"). Every get_db_connection() and remove_all_sessions() in ACE's hot loops
    returns a connection, so this produced several lines per connection per loop iteration
    per process, which is a large part of what made shutdown look like a failure."""

    def filter(self, record: logging.LogRecord) -> bool:
        # local: saq.shutdown imports saq.environment, which imports this module
        from saq.shutdown import is_shutting_down

        if record.levelno > logging.DEBUG and is_shutting_down():
            record.msg = f"{record.getMessage()} (shutting down): {record.exc_info[1] if record.exc_info else ''}"
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.levelno = logging.DEBUG
            record.levelname = logging.getLevelName(logging.DEBUG)

        return True


# a logger's filters only see records logged on that logger itself, not ones propagated up
# from its children, so this goes on the logger QueuePool actually logs to
logging.getLogger("sqlalchemy.pool.impl.QueuePool").addFilter(_QuietDuringShutdown())


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

def _get_engine(name: str) -> "Engine":
    """The engine behind get_db(name)'s session and get_db_connection(name), created if nothing has asked
    for it yet. It does not build the session: cursor code alone never loads the ORM."""
    with _db_sessions_lock:
        engine = _db_engine_by_name.get(name)
        if engine is None:
            engine = _db_engine_by_name[name] = _create_engine_for(name)
        return engine


@contextmanager
def get_db_connection(name='ace'):
    """A raw DBAPI connection for cursor code, checked out of the same pool as get_db(name)'s
    session, so each process holds one bounded pool per database rather than two. Returning it
    rolls back whatever the caller left uncommitted."""
    if name is None:
        name = 'ace'

    connection = _get_engine(name).raw_connection()
    try:
        yield connection
    finally:
        connection.close()

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

    def emit_pool_monitors(returning: int = 0):
        emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, engine.pool.status())
        emit_monitor(MONITOR_DB_POOL_AVAILABLE_COUNT, engine.pool.checkedin() + returning)
        emit_monitor(MONITOR_DB_POOL_IN_USE_COUNT, engine.pool.checkedout() - returning)

    @event.listens_for(engine, 'connect')
    def connect(dbapi_connection, connection_record):
        connection_record.info['pid'] = os.getpid()
        _track_connection(dbapi_connection)

    @event.listens_for(engine, 'checkin')
    def checkin(dbapi_connection, connection_record):
        # checkin fires before the connection is back in the pool, and an idle process
        # reports whatever its last checkin said
        emit_pool_monitors(returning=1)

    @event.listens_for(engine, 'checkout')
    def checkout(dbapi_connection, connection_record, connection_proxy):
        emit_pool_monitors()

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


def _build_database_url(database_config) -> "URL":
    """builds a SQLAlchemy connection URL for the given database config

    URL.create() rather than a formatted string: a password with "@", "%" or "/" in it has to
    reach the server as written, as it did when cursor code passed it to pymysql directly."""
    from sqlalchemy import URL

    if database_config.unix_socket:
        return URL.create(
            "mysql+pymysql",
            username=database_config.username,
            password=database_config.password,
            host="localhost",
            database=database_config.database,
            query={"unix_socket": database_config.unix_socket, "charset": "utf8mb4"})

    return URL.create(
        "mysql+pymysql",
        username=database_config.username,
        password=database_config.password,
        host=database_config.hostname,
        port=database_config.port,
        database=database_config.database,
        query={"charset": "utf8mb4"})


def _build_engine_options(database_config) -> dict:
    """builds the create_engine kwargs for the given database config"""
    options: dict[str, Any] = {
        "isolation_level": "READ COMMITTED",
        "pool_recycle": create_timedelta(database_config.max_connection_lifetime).total_seconds(),
        "pool_timeout": 30,
        "pool_size": database_config.pool_size,
        "max_overflow": database_config.max_overflow,
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
    engine = create_engine(_build_database_url(database_config), **_build_engine_options(database_config))
    _attach_engine_listeners(engine)
    return engine


def initialize_database():
    """Prepares the database connections. Each engine is built by the first get_db_connection() or
    get_db() that needs it, and the "ace" session by the first get_db(): building the session imports
    the ORM, which a process that never queries through it does not need."""

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
    stays up and the server is told nothing. It has to happen first, before the connections become unreachable:
    once SQLAlchemy's _finalize_fairy runs on a garbage collected connection it issues a reset
    (a ROLLBACK) on the way out. With no socket, pymysql refuses it before writing a byte, and
    SQLAlchemy logs that ("Exception during reset or similar") and invalidates the record,
    whose close is then a no-op. Nothing reaches the server.

    engine.dispose(close=False) is then SQLAlchemy's documented after-fork call: it swaps
    in a fresh pool and abandons the inherited one rather than closing it.
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
            engine.dispose(close=False)
        except Exception as e:
            _write_stderr(f"WARNING: unable to dispose inherited engine after fork: {e}\n")

    for name, session in list(_db_sessions.items()):
        if session is None:
            continue

        try:
            session.registry.clear()
        except Exception as e:
            _write_stderr(f"WARNING: unable to clear inherited {name} session after fork: {e}\n")

    _write_stderr(f"NOTICE: reset {len(inherited)} inherited database connections in pid {pid}\n")


def _before_fork():
    # take every registry lock across the fork. only the forking thread survives into the
    # child, so a lock another thread held at that moment would never be released there --
    # the child would deadlock on the first database call. holding them here means they are
    # ours to release on both sides.
    _db_sessions_lock.acquire()
    _tracked_connections_lock.acquire()


def _release_fork_locks():
    _tracked_connections_lock.release()
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
