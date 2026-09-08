import collections
from contextlib import contextmanager
from datetime import datetime
import logging
import os
import threading
from typing import Any, Callable
import warnings

import pymysql
from sqlalchemy import create_engine, event

from saq.configuration.config import get_config
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DB_POOL_AVAILABLE_COUNT, MONITOR_DB_POOL_IN_USE_COUNT, MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path, create_timedelta

from sqlalchemy.exc import DisconnectionError
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.orm.session import sessionmaker

# registry of SQLAlchemy ORM scoped sessions keyed by database config name
# the "ace" session is registered by initialize_database(); sessions for other
# databases are created lazily on first get_db() request
_db_sessions: dict[str, scoped_session] = {}
_db_sessions_lock = threading.RLock()

def get_db(name: str = "ace") -> scoped_session:
    """returns the SQLAlchemy scoped session for the named database

    get_db() with no argument returns the "ace" session
    sessions for other configured databases are created lazily (with their own
    engine) on first request."""
    if name is None:
        name = "ace"

    with _db_sessions_lock:
        session = _db_sessions.get(name)
        if session is not None:
            return session

        # the "ace" session is created by initialize_database() using the flask config
        if name == "ace":
            return None

        session = _db_sessions[name] = scoped_session(sessionmaker(bind=_create_engine_for(name)))
        logging.debug("created new scoped session for database %s", name)
        return session

def set_db(value):
    with _db_sessions_lock:
        _db_sessions["ace"] = value

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

        self.database_config = get_config().get_database_config(name)
        kwargs: dict[str, Any] = {
            'db': self.database_config.database,
            'user': self.database_config.username,
            'passwd': self.database_config.password,
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
            self.emit_monitors()

    def get_connection(self):
        connection = None
        with self.lock:
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
                    connection = self.open_new_connection()

                # drop old connections
                if datetime.now() >= connection.termination_date: # termination_date is a property we add in open_new_connection()
                    logging.info(f"terminating old connection {connection}")
                    self.close_connection(connection)
                    connection = self.open_new_connection()
            except IndexError:
                connection = self.open_new_connection()

            self.in_use.append(connection)
            connection.acquired = datetime.now()
            self.emit_monitors()

        return connection

    def return_connection(self, connection):
        if connection is None:
            return

        try:
            connection.rollback()
        except Exception as e:
            _log_pool_issue(f"unable to rollback connection {connection} on return to pool", e)
            self.destroy_connection(connection)
            return

        with self.lock:
            self.in_use.remove(connection)
            self.available.append(connection)
            self.emit_monitors()

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
                self.emit_monitors()
            except ValueError:
                logging.warning(f"attempted to remove missing database connection {connection}")

    def open_new_connection(self):
        connection = pymysql.connect(**self.kwargs)
        cursor = connection.cursor()
        cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
        cursor.close()
        connection.commit()

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

    the checkout listener's pid check is what makes an engine fork-safe -- a
    connection record created in a parent process is invalidated rather than
    reused after a fork."""

    @event.listens_for(engine, 'connect')
    def connect(dbapi_connection, connection_record):
        connection_record.info['pid'] = os.getpid()

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
    """builds the create_engine kwargs for the given database config

    mirrors the SQLALCHEMY_DATABASE_OPTIONS that flask_config builds for the
    ace database so that alternate databases get the same pooling behavior."""
    options: dict[str, Any] = {
        "pool_recycle": 60 * 10,  # 10 minute connection pool recycle
        "pool_timeout": 30,
        "pool_size": 5,
        "connect_args": {"init_command": "SET NAMES utf8mb4"},
        "pool_pre_ping": True,
    }

    if database_config.max_allowed_packet:
        options["connect_args"]["max_allowed_packet"] = database_config.max_allowed_packet

    if not database_config.unix_socket:
        if database_config.ssl_ca or database_config.ssl_cert or database_config.ssl_key:
            ssl_options = {"ca": abs_path(database_config.ssl_ca)}
            if database_config.ssl_cert:
                ssl_options["cert"] = abs_path(database_config.ssl_cert)
            if database_config.ssl_key:
                ssl_options["key"] = abs_path(database_config.ssl_key)
            options["connect_args"]["ssl"] = ssl_options

    return options


def _create_engine_for(name: str):
    """creates a SQLAlchemy engine for the named (non-ace) database config"""
    database_config = get_config().get_database_config(name)
    engine = create_engine(
        _build_database_url(database_config),
        isolation_level="READ COMMITTED",
        **_build_engine_options(database_config))
    _attach_engine_listeners(engine)
    return engine


def initialize_database():
    """Initializes database connections by creating the SQLAlchemy engine and session objects."""

    from flask_config import get_flask_config

    # see https://github.com/PyMySQL/PyMySQL/issues/644
    # /usr/local/lib/python3.6/dist-packages/pymysql/cursors.py:170: Warning: (1300, "Invalid utf8mb4 character string: '800363'")
    warnings.filterwarnings(action='ignore', message='.*Invalid utf8mb4 character string.*')

    if get_db() is None:
        engine = create_engine(
            get_flask_config(get_config().global_settings.instance_type).SQLALCHEMY_DATABASE_URI,
            isolation_level='READ COMMITTED',
            **get_flask_config(get_config().global_settings.instance_type).SQLALCHEMY_DATABASE_OPTIONS)

        _attach_engine_listeners(engine)
        set_db(scoped_session(sessionmaker(bind=engine)))

    else:
        # if you call this a second time it just closes all the sessions
        # this (currently) happens in unit testing
        from sqlalchemy.orm.session import close_all_sessions
        close_all_sessions()