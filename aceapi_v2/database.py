import asyncio
import logging
import os
import ssl
import threading
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import quote_plus
from weakref import WeakKeyDictionary

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from saq.configuration import get_config
from saq.util import abs_path

# pool settings kept in parity with the synchronous engines built in
# saq/database/pool.py and flask_config.py so the async engine recovers from
# stale connections the same way (proactive recycle + pre-ping)
POOL_RECYCLE_SECONDS = 60 * 10  # 10 minute connection pool recycle
POOL_TIMEOUT_SECONDS = 30
POOL_SIZE = 5


def build_database_url(db_name: str = "ace") -> str:
    """Build async SQLAlchemy database URL from config."""
    db_config = get_config().get_database_config(db_name)
    # URL-encode password in case it contains special characters
    password = quote_plus(db_config.password)
    if db_config.unix_socket:
        # host is ignored when a unix socket is supplied via connect_args
        return f"mysql+aiomysql://{db_config.username}:{password}@localhost/{db_config.database}"
    return f"mysql+aiomysql://{db_config.username}:{password}@{db_config.hostname}:{db_config.port}/{db_config.database}"


def _build_ssl_context(db_config) -> ssl.SSLContext | None:
    """build an ssl.SSLContext for the given database config, or None if no ssl configured

    aiomysql expects the ssl connect arg to be an ssl.SSLContext, unlike pymysql
    which takes a {ca, key, cert} dict in saq/database/pool.py."""
    if not (db_config.ssl_ca or db_config.ssl_key or db_config.ssl_cert):
        return None

    ca_path = None
    if db_config.ssl_ca:
        ca_path = abs_path(db_config.ssl_ca)
        if not os.path.exists(ca_path):
            logging.error("ssl_ca file %s does not exist (specified in %s)", ca_path, db_config.name)
            ca_path = None

    context = ssl.create_default_context(cafile=ca_path)

    if db_config.ssl_cert and db_config.ssl_key:
        cert_path = abs_path(db_config.ssl_cert)
        key_path = abs_path(db_config.ssl_key)
        if not os.path.exists(cert_path):
            logging.error("ssl_cert file %s does not exist (specified in %s)", cert_path, db_config.name)
        elif not os.path.exists(key_path):
            logging.error("ssl_key file %s does not exist (specified in %s)", key_path, db_config.name)
        else:
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    return context


def build_connect_args(db_name: str = "ace") -> dict[str, Any]:
    """build the aiomysql connect_args for the given database config

    mirrors the kwargs the synchronous pymysql pool builds in
    saq/database/pool.py so the async engine connects with the same charset,
    unix socket and ssl settings."""
    db_config = get_config().get_database_config(db_name)
    connect_args: dict[str, Any] = {
        "charset": "utf8mb4",
        "init_command": "SET NAMES utf8mb4",
    }

    # note: unlike pymysql, aiomysql.connect() has no max_allowed_packet kwarg, so
    # that setting cannot be carried over from the synchronous pool config here

    if db_config.unix_socket:
        connect_args["unix_socket"] = db_config.unix_socket

    ssl_context = _build_ssl_context(db_config)
    if ssl_context is not None:
        connect_args["ssl"] = ssl_context

    return connect_args


def create_engine_for(db_name: str = "ace") -> AsyncEngine:
    """create an async engine for the named database with stale-connection handling

    pool_recycle proactively retires pooled connections before MySQL closes them
    (wait_timeout), and pool_pre_ping validates a connection on checkout and
    transparently reconnects if it has gone stale."""
    return create_async_engine(
        build_database_url(db_name),
        echo=False,
        isolation_level="READ COMMITTED",
        pool_recycle=POOL_RECYCLE_SECONDS,
        pool_timeout=POOL_TIMEOUT_SECONDS,
        pool_size=POOL_SIZE,
        pool_pre_ping=True,
        connect_args=build_connect_args(db_name),
    )


# Per-loop engine and session maker registries. aiomysql connections are bound to the
# event loop that created them, so a single process-global engine would corrupt its pool
# if more than one loop touched it (e.g. uvicorn's serving loop and the persistent
# background loop in sync.py). keying the engine by the running loop makes cross-loop pool
# reuse structurally impossible. WeakKeyDictionary so a loop that is garbage collected
# drops its engine entry, avoiding unbounded growth. the lock guards the dicts because the
# loops live in separate threads and can create entries concurrently. it is reentrant
# because _get_session_maker calls _get_engine while holding the lock (same thread).
#
# the engine is also created lazily here (config may not be loaded at module import time).
_engines: "WeakKeyDictionary[asyncio.AbstractEventLoop, AsyncEngine]" = WeakKeyDictionary()
_session_makers: "WeakKeyDictionary[asyncio.AbstractEventLoop, async_sessionmaker]" = WeakKeyDictionary()
_registry_lock = threading.RLock()


async def dispose_engines_for_current_loop():
    """Dispose the async engine bound to the running event loop."""
    loop = asyncio.get_running_loop()
    with _registry_lock:
        engine = _engines.pop(loop, None)
        _session_makers.pop(loop, None)

    if engine is not None:
        await engine.dispose()


def _get_engine() -> AsyncEngine:
    """get or create the async engine bound to the running event loop"""
    loop = asyncio.get_running_loop()
    with _registry_lock:
        engine = _engines.get(loop)
        if engine is None:
            engine = create_engine_for("ace")
            _engines[loop] = engine
        return engine


def _get_session_maker() -> async_sessionmaker:
    """get or create the async session maker bound to the running event loop"""
    loop = asyncio.get_running_loop()
    with _registry_lock:
        maker = _session_makers.get(loop)
        if maker is None:
            maker = async_sessionmaker[AsyncSession](
                _get_engine(), class_=AsyncSession, expire_on_commit=False
            )
            _session_makers[loop] = maker
        return maker


async def get_async_session() -> AsyncGenerator[AsyncSession]:
    async with _get_session_maker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
