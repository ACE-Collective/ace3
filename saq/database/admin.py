"""Administrative (superuser) access to the MySQL server.

Everything ACE does at runtime goes through ``ace-user``, which only has DML grants on a
fixed list of schemas. Creating databases, running migrations, seeding reference rows and
provisioning the per-session unittest databases all need ``ace-superuser`` instead. The
credentials for that account come from the ``ACE_SUPERUSER_DB_USER_PASSWORD`` environment
variable or, in the docker development environment, from ``/auth/passwords/ace-superuser``
(written by ``bin/initialize_auth.sh``). The host comes from ``ACE_DB_HOST``.

This is the same lookup ``alembic/*/env.py`` and ``bin/seed_database.py`` have always
done; it lives here so there is one copy of it.
"""

import os
from contextlib import contextmanager
from typing import Iterator
from urllib.parse import quote_plus

import pymysql
from pymysql.connections import Connection
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

SUPERUSER_NAME = "ace-superuser"
SUPERUSER_PASSWORD_ENV = "ACE_SUPERUSER_DB_USER_PASSWORD"
SUPERUSER_PASSWORD_PATH = "/auth/passwords/ace-superuser"
DB_HOST_ENV = "ACE_DB_HOST"
DEFAULT_DB_HOST = "ace-db"
DB_PORT = 3306


def get_superuser_password() -> str:
    """Returns the password for the database superuser account.

    Raises RuntimeError with an explanation of where the password is looked for if it
    cannot be found."""
    password = os.environ.get(SUPERUSER_PASSWORD_ENV) or ""
    if password:
        return password

    try:
        with open(SUPERUSER_PASSWORD_PATH, "r") as fp:
            password = fp.read().strip()
    except OSError:
        password = ""

    if not password:
        raise RuntimeError(
            f"unable to find the password for the {SUPERUSER_NAME} database account: "
            f"set the {SUPERUSER_PASSWORD_ENV} environment variable or "
            f"create {SUPERUSER_PASSWORD_PATH}")

    return password


def get_database_host() -> str:
    """Returns the hostname of the primary database server."""
    return os.environ.get(DB_HOST_ENV, DEFAULT_DB_HOST)


def get_superuser_url(database: str | None = None) -> str:
    """Returns a SQLAlchemy URL that connects as the superuser, optionally to a database."""
    password = quote_plus(get_superuser_password())
    url = f"mysql+pymysql://{SUPERUSER_NAME}:{password}@{get_database_host()}:{DB_PORT}"
    if database:
        url = f"{url}/{database}"

    return url


def create_superuser_engine(database: str | None = None) -> Engine:
    """Creates a SQLAlchemy engine connected as the superuser.

    The caller owns the engine and must dispose() it; it is deliberately not registered
    with saq.database.pool so it never takes part in the fork-safety bookkeeping there."""
    return create_engine(get_superuser_url(database))


@contextmanager
def superuser_connection(database: str | None = None) -> Iterator[Connection]:
    """Context manager yielding a raw pymysql connection as the superuser.

    autocommit is on: this is for DDL and administrative statements, not transactions."""
    connection = pymysql.connect(
        host=get_database_host(),
        port=DB_PORT,
        user=SUPERUSER_NAME,
        password=get_superuser_password(),
        database=database,
        charset="utf8mb4",
        autocommit=True)

    try:
        yield connection
    finally:
        connection.close()
