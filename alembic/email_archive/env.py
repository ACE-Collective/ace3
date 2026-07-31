import os
import sys
from urllib.parse import quote_plus

# ensure the project root is on sys.path so saq is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from alembic import context
from sqlalchemy import create_engine, pool

from saq.database.meta import EmailArchiveBase
import saq.database.model  # noqa: F401 — populates EmailArchiveBase.metadata

target_metadata = EmailArchiveBase.metadata


def get_url() -> str:
    password = os.environ.get("ACE_SUPERUSER_DB_USER_PASSWORD") or ""
    if not password:
        with open("/auth/passwords/ace-superuser") as fp:
            password = fp.read().strip()
    password = quote_plus(password)
    host = os.environ.get("ACE_DB_HOST", "ace-db")
    # EMAIL_ARCHIVE_DATABASE_NAME is separate from DATABASE_NAME so the bootstrap
    # script can target main+cache+brocess+email-archive in the same shell without
    # collisions. NOTE the default is the hyphenated MySQL schema name.
    db_name = os.environ.get("EMAIL_ARCHIVE_DATABASE_NAME", "email-archive")
    return f"mysql+pymysql://ace-superuser:{password}@{host}:3306/{db_name}"


def run_migrations_offline() -> None:
    context.configure(url=get_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
