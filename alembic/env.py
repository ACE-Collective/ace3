import os
import sys
from urllib.parse import quote_plus

# Ensure the project root is on sys.path so saq is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alembic import context
from sqlalchemy import create_engine, pool

from saq.configuration.loader import load_configuration
from saq.database.meta import Base
import saq.database.model  # noqa: F401 — populates Base.metadata

target_metadata = Base.metadata


def get_url() -> str:
    raw = load_configuration(config_paths=[])
    db = raw._data["database_ace"]
    password = quote_plus(db["password"])
    db_name = os.environ.get("DATABASE_NAME", db["database"])
    return f"mysql+pymysql://{db['username']}:{password}@{db['hostname']}:{db['port']}/{db_name}"


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
