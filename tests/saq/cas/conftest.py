import os

import pytest
from sqlalchemy import func, text, update

from saq.cas import CASPool, get_cas
from saq.cas import index
from saq.crypto import CHUNK_SIZE
from saq.database.model import CASObject


@pytest.fixture
def plain_pool() -> CASPool:
    return get_cas().pool("test_plain")


@pytest.fixture
def enc_pool() -> CASPool:
    return get_cas().pool("test_encrypted")


@pytest.fixture
def perm_pool() -> CASPool:
    return get_cas().pool("test_permanent")


@pytest.fixture
def payload() -> bytes:
    return os.urandom(2 * CHUNK_SIZE + 123)


def age_object(pool: CASPool, digest: str, seconds: int) -> None:
    """Move an object's last_held_at into the past, as the database sees time."""
    with index.transaction() as session:
        session.execute(
            update(CASObject)
            .where(CASObject.pool == pool.name, CASObject.digest == digest)
            .values(last_held_at=func.date_sub(func.now(), text(f"INTERVAL {int(seconds)} SECOND")))
            .execution_options(synchronize_session=False))


def backend_path(pool: CASPool, digest: str) -> str:
    return pool.backend.path(pool.key(digest))
