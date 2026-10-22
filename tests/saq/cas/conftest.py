import os

import pytest
from sqlalchemy import func, text, update

from saq.cas import CASPool, get_cas
from saq.cas import index
from saq.crypto import CHUNK_SIZE
from saq.database.model import CASObject
from saq.monitor import emit_monitor


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


@pytest.fixture
def cas_emitted(monkeypatch):
    """Every monitor record the CAS emits, as (path, data), in order. Each one still goes
    through the real emit_monitor; the CAS swallows emit failures, so they fail the test here."""
    records = []
    failures = []

    def emit(monitor, data, identifier=None):
        try:
            result = emit_monitor(monitor, data, identifier)
        except Exception as e:
            failures.append((monitor.path, e))
            raise
        records.append((monitor.path, data))
        return result

    monkeypatch.setattr("saq.cas.pool.emit_monitor", emit)
    # the CLI imports emit_monitor inside its command functions
    monkeypatch.setattr("saq.monitor.emit_monitor", emit)
    yield records
    assert not failures, f"emit_monitor rejected CAS monitor records: {failures}"


def records_for(records: list[tuple[str, dict]], path: str) -> list[dict]:
    return [data for record_path, data in records if record_path == path]
