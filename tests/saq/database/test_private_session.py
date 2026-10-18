"""Running a private transaction again when MySQL rolls it back for a lock (saq.database.private_session)."""

import threading
import uuid

import pymysql
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError

from saq.database import private_session
from saq.database.model import Tag
from saq.database.pool import get_db
from saq.database.private_session import private_transaction, run_private_transaction


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(private_session.time, "sleep", lambda _: None)


def _error(code: int) -> OperationalError:
    return OperationalError("UPDATE tags", {}, pymysql.err.OperationalError(code, "no"))


def _tag_names(names: list[str]) -> list[str]:
    with private_transaction() as session:
        return sorted(session.execute(select(Tag.name).where(Tag.name.in_(names))).scalars())


def _failing(name: str, codes: list[int], calls: list):
    """Work that adds a tag, then fails with the next of codes, if any, before it commits."""
    def work(session, suffix):
        calls.append(suffix)
        session.add(Tag(name=f"{name}{suffix}"))
        session.flush()
        if len(calls) <= len(codes):
            raise _error(codes[len(calls) - 1])
        return len(calls)
    return work


@pytest.mark.integration
@pytest.mark.parametrize("code", [1205, 1213])
def test_a_lock_failure_is_run_again(caplog, code):
    name = f"retry-{uuid.uuid4()}"
    calls = []

    assert run_private_transaction(_failing(name, [code], calls), "-x", description="adding a tag",
                                   extra={"tag": name}) == 2

    assert calls == ["-x", "-x"]
    assert _tag_names([f"{name}-x"]) == [f"{name}-x"]
    warning, = [r for r in caplog.records if "trying again" in r.getMessage()]
    assert warning.getMessage().startswith(f"adding a tag rolled back ({code})")
    assert "attempt 2 of 5" in warning.getMessage()
    assert warning.tag == name and warning.error_code == code


@pytest.mark.integration
def test_another_error_is_raised_at_once():
    name = f"retry-{uuid.uuid4()}"
    calls = []

    with pytest.raises(OperationalError):
        run_private_transaction(_failing(name, [1062], calls), "")

    assert len(calls) == 1
    assert _tag_names([name]) == []


@pytest.mark.integration
def test_a_real_integrity_error_is_raised_at_once():
    name = f"retry-{uuid.uuid4()}"
    with private_transaction() as session:
        session.add(Tag(name=name))
    calls = []

    def work(session):
        calls.append(1)
        session.add(Tag(name=name))
        session.flush()

    with pytest.raises(IntegrityError):
        run_private_transaction(work)
    assert calls == [1]


@pytest.mark.integration
def test_a_lock_failure_that_keeps_happening_is_raised():
    name = f"retry-{uuid.uuid4()}"
    calls = []

    with pytest.raises(OperationalError) as e:
        run_private_transaction(_failing(name, [1213] * 3, calls), "", attempts=3)

    assert pymysql.err.OperationalError(1213, "no").args == e.value.orig.args
    assert len(calls) == 3
    assert _tag_names([name]) == []


@pytest.mark.integration
def test_nothing_is_run_again_while_shutting_down(monkeypatch):
    monkeypatch.setattr(private_session, "is_shutting_down", lambda: True)
    calls = []

    with pytest.raises(OperationalError):
        run_private_transaction(_failing(f"retry-{uuid.uuid4()}", [1213], calls), "")
    assert len(calls) == 1


@pytest.mark.unit
def test_attempts_must_be_positive():
    with pytest.raises(ValueError):
        run_private_transaction(lambda session: None, attempts=0)


@pytest.mark.integration
def test_the_callers_session_is_left_alone():
    """The caller's uncommitted work on get_db() survives a retried private transaction."""
    mine = f"retry-{uuid.uuid4()}"
    get_db().add(Tag(name=mine))
    get_db().flush()

    calls = []
    run_private_transaction(_failing(f"retry-{uuid.uuid4()}", [1213], calls), "")

    assert mine in get_db().execute(select(Tag.name).where(Tag.name == mine)).scalars().all()
    get_db().commit()
    assert _tag_names([mine]) == [mine]


@pytest.mark.integration
def test_a_real_deadlock_is_run_again():
    """Two transactions lock the same two rows in opposite order: MySQL rolls one back, and run
    again it waits for the other and both finish."""
    names = [f"retry-a-{uuid.uuid4()}", f"retry-b-{uuid.uuid4()}"]
    with private_transaction() as session:
        session.add_all([Tag(name=name) for name in names])
    barrier = threading.Barrier(2, timeout=10)
    attempts = {0: 0, 1: 0}
    errors = []

    def work(session, me, order):
        attempts[me] += 1
        session.execute(select(Tag).where(Tag.name == order[0]).with_for_update()).one()
        if attempts[me] == 1:
            barrier.wait()
        session.execute(select(Tag).where(Tag.name == order[1]).with_for_update()).one()

    def run(me, order):
        try:
            run_private_transaction(work, me, order)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run, args=(0, names)), threading.Thread(target=run, args=(1, names[::-1]))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert errors == []
    assert sorted(attempts.values()) == [1, 2]
