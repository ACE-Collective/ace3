"""Tests for how the retry helpers classify and report database failures.

These cover three defects that together produced most of the log noise when ACE was
stopped: a lost connection was reported as a deadlock, a real deadlock retried forever
regardless of the attempts limit, and a failure to roll back discarded the exception it
was handling.
"""

from unittest.mock import MagicMock, patch

import pymysql
import pytest
from sqlalchemy.exc import DBAPIError

from saq.database.model import Company
from saq.database.pool import get_db
from saq.database.retry import (
    CONNECTION_LOST_ERROR_CODES,
    get_dbapi_error_code,
    is_connection_lost,
    retry_on_deadlock,
)


class _Orig(Exception):
    """Stands in for the driver-level exception hanging off DBAPIError.orig."""

    def __init__(self, *args):
        self.args = args


def _dbapi_error(*args) -> DBAPIError:
    return DBAPIError("SELECT 1", {}, _Orig(*args))


@pytest.mark.unit
@pytest.mark.parametrize("code", sorted(CONNECTION_LOST_ERROR_CODES))
def test_connection_loss_codes_are_recognized(code):
    assert is_connection_lost(pymysql.err.OperationalError(code, "boom")) is True


@pytest.mark.unit
@pytest.mark.parametrize("code", [1213, 1205, 1064])
def test_other_codes_are_not_connection_loss(code):
    """1213/1205 are deadlocks and must stay retryable rather than being treated as a
    dead connection."""
    assert is_connection_lost(pymysql.err.OperationalError(code, "boom")) is False


@pytest.mark.unit
def test_error_code_survives_an_exception_with_no_args():
    """Connection-level failures often carry no args. Reading orig.args[0] blindly raised
    IndexError from inside the error handler, turning a lost connection into a confusing
    secondary exception."""
    assert get_dbapi_error_code(_dbapi_error()) is None
    assert is_connection_lost(_dbapi_error()) is False


@pytest.mark.unit
def test_error_code_survives_a_non_numeric_first_arg():
    assert get_dbapi_error_code(_dbapi_error("not a code")) is None


@pytest.mark.integration
def test_deadlock_respects_the_attempts_limit():
    """The condition used to read `a == 1213 or a == 1205 and attempt < attempts`, which
    python groups as `a == 1213 or (a == 1205 and ...)`. A 1213 therefore ignored the
    limit and retried forever."""
    target = MagicMock(side_effect=_dbapi_error(1213, "deadlock"))

    with pytest.raises(DBAPIError):
        retry_on_deadlock(target, attempts=3)

    # the initial attempt plus 3 retries, then it gives up rather than looping forever
    assert target.call_count == 4


@pytest.mark.integration
def test_deadlock_retries_then_succeeds():
    """the retry rolls back the real session and runs the target again on it"""
    def insert_then_deadlock():
        get_db().add(Company(name="deadlocked company"))
        get_db().flush()
        raise _dbapi_error(1213, "deadlock")

    def insert():
        get_db().add(Company(name="retried company"))
        return "ok"

    attempts = [insert_then_deadlock, insert]

    def target():
        return attempts.pop(0)()

    assert retry_on_deadlock(target, attempts=5, commit=True) == "ok"
    assert attempts == []

    names = {name for (name,) in get_db().query(Company.name)}
    # the rollback discarded the first attempt's write, the commit kept the second's
    assert "deadlocked company" not in names
    assert "retried company" in names


@pytest.mark.integration
def test_failed_rollback_preserves_the_original_exception():
    """The rollback handler rebound `e`, so a failure while rolling back re-raised the
    rollback error and hid the deadlock that caused it."""
    original = _dbapi_error(1213, "the real problem")
    target = MagicMock(side_effect=original)

    with patch.object(get_db(), "rollback", side_effect=RuntimeError("rollback also failed")), \
            patch("saq.error.reporting.write_error_report"):
        with pytest.raises(DBAPIError) as exc_info:
            retry_on_deadlock(target, attempts=3)

    assert exc_info.value is original


@pytest.mark.unit
def test_connection_loss_is_not_reported_as_a_deadlock(caplog):
    """A "MySQL server has gone away" used to be logged as DEADLOCK STATEMENT, one line
    per statement, which dominated the shutdown logs and sent people hunting for
    deadlocks that never happened."""
    target = MagicMock(side_effect=_dbapi_error(2006, "MySQL server has gone away"))

    with pytest.raises(DBAPIError):
        retry_on_deadlock(target, attempts=3)

    assert "DEADLOCK" not in caplog.text
    # and it is only tried once -- a dead connection is not worth retrying 15 times
    assert target.call_count == 1


@pytest.mark.unit
def test_connection_loss_is_quiet_while_shutting_down(caplog):
    from saq.shutdown import get_shutdown_coordinator, reset_shutdown_coordinator

    target = MagicMock(side_effect=_dbapi_error(2006, "MySQL server has gone away"))

    reset_shutdown_coordinator()
    try:
        get_shutdown_coordinator(deadline_seconds=5).request_shutdown("test")

        with caplog.at_level("DEBUG"):
            with pytest.raises(DBAPIError):
                retry_on_deadlock(target, attempts=3)

        # logged, but not as a warning or error anyone needs to chase
        assert "database connection lost during shutdown" in caplog.text
        assert not [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")]
    finally:
        reset_shutdown_coordinator()
