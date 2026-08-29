"""Tests for ``saq.database.util.delayed_analysis`` (see docs/ENGINE.md §19.4).

``add_delayed_analysis_request`` is the only thing that records a delayed
analysis request. Its return value is what ``Worker.delay_analysis`` uses to
decide whether the delay was accepted, so "the INSERT worked" and "the INSERT
did not work" have to be distinguishable: it returned ``False`` on failure but
fell off the end of the function -- returning ``None`` -- on success.

The database is mocked here on purpose: the point is the return value of each
branch, not the SQL.
"""
from unittest.mock import MagicMock, patch

import pymysql
import pytest


@pytest.fixture
def mock_db():
    """Patches everything ``add_delayed_analysis_request`` reaches out to and
    yields the connection mock ``get_db_connection()`` hands back."""
    with (
        patch("saq.database.util.delayed_analysis.get_db_connection") as mock_get_db_connection,
        patch("saq.database.util.delayed_analysis.execute_with_retry") as mock_execute_with_retry,
        patch("saq.database.util.delayed_analysis.get_global_runtime_settings") as mock_settings,
        patch("saq.database.util.delayed_analysis.report_exception"),
    ):
        mock_settings.return_value.saq_node_id = 1
        db = MagicMock()
        mock_get_db_connection.return_value.__enter__.return_value = db
        db.execute_with_retry = mock_execute_with_retry
        yield db


@pytest.fixture
def request_args():
    """The (root, observable, analysis_module) triple the function needs."""
    root = MagicMock()
    root.uuid = "d0f5b4d2-0f7f-4b9c-9c1e-4a3b2c1d0e9f"
    root.storage_dir = "/data/ace/d0f5b4d2-0f7f-4b9c-9c1e-4a3b2c1d0e9f"

    observable = MagicMock()
    observable.uuid = "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"

    analysis_module = MagicMock()
    analysis_module.name = "test_delayed_analysis"

    return root, observable, analysis_module


@pytest.mark.unit
def test_returns_true_on_success(mock_db, request_args):
    """A successful insert must report success -- the caller marks the analysis
    delayed based on this."""
    from saq.database.util.delayed_analysis import add_delayed_analysis_request

    assert add_delayed_analysis_request(*request_args, 0, 0, 10) is True
    mock_db.commit.assert_called_once()


@pytest.mark.unit
def test_returns_false_when_insert_fails(mock_db, request_args):
    """A failed insert means there is no row, and nothing will ever resume the
    analysis."""
    from saq.database.util import delayed_analysis

    with patch.object(delayed_analysis, "execute_with_retry", side_effect=RuntimeError("boom")):
        assert delayed_analysis.add_delayed_analysis_request(*request_args, 0, 0, 10) is False


@pytest.mark.unit
def test_returns_true_on_integrity_error(mock_db, request_args):
    """A row for this target already exists, so the analysis really is delayed.

    Unreachable with the current schema (``delayed_analysis`` has no unique
    constraint on the target) but kept as the correct answer for that case.
    """
    from saq.database.util import delayed_analysis

    with patch.object(
        delayed_analysis, "execute_with_retry", side_effect=pymysql.err.IntegrityError("duplicate")
    ):
        assert delayed_analysis.add_delayed_analysis_request(*request_args, 0, 0, 10) is True


@pytest.mark.unit
def test_inserts_the_request_row(mock_db, request_args):
    """The row identifies the target: root uuid, observable uuid, module name,
    the delay interval and the node that has to resume it."""
    from saq.database.util import delayed_analysis

    root, observable, analysis_module = request_args
    with patch.object(delayed_analysis, "execute_with_retry") as mock_execute_with_retry:
        delayed_analysis.add_delayed_analysis_request(root, observable, analysis_module, 1, 2, 3)

    sql, parameters = mock_execute_with_retry.call_args[0][2:4]
    assert "INSERT INTO delayed_analysis" in sql
    assert parameters == (
        root.uuid,
        observable.uuid,
        analysis_module.name,
        1,
        2,
        3,
        1,
        root.storage_dir,
    )
