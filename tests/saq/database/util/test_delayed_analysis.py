"""Tests for ``saq.database.util.delayed_analysis`` (see docs/ENGINE.md §19.4).

``add_delayed_analysis_request`` is the only thing that records a delayed
analysis request. Its return value is what ``Worker.delay_analysis`` uses to
decide whether the delay was accepted, so "the INSERT worked" and "the INSERT
did not work" have to be distinguishable: it returned ``False`` on failure but
fell off the end of the function -- returning ``None`` -- on success.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pymysql
import pytest

from saq.constants import F_TEST
from saq.database.pool import get_db_connection
from saq.database.util import delayed_analysis
from saq.environment import get_global_runtime_settings


@pytest.fixture
def request_args(root_analysis):
    """The (root, observable, analysis_module) triple the function needs."""
    observable = root_analysis.add_observable_by_spec(F_TEST, "test")
    root_analysis.save()
    return root_analysis, observable, SimpleNamespace(name="test_delayed_analysis")


def _delayed_analysis_rows(root_uuid: str) -> list[tuple]:
    """The delayed_analysis rows for root_uuid, each with the seconds from NOW() until its delayed_until."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(
            """SELECT uuid, observable_uuid, analysis_module, node_id, storage_dir,
                      TIMESTAMPDIFF(SECOND, NOW(), delayed_until)
               FROM delayed_analysis WHERE uuid = %s""", (root_uuid,))
        return cursor.fetchall()


@pytest.mark.integration
def test_returns_true_on_success(request_args):
    """A successful insert must report success -- the caller marks the analysis
    delayed based on this."""
    root = request_args[0]

    assert delayed_analysis.add_delayed_analysis_request(*request_args, 0, 0, 10) is True
    assert len(_delayed_analysis_rows(root.uuid)) == 1


@pytest.mark.integration
def test_returns_false_when_insert_fails(request_args):
    """A failed insert means there is no row, and nothing will ever resume the
    analysis."""
    with patch.object(delayed_analysis, "execute_with_retry", side_effect=RuntimeError("boom")), \
            patch("saq.error.reporting.write_error_report"):
        assert delayed_analysis.add_delayed_analysis_request(*request_args, 0, 0, 10) is False


@pytest.mark.integration
def test_returns_true_on_integrity_error(request_args):
    """A row for this target already exists, so the analysis really is delayed.

    Unreachable with the current schema (``delayed_analysis`` has no unique
    constraint on the target) but kept as the correct answer for that case.
    """
    with patch.object(
        delayed_analysis, "execute_with_retry", side_effect=pymysql.err.IntegrityError("duplicate")
    ):
        assert delayed_analysis.add_delayed_analysis_request(*request_args, 0, 0, 10) is True


@pytest.mark.integration
def test_inserts_the_request_row(request_args):
    """The row identifies the target: root uuid, observable uuid, module name,
    the delay interval and the node that has to resume it."""
    root, observable, analysis_module = request_args
    delayed_analysis.add_delayed_analysis_request(root, observable, analysis_module, 1, 2, 3)

    (row,) = _delayed_analysis_rows(root.uuid)
    assert row[:5] == (
        root.uuid,
        observable.uuid,
        analysis_module.name,
        get_global_runtime_settings().saq_node_id,
        root.storage_dir,
    )
    # delayed by 1h 2m 3s from the database's clock
    assert 3723 - 5 <= row[5] <= 3723
