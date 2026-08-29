"""Tests for the throttle on ``AnalysisExecutor._check_for_alert_disposition``.

``_check_for_alert_disposition`` is gate #1 of the per-module gauntlet, so it
runs on every module invocation against every observable.
``alert_disposition_check_frequency`` exists to hold the resulting
``SELECT disposition FROM alerts`` down to one query per window; these tests pin
that the window actually closes again after a check (see docs/ENGINE.md §19.1).

The defect being guarded against is arithmetic, not integration:
``context.last_disposition_check`` was read but never written, so once the first
window elapsed every subsequent call queried. Mocking ``get_db`` and
``get_engine_config`` keeps these as unit tests with no DB or engine.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
)
from saq.engine.executor import AnalysisExecutionContext, AnalysisExecutor

ALERT_UUID = "00000000-0000-0000-0000-000000000001"


def _make_executor(frequency: int) -> AnalysisExecutor:
    """Minimum-viable AnalysisExecutor for the disposition helper.

    ``self.config`` is just ``configuration_manager.config``, so the frequency
    is the only attribute that has to be a real value.
    """
    configuration_manager = MagicMock()
    configuration_manager.config.alert_disposition_check_frequency = frequency
    return AnalysisExecutor(
        configuration_manager=configuration_manager,
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_context(tmp_path, elapsed_seconds: float = 0) -> AnalysisExecutionContext:
    """Real context, with ``last_disposition_check`` rewound by
    ``elapsed_seconds`` to simulate an analysis that has been running a while."""
    context = AnalysisExecutionContext(RootAnalysis(storage_dir=str(tmp_path)))
    context.last_disposition_check = datetime.now() - timedelta(seconds=elapsed_seconds)
    return context


def _mock_db(disposition=None) -> MagicMock:
    """A ``get_db`` stand-in whose ``query(...).filter(...).scalar()`` returns
    ``disposition``. Query count is ``mock.return_value.query.call_count``."""
    mock_get_db = MagicMock()
    mock_get_db.return_value.query.return_value.filter.return_value.scalar.return_value = (
        disposition
    )
    return mock_get_db


def _mock_engine_config(
    stop_on_any: bool = True, stop_on: list[str] | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        stop_analysis_on_any_alert_disposition=stop_on_any,
        stop_analysis_on_dispositions=stop_on
        if stop_on is not None
        else [DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE],
    )


def _query_count(mock_get_db: MagicMock) -> int:
    return mock_get_db.return_value.query.call_count


@pytest.mark.unit
def test_disposition_check_is_throttled(tmp_path):
    """Repeated calls inside one throttle window issue exactly one query."""
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)
    rewound = context.last_disposition_check
    mock_get_db = _mock_db()

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config", return_value=_mock_engine_config()
    ):
        for _ in range(10):
            executor._check_for_alert_disposition(
                context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
            )

    assert _query_count(mock_get_db) == 1
    # the check has to record itself, otherwise the window never closes again
    assert context.last_disposition_check > rewound


@pytest.mark.unit
def test_disposition_check_refires_after_window(tmp_path):
    """The throttle opens again once the window has passed — it does not latch."""
    executor = _make_executor(frequency=1)
    context = _make_context(tmp_path, elapsed_seconds=5)
    mock_get_db = _mock_db()

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config", return_value=_mock_engine_config()
    ):
        executor._check_for_alert_disposition(
            context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
        )
        assert _query_count(mock_get_db) == 1

        # this call is inside the window and must be suppressed
        executor._check_for_alert_disposition(
            context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
        )
        assert _query_count(mock_get_db) == 1

        context.last_disposition_check = datetime.now() - timedelta(seconds=5)
        executor._check_for_alert_disposition(
            context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
        )

    assert _query_count(mock_get_db) == 2


@pytest.mark.unit
def test_disposition_check_frequency_zero_checks_every_time(tmp_path):
    """frequency 0 means check every time — tests/saq/modules/test_alerting.py
    sets this to force the disposition to be noticed mid-analysis."""
    executor = _make_executor(frequency=0)
    context = _make_context(tmp_path)
    mock_get_db = _mock_db()

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config", return_value=_mock_engine_config()
    ):
        for _ in range(3):
            executor._check_for_alert_disposition(
                context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
            )

    assert _query_count(mock_get_db) == 3


@pytest.mark.unit
def test_disposition_check_skipped_outside_correlation_mode(tmp_path):
    """Only alerts in correlation mode have a disposition worth polling for."""
    executor = _make_executor(frequency=0)
    context = _make_context(tmp_path)
    mock_get_db = _mock_db(DISPOSITION_FALSE_POSITIVE)

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config", return_value=_mock_engine_config()
    ):
        for _ in range(3):
            executor._check_for_alert_disposition(context, "test_groups", ALERT_UUID)

    assert _query_count(mock_get_db) == 0
    assert not context.cancel_analysis_flag


@pytest.mark.unit
def test_disposition_check_cancels_on_stop_disposition(tmp_path):
    """Throttling must not break the reason the check exists."""
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)
    mock_get_db = _mock_db(DISPOSITION_FALSE_POSITIVE)

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config", return_value=_mock_engine_config()
    ):
        executor._check_for_alert_disposition(
            context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
        )

    assert _query_count(mock_get_db) == 1
    assert context.cancel_analysis_flag


@pytest.mark.unit
def test_disposition_check_continues_on_non_stop_disposition(tmp_path):
    """A disposition that is not configured to stop analysis lets it run on."""
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)
    mock_get_db = _mock_db(DISPOSITION_DELIVERY)

    with patch("saq.engine.executor.get_db", mock_get_db), patch(
        "saq.engine.executor.get_engine_config",
        return_value=_mock_engine_config(
            stop_on_any=False,
            stop_on=[DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE],
        ),
    ):
        executor._check_for_alert_disposition(
            context, ANALYSIS_MODE_CORRELATION, ALERT_UUID
        )

    assert _query_count(mock_get_db) == 1
    assert not context.cancel_analysis_flag
