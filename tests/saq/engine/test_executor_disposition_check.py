"""Tests for the throttle on ``AnalysisExecutor._check_for_alert_disposition``.

``_check_for_alert_disposition`` is gate #1 of the per-module gauntlet, so it
runs on every module invocation against every observable.
``alert_disposition_check_frequency`` exists to hold the resulting
``SELECT disposition FROM alerts`` down to one query per window; these tests pin
that the window actually closes again after a check (see docs/ENGINE.md §19.1).

The defect being guarded against is arithmetic: ``context.last_disposition_check``
was read but never written, so once the first window elapsed every subsequent
call queried. The queries counted here are the statements the real session
sends to the database.
"""
import re
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_engine_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DISPOSITION_DELIVERY,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_IGNORE,
)
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.execution_context import EngineExecutionContext
from saq.engine.executor import AnalysisExecutor
from saq.engine.tracking import NullTrackingWriter
from tests.saq.helpers import count_queries, insert_alert_with_detections


def _make_executor(frequency: int) -> AnalysisExecutor:
    config = EngineConfiguration(single_threaded_mode=True)
    config.alert_disposition_check_frequency = frequency
    return AnalysisExecutor(
        configuration_manager=ConfigurationManager(config),
        # the disposition check never delays analysis
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=NullTrackingWriter("test"),
        single_threaded_mode=True,
    )


def _make_context(tmp_path, elapsed_seconds: float = 0) -> EngineExecutionContext:
    """Real context, with ``last_disposition_check`` rewound by
    ``elapsed_seconds`` to simulate an analysis that has been running a while."""
    context = EngineExecutionContext(RootAnalysis(storage_dir=str(tmp_path)))
    context.last_disposition_check = datetime.now() - timedelta(seconds=elapsed_seconds)
    return context


@pytest.fixture
def disposition_queries():
    """Returns the disposition lookups sent to the database during the test so far."""
    with count_queries() as statements:
        yield lambda: [s for s in statements if re.match(r"SELECT alerts\.disposition( AS \w+)?\s+FROM alerts\b", s)]


@pytest.fixture
def stop_on(monkeypatch):
    """Sets the engine's stop-analysis settings on the real engine config."""
    def _set(any_disposition: bool = True, dispositions: list[str] | None = None):
        monkeypatch.setattr(get_engine_config(), "stop_analysis_on_any_alert_disposition", any_disposition)
        monkeypatch.setattr(get_engine_config(), "stop_analysis_on_dispositions",
                            dispositions if dispositions is not None else [DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE])

    _set()
    return _set


@pytest.mark.integration
def test_disposition_check_is_throttled(tmp_path, disposition_queries, stop_on):
    """Repeated calls inside one throttle window issue exactly one query."""
    alert = insert_alert_with_detections([])
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)
    rewound = context.last_disposition_check

    for _ in range(10):
        executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)

    assert len(disposition_queries()) == 1
    # the check has to record itself, otherwise the window never closes again
    assert context.last_disposition_check > rewound
    assert not context.cancel_analysis_flag


@pytest.mark.integration
def test_disposition_check_refires_after_window(tmp_path, disposition_queries, stop_on):
    """The throttle opens again once the window has passed — it does not latch."""
    alert = insert_alert_with_detections([])
    executor = _make_executor(frequency=1)
    context = _make_context(tmp_path, elapsed_seconds=5)

    executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)
    assert len(disposition_queries()) == 1

    # this call is inside the window and must be suppressed
    executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)
    assert len(disposition_queries()) == 1

    context.last_disposition_check = datetime.now() - timedelta(seconds=5)
    executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)

    assert len(disposition_queries()) == 2


@pytest.mark.integration
def test_disposition_check_frequency_zero_checks_every_time(tmp_path, disposition_queries, stop_on):
    """frequency 0 means check every time — tests/saq/modules/test_alerting.py
    sets this to force the disposition to be noticed mid-analysis."""
    alert = insert_alert_with_detections([])
    executor = _make_executor(frequency=0)
    context = _make_context(tmp_path)

    for _ in range(3):
        executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)

    assert len(disposition_queries()) == 3


@pytest.mark.integration
def test_disposition_check_skipped_outside_correlation_mode(tmp_path, disposition_queries, stop_on):
    """Only alerts in correlation mode have a disposition worth polling for."""
    alert = insert_alert_with_detections([], disposition=DISPOSITION_FALSE_POSITIVE)
    executor = _make_executor(frequency=0)
    context = _make_context(tmp_path)

    for _ in range(3):
        executor._check_for_alert_disposition(context, "test_groups", alert.uuid)

    assert disposition_queries() == []
    assert not context.cancel_analysis_flag


@pytest.mark.integration
def test_disposition_check_cancels_on_stop_disposition(tmp_path, disposition_queries, stop_on):
    """Throttling must not break the reason the check exists."""
    alert = insert_alert_with_detections([], disposition=DISPOSITION_FALSE_POSITIVE)
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)

    executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)

    assert len(disposition_queries()) == 1
    assert context.cancel_analysis_flag


@pytest.mark.integration
def test_disposition_check_continues_on_non_stop_disposition(tmp_path, disposition_queries, stop_on):
    """A disposition that is not configured to stop analysis lets it run on."""
    alert = insert_alert_with_detections([], disposition=DISPOSITION_DELIVERY)
    stop_on(any_disposition=False, dispositions=[DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE])
    executor = _make_executor(frequency=5)
    context = _make_context(tmp_path, elapsed_seconds=10)

    executor._check_for_alert_disposition(context, ANALYSIS_MODE_CORRELATION, alert.uuid)

    assert len(disposition_queries()) == 1
    assert not context.cancel_analysis_flag
