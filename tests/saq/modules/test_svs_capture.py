"""The svs_yara_sample_capture module, through the engine: an alert's YARA-matched files are captured
when the alert is dispositioned tp or fp and analyzed in dispositioned mode (docs/SVS_SAMPLES.md)."""

import pytest
from sqlalchemy import true

from saq.cas import get_cas
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    ANALYSIS_MODE_DISPOSITIONED,
    DISPOSITION_DELIVERY,
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_REVIEWED,
    F_TEST,
)
from saq.database import ALERT, DelayedAnalysis, User, get_db, set_dispositions
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.modules import svs as svs_module
from saq.svs.capture import CaptureState, capture_hold
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import OTHER_RULE_UUID, RULE_UUID, add_file, add_yara_match, capture_rows

pytestmark = pytest.mark.integration


def _alert_with_yara_matches():
    """An alert whose correlation pass is over: one file matched by two rules."""
    root = create_root_analysis(analysis_mode=ANALYSIS_MODE_CORRELATION)
    root.initialize_storage()
    _file = add_file(root, "attachment.doc")
    add_yara_match(_file)
    add_yara_match(_file, rule="other_rule", rule_uuid=OTHER_RULE_UUID)
    root.save()
    ALERT(root)
    return root, _file


def _disposition(root, disposition):
    set_dispositions([root.uuid], disposition, get_db().query(User).first().id)
    get_db().close()


def _run_dispositioned():
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_DISPOSITIONED]))
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)


@pytest.mark.parametrize("disposition", [DISPOSITION_FALSE_POSITIVE, DISPOSITION_DELIVERY])
def test_a_classified_alert_is_captured(disposition):
    root, _file = _alert_with_yara_matches()

    _disposition(root, disposition)
    _run_dispositioned()

    rows = capture_rows(root.uuid)
    assert sorted(r.rule_uuid for r in rows) == sorted([RULE_UUID, OTHER_RULE_UUID])
    assert all(r.state == CaptureState.STORED and r.sha256 == _file.value for r in rows)
    pool = get_cas().pool("svs_samples")
    assert all(capture_hold(r.id) in pool.holds(_file.value) for r in rows)


def test_an_unclassified_alert_is_captured_once_it_is_classified():
    root, _ = _alert_with_yara_matches()

    _disposition(root, DISPOSITION_REVIEWED)
    _run_dispositioned()
    assert capture_rows(root.uuid) == []

    # the module ran on the REVIEWED pass and must run again on this one
    _disposition(root, DISPOSITION_FALSE_POSITIVE)
    _run_dispositioned()
    assert len(capture_rows(root.uuid)) == 2


def test_a_disposition_change_does_not_capture_twice():
    root, _ = _alert_with_yara_matches()

    _disposition(root, DISPOSITION_FALSE_POSITIVE)
    _run_dispositioned()
    first = capture_rows(root.uuid)

    _disposition(root, DISPOSITION_DELIVERY)
    _run_dispositioned()

    assert [r.id for r in capture_rows(root.uuid)] == [r.id for r in first]


def test_an_alert_of_an_unreviewed_run_is_not_captured(monkeypatch):
    root, _ = _alert_with_yara_matches()
    monkeypatch.setattr(svs_module, "unreviewed_run_condition", lambda alert: true())

    _disposition(root, DISPOSITION_FALSE_POSITIVE)
    _run_dispositioned()

    assert capture_rows(root.uuid) == []


def test_an_alert_dispositioned_during_delayed_analysis_is_captured_when_it_finishes():
    """Post-analysis does not run while delayed analysis is outstanding, so capture waits for it."""
    root = create_root_analysis(analysis_mode="test_groups")
    root.initialize_storage()
    # delayed long enough for the dispositioned pass to run first
    root.add_observable_by_spec(F_TEST, "0:03|0:30")
    _file = add_file(root, "attachment.doc")
    add_yara_match(_file)
    root.save()
    root.schedule()
    ALERT(root)

    engine = Engine()
    engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)
    assert get_db().query(DelayedAnalysis.id).count() == 1

    _disposition(root, DISPOSITION_FALSE_POSITIVE)
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_DISPOSITIONED, "test_groups"]))
    # enable_module maps modules by hand, so the capture module has to be named too
    engine.configuration_manager.enable_module("test_delayed_analysis", "test_groups")
    engine.configuration_manager.enable_module("svs_yara_sample_capture", ANALYSIS_MODE_DISPOSITIONED)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    get_db().close()
    assert get_db().query(DelayedAnalysis.id).count() == 0
    (row,) = capture_rows(root.uuid)
    assert row.state == CaptureState.STORED
