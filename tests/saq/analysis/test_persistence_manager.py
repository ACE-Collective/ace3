import logging
from unittest.mock import Mock

import pytest

from saq.analysis.persistence_manager import AnalysisDetailsPersistenceManager


@pytest.mark.unit
def test_load_details_with_unreadable_json_is_a_warning(tmp_path, monkeypatch, caplog):
    (tmp_path / ".ace").mkdir()
    (tmp_path / ".ace" / "details.json").write_text("{not json")
    manager = AnalysisDetailsPersistenceManager(Mock(storage_dir=str(tmp_path)))
    analysis = Mock(external_details_path="details.json", details_size=None)
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

    with caplog.at_level(logging.WARNING):
        assert manager.load_details(analysis) is False

    # expected while an alert is still being analyzed, since details are flushed as it goes
    records = [r for r in caplog.records if "unable to load json" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    write_error_report.assert_not_called()
