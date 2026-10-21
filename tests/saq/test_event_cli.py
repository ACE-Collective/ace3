import argparse
import logging
from unittest.mock import Mock

import pytest

from saq.cli.commands.misc import close_event


@pytest.mark.integration
def test_close_event_failure_is_reported(monkeypatch, caplog):
    write_error_report = Mock()
    monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)
    args = argparse.Namespace(auto=False, event_id=[999999999], dry_run=True)

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
        close_event(args)

    # an event that cannot be closed does not fail the command
    assert exit_info.value.code == 0
    records = [r for r in caplog.records if r.getMessage().startswith("unable to close event 999999999")]
    assert len(records) == 1
    write_error_report.assert_called_once()
