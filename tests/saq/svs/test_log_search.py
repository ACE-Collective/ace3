"""svs.log_search_url: what the config accepts, and the window a run's search covers
(saq.svs.log_search)."""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from saq.configuration.schema import SVSConfig
from saq.database.model import SVSRun
from saq.svs.log_search import log_search_window

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 15, 12, 0, 0)


@pytest.mark.parametrize("template", [
    "https://logs.example/?q=svs_run%3D{run_uuid}",
    "http://logs.example/{marker}/{test_guid}?from={earliest}&to={latest}",
    "https://logs.example/?q={{literal}}",
])
def test_accepted(template):
    assert SVSConfig(log_search_url=template).log_search_url == template


@pytest.mark.parametrize("template", [
    "https://logs.example/{run}",           # not one of the names
    "https://logs.example/{0}",             # positional
    "https://logs.example/{}",
    "https://logs.example/{run_uuid!r}",    # a conversion
    "https://logs.example/{earliest:>12}",  # a format spec
    "https://logs.example/{run_uuid.hex}",  # an attribute
    "https://logs.example/{",               # not a template
    "javascript:alert({run_uuid})",         # it becomes a link
])
def test_refused(template):
    with pytest.raises(ValidationError):
        SVSConfig(log_search_url=template)


def test_unset():
    assert SVSConfig().log_search_url is None
    assert SVSConfig(log_search_url="").log_search_url is None


def _run(**values) -> SVSRun:
    return SVSRun(created_at=NOW - timedelta(hours=10), **values)


def test_the_window():
    started = NOW - timedelta(hours=9)
    # registered, not started: from its registration until now
    assert log_search_window(_run(), NOW) == (NOW - timedelta(hours=10), NOW)
    # inside its attribution window: until now
    assert log_search_window(_run(started_at=started, attribution_ends_at=NOW + timedelta(hours=1)), NOW) == (
        started, NOW)
    # past it: until it ended
    assert log_search_window(_run(started_at=started, attribution_ends_at=NOW - timedelta(hours=1)), NOW) == (
        started, NOW - timedelta(hours=1))
    # canceled before it started
    assert log_search_window(_run(canceled_at=NOW - timedelta(hours=8)), NOW) == (
        NOW - timedelta(hours=10), NOW - timedelta(hours=8))
