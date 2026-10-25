import pytest

from saq.analysis import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import F_URL


@pytest.mark.unit
@pytest.mark.parametrize("url, managed", [
    ("https://intranet.local.example/login", True),
    ("https://bücher.local.example/", True),
    ("https://mail.example.org/owa", True),
    ("https://local.example.evil.net/login", False),
])
def test_url_is_managed(monkeypatch, url, managed):
    monkeypatch.setattr(get_config().global_settings, "local_domains", ["local.example"])
    monkeypatch.setattr(get_config().global_settings, "local_email_domains", ["example.org"])
    observable = RootAnalysis().add_observable_by_spec(F_URL, url)
    assert observable.is_managed() is managed
