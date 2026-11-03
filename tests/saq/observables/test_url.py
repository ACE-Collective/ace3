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


@pytest.mark.unit
@pytest.mark.parametrize("url", [
    "https:..",
    "http://",
    "HTTPS://..",
    "https:\\\\..\\x",
    "https://user@/path",
    "ftp://:21/file",
])
def test_url_without_host_is_rejected(url):
    assert RootAnalysis().add_observable_by_spec(F_URL, url) is None


@pytest.mark.unit
@pytest.mark.parametrize("url", [
    "https://example.com",
    "HTTP://Evil.com/Path/",
    "http://localhost:6333",
    "https://bücher.example/",
    "http://1.2.3.4/x",
    "http://[2001:db8::1]/x",
    # browsers skip any run of / and \ after the scheme of an http(s) or ftp URL, so these all open a real host
    "https:/x",
    "https:evil.com/x",
    "http:///evil.com/x",
    "https:\\\\evil.com\\x",
    # and drop tab, CR and LF anywhere first, which a Safe Links url=...%09... decodes to
    "https:/\t/evil.com/x",
    "https:\t//evil.com/x",
    # urlsplit refuses these netlocs, but an attacker wrote them and they still name a host
    "http://[x/",
    # schemes that do not name a host, and values without a scheme, are not checked
    "mailto:user@example.com",
    "file:///\\\\host\\share\\doc.dotm",
    "example.com/path",
])
def test_url_with_host_or_without_host_scheme_is_kept(url):
    observable = RootAnalysis().add_observable_by_spec(F_URL, url)
    assert observable is not None
    assert observable.value == url
