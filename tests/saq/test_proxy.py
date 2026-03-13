import pytest

from saq.configuration.config import get_config
from saq.configuration.schema import ProxyConfig
from saq.proxy import proxies, proxy_string_for_seleniumbase

INVALID_KEY = "WrongKey"

@pytest.mark.unit
def test_wrong_key_raises():
    with pytest.raises(ValueError):
        proxy = proxies(INVALID_KEY)

@pytest.mark.unit
def test_proxy_config(monkeypatch):
    mock_proxy_config = ProxyConfig(name="default", transport="http", host="proxy.local", port=3128)
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("default", mock_proxy_config)
    monkeypatch.setattr(get_config().global_settings, "default_proxy", "default")

    assert proxies() == {
        'http': 'http://proxy.local:3128',
        'https': 'http://proxy.local:3128',
    }

    mock_proxy_config.user = "ace"
    mock_proxy_config.password = "1234"

    assert proxies() == {
        'http': 'http://ace:1234@proxy.local:3128',
        'https': 'http://ace:1234@proxy.local:3128',
    }


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_none():
    """Returns None when proxy_name is None."""
    assert proxy_string_for_seleniumbase(None) is None


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_http_no_auth():
    """HTTP proxy without auth returns host:port."""
    config = ProxyConfig(name="test", transport="http", host="proxy.example.com", port=8080)
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("test", config)

    result = proxy_string_for_seleniumbase("test")
    assert result == "proxy.example.com:8080"


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_http_with_auth():
    """HTTP proxy with auth returns user:pass@host:port."""
    config = ProxyConfig(name="test", transport="http", host="proxy.example.com", port=8080, user="myuser", password="mypass")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("test", config)

    result = proxy_string_for_seleniumbase("test")
    assert result == "myuser:mypass@proxy.example.com:8080"


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_socks5_no_auth():
    """SOCKS5 proxy without auth returns socks5://host:port."""
    config = ProxyConfig(name="test", transport="socks5", host="socks.example.com", port=1080)
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("test", config)

    result = proxy_string_for_seleniumbase("test")
    assert result == "socks5://socks.example.com:1080"


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_socks5_with_auth():
    """SOCKS5 proxy with auth returns socks5://user:pass@host:port."""
    config = ProxyConfig(name="test", transport="socks5", host="socks.example.com", port=1080, user="suser", password="spass")
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("test", config)

    result = proxy_string_for_seleniumbase("test")
    assert result == "socks5://suser:spass@socks.example.com:1080"


@pytest.mark.unit
def test_proxy_string_for_seleniumbase_special_chars_not_encoded():
    """Credentials with special characters must NOT be URL-encoded for SeleniumBase."""
    config = ProxyConfig(
        name="test", transport="http", host="proxy.example.com", port=8080,
        user="admin", password="my+pass/word"
    )
    get_config().clear_proxy_configs()
    get_config().add_proxy_config("test", config)

    result = proxy_string_for_seleniumbase("test")
    assert result == "admin:my+pass/word@proxy.example.com:8080"
