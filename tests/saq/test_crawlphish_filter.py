import pytest

from saq.configuration.config import get_config
from saq.crawlphish_filter import REASON_BLACKLISTED, REASON_COMMON_NETWORK, REASON_DIRECT_IPV4, REASON_OK, REASON_WHITELISTED, CrawlphishURLFilter

@pytest.fixture(autouse=True, scope="function")
def reset_crawlphish(tmpdir):
    whitelist_path = str(tmpdir / "test.whitelist")
    get_config()['analysis_module_crawlphish']['whitelist_path'] = whitelist_path

    regex_path = str(tmpdir / "test.regex")
    get_config()['analysis_module_crawlphish']['regex_path'] = regex_path

    blacklist_path = str(tmpdir / "test.blacklist")
    get_config()['analysis_module_crawlphish']['blacklist_path'] = blacklist_path

    with open(blacklist_path, 'w') as fp:
        fp.write('10.0.0.0/8\n')
        fp.write('127.0.0.1\n')
        fp.write('localhost.local\n')

    with open(regex_path, 'w') as fp:
        fp.write('.(pdf|zip|scr|js|cmd|bat|ps1|doc|docx|xls|xlsx|ppt|pptx|exe|vbs|vbe|jse|wsh|cpl|rar|ace|hta)$\n')

    with open(whitelist_path, 'w') as fp:
        fp.write('anonfile.xyz\n')

@pytest.mark.integration
def test_filters():

    _filter = CrawlphishURLFilter()
    _filter.load()

    result = _filter.filter('http://127.0.0.1/blah.exe')
    assert result.filtered
    assert result.reason == REASON_BLACKLISTED

    # test disable blacklist filters
    _filter.blacklist_filter_enabled = False
    result = _filter.filter('http://127.0.0.1/blah.exe')
    assert not result.filtered
    assert result.reason == REASON_DIRECT_IPV4
    _filter.blacklist_filter_enabled = True

    result = _filter.filter('http://10.1.1.1/whatever/test.asp')
    assert result.filtered
    result.reason, REASON_BLACKLISTED

    result = _filter.filter('http://localhost.local/whatever/test.asp')
    assert result.filtered
    assert result.reason == REASON_BLACKLISTED

    result = _filter.filter('http://subdomain.localhost.local/whatever/test.asp')
    assert result.filtered
    assert result.reason == REASON_BLACKLISTED

    result = _filter.filter('http://super.subdomain.localhost.local/whatever/test.asp')
    assert result.filtered
    assert result.reason == REASON_BLACKLISTED

    result = _filter.filter('http://evil.com/phish.pdf')
    assert not result.filtered
    assert result.reason == REASON_WHITELISTED

    result = _filter.filter('http://evil.com/phish.zip')
    assert not result.filtered
    assert result.reason == REASON_WHITELISTED

    result = _filter.filter('http://evil.com/phish.vbs')
    assert not result.filtered
    assert result.reason == REASON_WHITELISTED

    # this would still be blacklisted since blacklisting comes first
    result = _filter.filter('http://127.0.0.1/phish.vbs')
    assert result.filtered
    assert result.reason == REASON_BLACKLISTED

    result = _filter.filter('http://anonfile.xyz')
    assert not result.filtered
    assert result.reason == REASON_WHITELISTED

    result = _filter.filter('http://anonfile.xyz/whatever/')
    assert not result.filtered
    assert result.reason == REASON_WHITELISTED

    # this matches nothing
    result = _filter.filter('http://anonfile.xyz.xyz/whatever/')
    assert not result.filtered
    assert result.reason == REASON_OK

    # always crawl direct ipv4
    result = _filter.filter('http://1.2.3.4/hello.world')
    assert not result.filtered
    assert result.reason == REASON_DIRECT_IPV4
    _filter.direct_ipv4_filter_enabled = False
    result = _filter.filter('http://1.2.3.4/hello.world')
    assert not result.filtered
    assert result.reason == REASON_OK
    _filter.direct_ipv4_filter_enabled = True
    
    result = _filter.filter('http://test1.local')
    assert result.filtered
    assert result.reason == REASON_COMMON_NETWORK
    _filter.common_filter_enabled = False
    result = _filter.filter('http://test1.local')
    assert not result.filtered
    assert result.reason == REASON_OK
    _filter.common_filter_enabled = True
    
    result = _filter.filter('http://test2.local')
    assert not result.filtered
    assert result.reason == REASON_OK
