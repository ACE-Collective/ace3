import logging
import os

import pytest

from saq.whitelist import (
    BrotexWhitelist,
    WHITELIST_TYPE_HTTP_DEST_IP,
    WHITELIST_TYPE_HTTP_HOST,
    WHITELIST_TYPE_HTTP_SRC_IP,
    WHITELIST_TYPE_SMTP_FROM,
    WHITELIST_TYPE_SMTP_TO,
)


def _load(tmp_path, content: str) -> BrotexWhitelist:
    path = tmp_path / "brotex.whitelist"
    path.write_text(content)
    whitelist = BrotexWhitelist(str(path))
    whitelist.check_whitelist()
    return whitelist


@pytest.mark.unit
def test_load_skips_comments_and_bad_lines(tmp_path, caplog):
    whitelist = _load(tmp_path, "\n".join([
        "# a comment",
        "",
        "no separator here",
        "bogus_key:value",
        "smtp_from:   ",
        "smtp_from: sender@example.com ",
        "smtp_to:rcpt@example.com",
    ]))

    assert whitelist.whitelist == {
        WHITELIST_TYPE_SMTP_FROM: {"sender@example.com"},
        WHITELIST_TYPE_SMTP_TO: {"rcpt@example.com"},
    }
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert any("unable to parse whitelist item no separator here" in m for m in errors)
    assert "invalid whitelist key bogus_key" in errors
    assert "empty or all whitelist value for smtp_from" in errors


@pytest.mark.unit
def test_email_addresses_match_case_insensitive_substring(tmp_path):
    whitelist = _load(tmp_path, "smtp_from:Example.com\nsmtp_to:rcpt@example.org\n")

    assert whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, "Someone <someone@EXAMPLE.COM>")
    assert not whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_FROM, "someone@example.net")
    assert whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, "RCPT@example.org")
    assert not whitelist.is_whitelisted(WHITELIST_TYPE_SMTP_TO, "other@example.org")


@pytest.mark.unit
def test_fqdn_matches_by_suffix(tmp_path):
    whitelist = _load(tmp_path, "http_host:example.com\n")

    assert whitelist.is_whitelisted(WHITELIST_TYPE_HTTP_HOST, "www.EXAMPLE.com")
    assert not whitelist.is_whitelisted(WHITELIST_TYPE_HTTP_HOST, "example.com.evil.net")


@pytest.mark.unit
@pytest.mark.parametrize("_type", [WHITELIST_TYPE_HTTP_SRC_IP, WHITELIST_TYPE_HTTP_DEST_IP])
def test_ip_ranges(tmp_path, caplog, _type):
    whitelist = _load(tmp_path, f"{_type}:10.0.0.0/8\n{_type}:not an ip\n{_type}:192.168.1.1\n")

    assert whitelist.is_whitelisted(_type, "10.1.2.3")
    assert whitelist.is_whitelisted(_type, "192.168.1.1")
    assert not whitelist.is_whitelisted(_type, "192.168.1.2")
    assert any("unable to translate not an ip" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
@pytest.mark.parametrize("_type", [WHITELIST_TYPE_HTTP_SRC_IP, WHITELIST_TYPE_HTTP_DEST_IP])
def test_invalid_ip_ranges_are_dropped(tmp_path, _type):
    # the raw strings must not stay behind, or an ip would be matched as a substring of them
    whitelist = _load(tmp_path, f"{_type}:10.0.0.0/8x\n")

    assert whitelist.whitelist[_type] == set()
    assert not whitelist.is_whitelisted(_type, "10.0.0.0")


@pytest.mark.unit
@pytest.mark.parametrize("_type", [
    WHITELIST_TYPE_SMTP_FROM,
    WHITELIST_TYPE_SMTP_TO,
    WHITELIST_TYPE_HTTP_HOST,
    WHITELIST_TYPE_HTTP_SRC_IP,
    WHITELIST_TYPE_HTTP_DEST_IP,
])
def test_nothing_is_whitelisted_for_a_type_without_entries(tmp_path, _type):
    whitelist = _load(tmp_path, "# empty\n")

    assert not whitelist.is_whitelisted(_type, "10.0.0.1")


@pytest.mark.unit
def test_unknown_type_is_not_whitelisted(tmp_path, caplog):
    whitelist = _load(tmp_path, "smtp_from:example.com\n")

    assert not whitelist.is_whitelisted("bogus", "example.com")
    assert "OOPS no whitelist compare function for type bogus" in caplog.text


@pytest.mark.unit
def test_check_whitelist_reloads_only_when_modified(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    whitelist = _load(tmp_path, "smtp_from:old.example.com\n")
    path = whitelist.whitelist_path

    whitelist.check_whitelist()
    assert "brotex whitelist modified" not in caplog.text

    with open(path, "w") as fp:
        fp.write("smtp_from:new.example.com\n")
    mtime = whitelist.whitelist_timestamp + 10
    os.utime(path, (mtime, mtime))
    whitelist.check_whitelist()

    assert "brotex whitelist modified - loading new whitelist values" in caplog.text
    assert whitelist.whitelist == {WHITELIST_TYPE_SMTP_FROM: {"new.example.com"}}
