import pytest

from email.header import Header

from saq.email import decode_rfc2822, is_local_email_domain, normalize_email_address, normalize_message_id

@pytest.mark.parametrize('email_address, expected_result', [
    ('test@localdomain', True),
    ('test@host.localdomain', True),
    ('test@otherdomain', False),
    ('"Test User" <test@localdomain>', True)])
@pytest.mark.integration
def test_is_local_email_domain(email_address, expected_result):
    assert is_local_email_domain(email_address) == expected_result

@pytest.mark.parametrize("source, target", [
    ('"user name" <TEST@USER.COM>', 'test@user.com'),
    (Header('soc@radarblows.com'), 'soc@radarblows.com'),
    (Header('<<soc@radarblows.com>>'), 'soc@radarblows.com'),
    (None, None),
])
@pytest.mark.unit
def test_normalize_email_address(source, target):
    assert normalize_email_address(source) == target

@pytest.mark.parametrize("source, target", [
    ('=?Windows-1252?Q?Money_Talk_=96_Profit=99_Performance_Monitor_(Honeywell_?= =?Windows-1252?Q?Webinar)?=', 
                        'Money Talk – Profit™ Performance Monitor (Honeywell Webinar)'),
])
@pytest.mark.unit
def test_decode_rfc2822(source: str, target: str):
    assert decode_rfc2822(source) == target

# TODO - move check_message_id to shared location as well as the tests for it.
@pytest.mark.parametrize("message_id", [
    '<this_is_fake@local.local',
    ' this_is_fake@local.local>\n',
    Header('this_is_fake@local.local'),
])
@pytest.mark.unit
def test_normalize_message_id_no_brackets(message_id):
    assert normalize_message_id(message_id) == "<this_is_fake@local.local>"

@pytest.mark.unit
def test_normalize_message_id_none():
    assert normalize_message_id(None) is None