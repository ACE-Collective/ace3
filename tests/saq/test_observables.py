import pytest

from saq.analysis import RootAnalysis, Observable
from saq.constants import F_EMAIL_ADDRESS, F_EMAIL_DELIVERY, F_FILE_LOCATION, F_IP, F_MD5, F_MESSAGE_ID, F_SHA1, F_SHA256, F_USER, F_YARA_STRING
from saq.util.hashing import EMPTY_CONTENT_MD5, EMPTY_CONTENT_SHA1, EMPTY_CONTENT_SHA256

@pytest.mark.unit
def test_observables():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_MESSAGE_ID, '0100017508099fde-100fa3e5-c4b7-4fdc-b5ba-2a90040b0900-000000@email.amazonses.com')
    assert o.value == '<0100017508099fde-100fa3e5-c4b7-4fdc-b5ba-2a90040b0900-000000@email.amazonses.com>'

@pytest.mark.parametrize('address,expected_value', [
    ('', None),
    ('john_doe@company.com', 'john_doe@company.com'),
    ('"John Doe" <john_doe@company.com>', 'john_doe@company.com'),
    ('invalid_email@.@company.com', 'invalid_email@.@company.com'),
    ('invalid_email_AT_company.com', None),
])
@pytest.mark.unit
def test_email_address(address, expected_value):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_EMAIL_ADDRESS, address) 
    if expected_value is None:
        assert o is None
    else:
        assert o.value == expected_value

@pytest.mark.parametrize('value,expected_result', [
    ('<message_id>|john@company.com', ('<message_id>', 'john@company.com')), # valid
    ('<message_id>_john@company.com', None), # invalid: no sep
    ('<message_id>|', None), # invalid: no email address
    ('|john@company.com', None), # invalid: no message-id
    ('<message_id>|"John Smith" <john@company.com>', ('<message_id>', 'john@company.com')), # normalize email address
    ('message_id|john@company.com', ('<message_id>', 'john@company.com')), # normalize message-id
])
@pytest.mark.unit
def test_email_delivery(value, expected_result):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_EMAIL_DELIVERY, value)
    if expected_result is None:
        assert o is None
    else:
        assert o.message_id == expected_result[0]
        assert o.email_address == expected_result[1]


@pytest.mark.parametrize('value,expected', [
    (r'PCN31337@C:\users\lol.txt', ('PCN31337', r'C:\users\lol.txt')),  # valid
    ('PCN31337@', None),             # invalid: no path
    ('@C:\\users\\lol.txt', None),   # invalid: no hostname
    ('PCN31337', None),              # invalid: no @ separator
    ('@', None),                     # invalid: neither
])
@pytest.mark.unit
def test_file_location(value, expected):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_FILE_LOCATION, value)
    if expected is None:
        assert o is None
    else:
        assert o.hostname == expected[0]
        assert o.full_path == expected[1]


@pytest.mark.parametrize('initial_value,expected_value', [
    ('testuser', 'testuser'),
    ('testdomain\\testuser', 'testuser'),
])
@pytest.mark.unit
def test_user_observable(initial_value, expected_value):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_USER, initial_value)
    assert o.value == expected_value


@pytest.mark.parametrize('value', ['', '   ', '\t\n'])
@pytest.mark.unit
def test_empty_value_user_observable_rejected(value):
    """A user observable with an empty/whitespace-only value must not be added.

    Reproduces a production alert where a hunt added a `user` observable with an
    empty value. UserObservable is a CaselessObservable with no empty-value guard
    of its own, so the rejection happens centrally in ObservableRegistry.record().
    """
    root = RootAnalysis()
    assert root.add_observable_by_spec(F_USER, value) is None


@pytest.mark.unit
def test_empty_value_generic_observable_rejected():
    """Unknown/generic observable types (DefaultObservable) must also reject empty values."""
    root = RootAnalysis()
    assert root.add_observable_by_spec('some_unknown_type', '') is None
    assert root.add_observable_by_spec('some_unknown_type', '   ') is None


@pytest.mark.unit
def test_non_empty_user_observable_still_added():
    """A valid user observable is still added and dedupes as before."""
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_USER, 'testuser')
    assert o is not None
    assert o.value == 'testuser'
    # adding the same value again returns the existing observable
    assert root.add_observable_by_spec(F_USER, 'testuser') is o


@pytest.mark.unit
def test_message_id_observable(caplog):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_MESSAGE_ID, '<$null>')
    assert o is None

    o = root.add_observable_by_spec(F_MESSAGE_ID, 'asdf@asdf.com')
    assert o.value == '<asdf@asdf.com>'

@pytest.mark.parametrize('o_type,valid_value,empty_content_hash', [
    (F_MD5, 'a3aa6e1cf9973fd30868021b2dd7b5cf', EMPTY_CONTENT_MD5),
    (F_SHA1, '9d8f22a2d1a9d8a4f43b1c4b8a0ef5d0b3d1a3c5', EMPTY_CONTENT_SHA1),
    (F_SHA256, '90645b5c3c279e2c40649c72915575ca98c1f73a53fe3bdbf9d0b991dfc03924', EMPTY_CONTENT_SHA256),
])
@pytest.mark.unit
def test_hash_observable_refuses_placeholder_values(o_type, valid_value, empty_content_hash):
    root = RootAnalysis()
    o = root.add_observable_by_spec(o_type, valid_value)
    assert o is not None
    assert o.value == valid_value

    # surrounding whitespace is stripped
    assert root.add_observable_by_spec(o_type, f' {valid_value} ') is o

    # all-zero placeholder hashes
    assert root.add_observable_by_spec(o_type, '0' * len(valid_value)) is None

    # the hash of zero-length content, in any case
    assert root.add_observable_by_spec(o_type, empty_content_hash) is None
    assert root.add_observable_by_spec(o_type, empty_content_hash.upper()) is None
    assert root.add_observable_by_spec(o_type, f' {empty_content_hash} ') is None

@pytest.mark.unit
def test_yara_string_observable():
    from saq.observables import YaraStringObservable, ObservableValueError
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_YARA_STRING, "rule:$string")
    assert o
    assert o.value == "rule:$string"
    assert o.rule == "rule"
    assert o.string == "$string"

    with pytest.raises(ObservableValueError):
        YaraStringObservable("test")

    assert root.add_observable_by_spec(F_YARA_STRING, "") is None

@pytest.mark.unit
def test_volatile():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, '1.2.3.4', volatile=True)
    assert o.volatile
    assert Observable.from_json(o.json).volatile
