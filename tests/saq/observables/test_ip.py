import pytest

from saq.analysis import RootAnalysis, Observable
from saq.constants import F_IP, F_IP_CONVERSATION
from saq.observables.base import ObservableValueError
from saq.observables.network.ip import IPObservable, IPConversationObservable
from saq.environment import get_global_runtime_settings


# IPObservable Tests

@pytest.mark.unit
def test_ip_observable_valid_ipv4():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o is not None
    assert o.value == "192.168.1.1"
    assert isinstance(o, IPObservable)


@pytest.mark.unit
def test_ip_observable_valid_ipv6():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert o is not None
    assert o.value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


@pytest.mark.unit
def test_ip_observable_whitespace():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "  192.168.1.1  ")
    assert o is not None
    assert o.value == "192.168.1.1"


@pytest.mark.unit
def test_ip_observable_invalid():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "not_an_ip")
    assert o is None


@pytest.mark.parametrize("value,expected", [
    ("192.168.1.1", "192.168.1.1"),
    ("10.0.0.1", "10.0.0.1"),
    ("8.8.8.8", "8.8.8.8"),
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("::1", "::1"),
    ("fe80::1", "fe80::1"),
    ("256.1.1.1", None),
    ("1.1.1", None),
    ("not_an_ip", None),
    ("", None),
    ("gggg::1", None),
])
@pytest.mark.unit
def test_ip_observable_validation(value, expected):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, value)
    if expected is None:
        assert o is None
    else:
        assert o is not None
        assert o.value == expected


@pytest.mark.unit
def test_is_managed_true(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "managed_network_cidrs", ["192.168.0.0/16", "10.0.0.0/8"])

    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o.is_managed() is True

    o2 = root.add_observable_by_spec(F_IP, "10.5.10.20")
    assert o2.is_managed() is True


@pytest.mark.unit
def test_is_managed_false(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "managed_network_cidrs", ["192.168.0.0/16", "10.0.0.0/8"])

    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "8.8.8.8")
    assert o.is_managed() is False


@pytest.mark.unit
def test_is_managed_ipv6(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "managed_network_cidrs", ["2001:db8::/32"])

    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "2001:db8::1")
    assert o.is_managed() is True

    o2 = root.add_observable_by_spec(F_IP, "2001:0db9::1")
    assert o2.is_managed() is False


@pytest.mark.unit
def test_is_managed_empty_list(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "managed_network_cidrs", [])

    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o.is_managed() is False


@pytest.mark.unit
def test_matches_exact():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o.matches("192.168.1.1") is True


@pytest.mark.unit
def test_matches_cidr_ipv4():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.50")
    assert o.matches("192.168.1.0/24") is True
    assert o.matches("192.168.0.0/16") is True
    assert o.matches("10.0.0.0/8") is False


@pytest.mark.unit
def test_matches_cidr_ipv6():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "2001:db8::1")
    assert o.matches("2001:db8::/32") is True
    assert o.matches("2001:db9::/32") is False


@pytest.mark.unit
def test_matches_no_match():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o.matches("192.168.1.2") is False


@pytest.mark.unit
def test_matches_invalid_cidr():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    # should not crash with invalid CIDR notation
    assert o.matches("not_a_valid_cidr/32") is False


@pytest.mark.unit
def test_ip_observable_json_roundtrip():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")

    # serialize and deserialize
    o2 = Observable.from_json(o.json)
    assert o2.value == "192.168.1.1"
    assert o2.type == F_IP


# IPConversationObservable Tests

@pytest.mark.unit
def test_ip_conversation_valid():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, "192.168.1.1_192.168.1.2")
    assert o is not None
    assert o.value == "192.168.1.1_192.168.1.2"
    assert isinstance(o, IPConversationObservable)


@pytest.mark.unit
def test_ip_conversation_properties():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, "192.168.1.1_10.0.0.1")
    assert o.source == "192.168.1.1"
    assert o.destination == "10.0.0.1"


@pytest.mark.unit
def test_ip_conversation_whitespace():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, "  192.168.1.1_192.168.1.2  ")
    assert o.value == "192.168.1.1_192.168.1.2"


@pytest.mark.parametrize("value,expected_source,expected_dest", [
    ("192.168.1.1_192.168.1.2", "192.168.1.1", "192.168.1.2"),
    ("10.0.0.1_8.8.8.8", "10.0.0.1", "8.8.8.8"),
    ("2001:db8::1_2001:db8::2", "2001:db8::1", "2001:db8::2"),
])
@pytest.mark.unit
def test_ip_conversation_valid_formats(value, expected_source, expected_dest):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, value)
    assert o is not None
    assert o.source == expected_source
    assert o.destination == expected_dest


@pytest.mark.parametrize("value", [
    "192.168.1.1",  # missing separator
    "192.168.1.1_192.168.1.2_extra",  # too many parts
    "_192.168.1.1",  # missing source
    "192.168.1.1_",  # missing destination
    "",  # empty string
])
@pytest.mark.unit
def test_ip_conversation_invalid_formats(value):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, value)
    assert o is None


@pytest.mark.unit
def test_ip_conversation_invalid_format_direct():
    with pytest.raises(ObservableValueError):
        IPConversationObservable("no_separator_here")


@pytest.mark.unit
def test_ip_conversation_missing_separator():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, "192.168.1.1")
    assert o is None


@pytest.mark.unit
def test_ip_conversation_json_roundtrip():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, "192.168.1.1_10.0.0.1")

    # serialize and deserialize
    o2 = Observable.from_json(o.json)
    assert o2.value == "192.168.1.1_10.0.0.1"
    assert o2.type == F_IP_CONVERSATION
    assert o2.source == "192.168.1.1"
    assert o2.destination == "10.0.0.1"


@pytest.mark.parametrize("value", [
    "not_an_ip_1.2.3.4",  # invalid source IP
    "192.168.1.1_not_an_ip",  # invalid dest IP
])
@pytest.mark.unit
def test_ip_conversation_invalid_ips(value):
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP_CONVERSATION, value)
    assert o is None


# Observable Registration Tests

@pytest.mark.unit
def test_observable_types_registered():
    root = RootAnalysis()

    # test F_IP is registered
    o1 = root.add_observable_by_spec(F_IP, "192.168.1.1")
    assert o1 is not None
    assert isinstance(o1, IPObservable)

    # test F_IP_CONVERSATION is registered
    o2 = root.add_observable_by_spec(F_IP_CONVERSATION, "192.168.1.1_192.168.1.2")
    assert o2 is not None
    assert isinstance(o2, IPConversationObservable)
