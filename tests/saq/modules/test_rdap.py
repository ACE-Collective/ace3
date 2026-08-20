import json
from datetime import datetime, timezone

import pytest
from whois.exceptions import PywhoisError
from whoisit.errors import (
    BootstrapError,
    QueryError,
    ResourceDoesNotExist,
    UnsupportedError,
)

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_RDAP_ANALYZER,
    F_FQDN,
    F_IP,
    AnalysisExecutionResult,
)
from saq.json_encoding import _JSONEncoder
from saq.modules.rdap import RdapAnalysis, RdapAnalyzer, _registrable_domain
from tests.saq.helpers import create_root_analysis

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_rdap(monkeypatch, fn):
    """Patch ``whoisit.domain`` and short-circuit the bootstrap check."""
    monkeypatch.setattr("saq.modules.rdap.whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.bootstrap", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.domain", fn)


def _patch_rdap_ip(monkeypatch, fn):
    """Patch ``whoisit.ip`` and short-circuit the bootstrap check."""
    monkeypatch.setattr("saq.modules.rdap.whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.bootstrap", lambda: True)
    monkeypatch.setattr("saq.modules.rdap.whoisit.ip", fn)


def _patch_whois(monkeypatch, fn):
    monkeypatch.setattr("saq.modules.rdap.whois.whois", fn)


def _patch_whois_must_not_be_called(monkeypatch):
    def _explode(_domain):
        raise AssertionError("whois.whois must not be called for this case")

    monkeypatch.setattr("saq.modules.rdap.whois.whois", _explode)


class _MockWhoisResult(dict):
    """Stand-in for python-whois' ``WhoisEntry`` (dict subclass with
    a ``.text`` attribute)."""

    def __init__(self, data):
        super().__init__(data)
        self.text = data.get("text", "mock whois text")


def _make_rdap_result(**overrides):
    """Build a realistic whoisit.domain() return dict."""
    result = {
        "name": "EXAMPLE.COM",
        "url": "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM",
        "rir": "iana",
        "nameservers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
        "status": ["client transfer prohibited"],
        "registration_date": datetime(1995, 8, 14, 4, 0, tzinfo=timezone.utc),
        "last_changed_date": datetime(2024, 8, 14, 7, 1, 34, tzinfo=timezone.utc),
        "expiration_date": datetime(2026, 8, 13, 4, 0, tzinfo=timezone.utc),
        "entities": {
            "registrar": [
                {"name": "RESERVED-Internet Assigned Numbers Authority",
                 "email": "registrar@example.test"},
            ],
            "abuse": [
                {"name": "Abuse Contact", "email": "abuse@example.test"},
            ],
        },
        "raw": {"objectClassName": "domain", "ldhName": "EXAMPLE.COM"},
    }
    result.update(overrides)
    return result


def _make_rdap_ip_result(**overrides):
    """Build a realistic whoisit.ip() return dict.

    Mirrors the flat-dict shape ``whoisit.ip()`` produces: network
    identity/CIDR/country fields plus the shared date/entity/url fields.
    For IPs the entity roles are typically ``registrant``/``abuse``
    (no ``registrar`` role), so ``registrar`` extraction yields None.
    """
    from ipaddress import IPv4Network

    result = {
        "name": "GOGL",
        "handle": "GOGL",
        "parent_handle": "NET8",
        "type": "ip network",
        "country": "US",
        "ip_version": 4,
        "assignment_type": "direct allocation",
        "network": IPv4Network("8.8.8.0/24"),
        "url": "https://rdap.arin.net/registry/ip/8.8.8.0",
        "rir": "arin",
        "registration_date": datetime(2009, 3, 30, tzinfo=timezone.utc),
        "last_changed_date": datetime(2012, 2, 24, tzinfo=timezone.utc),
        "expiration_date": None,
        "entities": {
            "registrant": [
                {"name": "Google LLC", "email": "arin-contact@google.test"},
            ],
            "abuse": [
                {"name": "Abuse", "email": "network-abuse@google.test"},
            ],
        },
        "raw": {"objectClassName": "ip network", "handle": "NET-8-8-8-0-1"},
    }
    result.update(overrides)
    return result


def _make_analyzer(test_context):
    return RdapAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER),
    )


# ---------------------------------------------------------------------------
# RdapAnalysis dataclass-ish
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analysis_properties():
    """All declared properties round-trip through the details dict."""
    analysis = RdapAnalysis()

    assert analysis.error is None
    assert analysis.lookup_protocol is None
    assert analysis.rdap_attempt_error is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    assert analysis.datetime_created is None
    assert analysis.datetime_expiration is None
    assert analysis.datetime_of_analysis is None
    assert analysis.datetime_of_last_update is None
    assert analysis.domain_name is None
    assert analysis.registrar is None
    assert analysis.rdap_service_url is None
    assert analysis.name_servers is None
    assert analysis.emails is None
    assert analysis.network_cidr is None
    assert analysis.network_name is None
    assert analysis.country is None
    assert analysis.ip_version is None
    assert analysis.assignment_type is None
    assert analysis.rdap_data is None
    assert analysis.rdap_raw_json is None
    assert analysis.whois_data is None
    assert analysis.whois_raw_text is None

    analysis.error = "test error"
    assert analysis.error == "test error"

    analysis.lookup_protocol = "rdap"
    assert analysis.lookup_protocol == "rdap"

    analysis.rdap_attempt_error = "transient bootstrap blip"
    assert analysis.rdap_attempt_error == "transient bootstrap blip"

    analysis.age_created_in_days = "30"
    assert analysis.age_created_in_days == "30"

    analysis.age_last_updated_in_days = "5"
    assert analysis.age_last_updated_in_days == "5"

    analysis.datetime_created = "2023-01-01 00:00:00"
    assert analysis.datetime_created == "2023-01-01 00:00:00"

    analysis.datetime_expiration = "2030-01-01 00:00:00"
    assert analysis.datetime_expiration == "2030-01-01 00:00:00"

    analysis.datetime_of_analysis = "2023-01-31 12:00:00"
    assert analysis.datetime_of_analysis == "2023-01-31 12:00:00"

    analysis.datetime_of_last_update = "2023-01-25 10:00:00"
    assert analysis.datetime_of_last_update == "2023-01-25 10:00:00"

    analysis.domain_name = "example.com"
    assert analysis.domain_name == "example.com"

    analysis.registrar = "Test Registrar"
    assert analysis.registrar == "Test Registrar"

    analysis.rdap_service_url = "https://rdap.example.com/"
    assert analysis.rdap_service_url == "https://rdap.example.com/"

    analysis.name_servers = ["ns1.example.com", "ns2.example.com"]
    assert analysis.name_servers == ["ns1.example.com", "ns2.example.com"]

    analysis.emails = ["admin@example.com"]
    assert analysis.emails == ["admin@example.com"]

    rdap_payload = {"name": "example.com"}
    analysis.rdap_data = rdap_payload
    assert analysis.rdap_data == rdap_payload

    analysis.rdap_raw_json = '{"objectClassName": "domain"}'
    assert analysis.rdap_raw_json == '{"objectClassName": "domain"}'

    whois_payload = {"domain_name": "example.com"}
    analysis.whois_data = whois_payload
    assert analysis.whois_data == whois_payload

    analysis.whois_raw_text = "raw whois blob"
    assert analysis.whois_raw_text == "raw whois blob"


@pytest.mark.unit
def test_rdap_analysis_generate_summary_with_error():
    analysis = RdapAnalysis()
    analysis.error = "domain not found"

    assert analysis.generate_summary() == "RDAP Analysis: error: domain not found"


@pytest.mark.unit
def test_rdap_analysis_generate_summary_success_rdap():
    analysis = RdapAnalysis()
    analysis.lookup_protocol = "rdap"
    analysis.age_created_in_days = "30"
    analysis.age_last_updated_in_days = "5"
    analysis.name_servers = ["ns1.example.com", "ns2.example.com"]
    analysis.registrar = "Test Registrar"
    analysis.rdap_service_url = "https://rdap.example.com/"
    analysis.emails = ["admin@example.com", "tech@example.com"]

    summary = analysis.generate_summary()
    expected = (
        "RDAP Analysis: created: 30 day(s) ago, "
        "last updated: 5 day(s) ago, "
        "nameservers: (ns1.example.com, ns2.example.com), "
        "registrar: Test Registrar, "
        "rdap service: https://rdap.example.com/, "
        "emails: (admin@example.com, tech@example.com)"
    )
    assert summary == expected


@pytest.mark.unit
def test_rdap_analysis_generate_summary_success_whois_fallback():
    """Summary makes the fallback path visible to analysts."""
    analysis = RdapAnalysis()
    analysis.lookup_protocol = "whois"
    analysis.age_created_in_days = "30"
    analysis.registrar = "Test Registrar"

    summary = analysis.generate_summary()
    assert summary == (
        "RDAP Analysis (whois fallback): created: 30 day(s) ago, "
        "registrar: Test Registrar"
    )


@pytest.mark.unit
def test_rdap_analysis_generate_summary_empty():
    assert RdapAnalysis().generate_summary() is None


@pytest.mark.unit
def test_rdap_analyzer_properties():
    analyzer = RdapAnalyzer(
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER)
    )
    assert analyzer.generated_analysis_type == RdapAnalysis
    assert analyzer.valid_observable_types == [F_FQDN, F_IP]


# ---------------------------------------------------------------------------
# custom_requirement (non-routable IP skip)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "10.1.2.3",        # RFC1918
        "172.16.5.5",      # RFC1918
        "192.168.1.1",     # RFC1918
        "127.0.0.1",       # loopback
        "169.254.10.10",   # link-local
        "100.64.0.1",      # CGNAT shared address space
        "::1",             # IPv6 loopback
        "fe80::1",         # IPv6 link-local
    ],
)
def test_rdap_analyzer_skips_non_routable_ip(value):
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, value)

    analyzer = RdapAnalyzer(
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER)
    )
    assert analyzer.custom_requirement(observable) is False


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_rdap_analyzer_accepts_routable_ip(value):
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, value)

    analyzer = RdapAnalyzer(
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER)
    )
    assert analyzer.custom_requirement(observable) is True


@pytest.mark.unit
def test_rdap_analyzer_custom_requirement_ignores_fqdn():
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "intranet.example.com")

    analyzer = RdapAnalyzer(
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER)
    )
    assert analyzer.custom_requirement(observable) is True


@pytest.mark.unit
def test_rdap_analyzer_custom_requirement_unparseable_ip():
    # IPObservable validates its value, so this can't happen through the
    # normal observable path — defensive branch only.
    class _FakeObservable:
        type = F_IP
        value = "not-an-ip"

    analyzer = RdapAnalyzer(
        config=get_analysis_module_config(ANALYSIS_MODULE_RDAP_ANALYZER)
    )
    assert analyzer.custom_requirement(_FakeObservable()) is True


# ---------------------------------------------------------------------------
# Happy-path RDAP
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analyzer_success(test_context, monkeypatch):
    rdap_result = _make_rdap_result()
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.lookup_protocol == "rdap"
    assert analysis.rdap_attempt_error is None

    assert analysis.domain_name == "EXAMPLE.COM"
    assert analysis.registrar == "RESERVED-Internet Assigned Numbers Authority"
    assert analysis.name_servers == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
    assert analysis.emails == ["abuse@example.test", "registrar@example.test"]
    assert analysis.rdap_service_url == "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM"

    assert analysis.datetime_created is not None
    assert analysis.age_created_in_days is not None
    assert analysis.age_created_in_days.isdigit()
    assert analysis.datetime_of_last_update is not None
    assert analysis.age_last_updated_in_days is not None
    assert analysis.datetime_expiration == "2026-08-13 04:00:00+00:00"
    assert analysis.datetime_of_analysis is not None

    # WHOIS fallback fields stay None.
    assert analysis.whois_data is None
    assert analysis.whois_raw_text is None

    # rdap_data is the parsed dict (with raw stripped out and stored
    # separately as JSON).
    assert isinstance(analysis.rdap_data, dict)
    assert "raw" not in analysis.rdap_data
    assert analysis.rdap_raw_json is not None
    assert "objectClassName" in analysis.rdap_raw_json


@pytest.mark.unit
def test_rdap_analyzer_extracts_expiration(test_context, monkeypatch):
    """The legacy WHOIS module declared KEY_DATETIME_EXPIRATION but
    never set it. The RDAP module must populate it from
    ``expiration_date`` when present.
    """
    rdap_result = _make_rdap_result(
        expiration_date=datetime(2030, 1, 1, tzinfo=timezone.utc)
    )
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.datetime_expiration == "2030-01-01 00:00:00+00:00"


# ---------------------------------------------------------------------------
# Happy-path RDAP for IP observables
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analyzer_ip_success(test_context, monkeypatch):
    """An IP observable is queried via ``whoisit.ip`` and the
    IP-specific fields (network CIDR/name/country/version) are
    populated alongside the shared registration data."""
    ip_result = _make_rdap_ip_result()
    _patch_rdap_ip(monkeypatch, lambda _ip, **_kw: ip_result)
    _patch_whois_must_not_be_called(monkeypatch)
    # domain() must not be used for an IP observable.
    monkeypatch.setattr(
        "saq.modules.rdap.whoisit.domain",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            AssertionError("whoisit.domain must not be called for an IP")
        ),
    )

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "8.8.8.8")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis is not None
    assert analysis.error is None
    assert analysis.lookup_protocol == "rdap"

    assert analysis.network_cidr == "8.8.8.0/24"
    assert analysis.network_name == "GOGL"
    assert analysis.country == "US"
    assert analysis.ip_version == 4
    assert analysis.assignment_type == "direct allocation"
    assert analysis.rdap_service_url == "https://rdap.arin.net/registry/ip/8.8.8.0"

    # Shared fields still populate from the IP response.
    assert analysis.emails == ["arin-contact@google.test", "network-abuse@google.test"]
    assert analysis.datetime_created is not None
    assert analysis.age_created_in_days.isdigit()
    assert analysis.datetime_of_last_update is not None
    # IP allocations have no expiration.
    assert analysis.datetime_expiration is None
    # No registrar role on IP responses.
    assert analysis.registrar is None
    assert analysis.name_servers == []

    # network_cidr is a plain string for display/summary use.
    assert analysis.network_cidr == "8.8.8.0/24"
    # rdap_data keeps the raw ipaddress network object; the details must still
    # serialize via ACE's analysis JSON encoder (regression guard — saving the
    # analysis would otherwise fail with "unsupported type ... IPv4Network").
    serialized = json.dumps(analysis.details, cls=_JSONEncoder)
    assert "8.8.8.0/24" in serialized

    summary = analysis.generate_summary()
    assert "network: 8.8.8.0/24 (GOGL)" in summary
    assert "country: US" in summary


@pytest.mark.unit
def test_rdap_analyzer_ip_queried_verbatim(test_context, monkeypatch):
    """IP observables must be passed to ``whoisit.ip`` unchanged — the
    eTLD+1 reduction applied to domains must NOT touch an IP."""
    seen = {}

    def _capture(ip, **_kw):
        seen["query"] = ip
        return _make_rdap_ip_result()

    _patch_rdap_ip(monkeypatch, _capture)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "8.8.8.8")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    assert seen["query"] == "8.8.8.8"


@pytest.mark.unit
def test_rdap_analyzer_ip_resource_does_not_exist(test_context, monkeypatch):
    """Authoritative ``does not exist`` for an IP is final — no fallback."""
    def _raise(_ip, **_kw):
        raise ResourceDoesNotExist("Object does not exist in registry")

    _patch_rdap_ip(monkeypatch, _raise)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "203.0.113.5")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol is None
    assert analysis.error is not None
    assert "not found" in analysis.error
    assert analysis.network_cidr is None


@pytest.mark.unit
def test_rdap_analyzer_ip_falls_back_to_whois(test_context, monkeypatch):
    """When RDAP errors for an IP, the generic WHOIS fallback still runs
    against the raw IP."""
    def _rdap(_ip, **_kw):
        raise QueryError("RDAP service errored")

    _patch_rdap_ip(monkeypatch, _rdap)
    whois_calls = {}

    def _whois(target):
        whois_calls["target"] = target
        return _MockWhoisResult({"text": "mock arin whois"})

    _patch_whois(monkeypatch, _whois)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_IP, "8.8.8.8")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol == "whois"
    assert analysis.rdap_attempt_error is not None
    # The raw IP (not an eTLD+1 reduction) is what WHOIS is queried with.
    assert whois_calls["target"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# RDAP failure modes
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analyzer_resource_does_not_exist_no_fallback(test_context, monkeypatch):
    """Authoritative ``does not exist`` from RDAP is final — don't waste
    a WHOIS query.
    """
    def _raise(_domain, **_kw):
        raise ResourceDoesNotExist("Object does not exist in registry")

    _patch_rdap(monkeypatch, _raise)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "nope.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol is None
    assert analysis.error is not None
    assert "domain not found" in analysis.error
    assert analysis.domain_name is None
    assert analysis.registrar is None
    assert analysis.age_created_in_days is None


@pytest.mark.unit
def test_rdap_analyzer_falls_back_on_unsupported_tld(test_context, monkeypatch):
    """RDAP can't handle this TLD (e.g. .de) → WHOIS fallback succeeds."""
    def _rdap(_domain, **_kw):
        raise UnsupportedError("No RDAP service for TLD 'de'")

    _patch_rdap(monkeypatch, _rdap)
    whois_data = {
        "domain_name": "example.de",
        "registrar": "DENIC eG",
        "name_servers": ["ns1.example.de"],
        "creation_date": datetime(2000, 1, 1),
        "updated_date": datetime(2024, 6, 1),
        "expiration_date": datetime(2026, 1, 1),
        "emails": "admin@example.de",
        "text": "mock denic whois response",
    }
    _patch_whois(monkeypatch, lambda _d: _MockWhoisResult(whois_data))

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.de")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol == "whois"
    assert analysis.error is None
    assert analysis.rdap_attempt_error is not None
    assert "no RDAP service" in analysis.rdap_attempt_error

    assert analysis.domain_name == "example.de"
    assert analysis.registrar == "DENIC eG"
    assert analysis.name_servers == ["ns1.example.de"]
    assert analysis.emails == ["admin@example.de"]
    assert analysis.datetime_created is not None
    assert analysis.datetime_of_last_update is not None
    assert analysis.datetime_expiration is not None
    assert analysis.whois_data == dict(whois_data)
    assert analysis.whois_raw_text == "mock denic whois response"


@pytest.mark.unit
def test_rdap_analyzer_falls_back_on_bootstrap_error(test_context, monkeypatch):
    """Network blip during bootstrap → fall back to WHOIS."""
    def _bootstrap():
        raise BootstrapError("IANA endpoint unreachable")

    monkeypatch.setattr("saq.modules.rdap.whoisit.is_bootstrapped", lambda: False)
    monkeypatch.setattr("saq.modules.rdap.whoisit.bootstrap", _bootstrap)

    whois_data = {
        "domain_name": "example.com",
        "registrar": "Some Registrar",
        "name_servers": ["ns1.example.com"],
        "creation_date": datetime(2000, 1, 1),
        "updated_date": datetime(2024, 1, 1),
        "text": "whois fallback text",
    }
    _patch_whois(monkeypatch, lambda _d: _MockWhoisResult(whois_data))

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol == "whois"
    assert analysis.rdap_attempt_error is not None
    assert "bootstrap failed" in analysis.rdap_attempt_error
    assert analysis.error is None
    assert analysis.domain_name == "example.com"


@pytest.mark.unit
def test_rdap_analyzer_falls_back_on_query_error(test_context, monkeypatch):
    def _rdap(_domain, **_kw):
        raise QueryError("RDAP server returned 500")

    _patch_rdap(monkeypatch, _rdap)
    whois_data = {
        "domain_name": "flaky.example",
        "registrar": "Flaky Registry",
        "name_servers": ["ns1.flaky.example"],
        "creation_date": datetime(2010, 1, 1),
        "updated_date": datetime(2024, 1, 1),
        "text": "whois text",
    }
    _patch_whois(monkeypatch, lambda _d: _MockWhoisResult(whois_data))

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "flaky.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol == "whois"
    assert analysis.rdap_attempt_error == "RDAP server returned 500"
    assert analysis.error is None


@pytest.mark.unit
def test_rdap_analyzer_both_protocols_fail(test_context, monkeypatch):
    """When both protocols fail, the combined error message exposes
    both failure modes to the analyst.
    """
    def _rdap(_domain, **_kw):
        raise UnsupportedError("No RDAP service for TLD 'xx'")

    def _whois(_domain):
        raise PywhoisError("No whois server is known for this kind of object.")

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois(monkeypatch, _whois)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "unknown.xx")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol is None
    assert analysis.error is not None
    assert "rdap: no RDAP service" in analysis.error
    assert "whois: No whois server is known" in analysis.error


@pytest.mark.unit
def test_rdap_analyzer_multiline_query_error_first_line_only(test_context, monkeypatch):
    """Like the legacy module: free-form error text gets trimmed to
    its first line for the analyst's summary.
    """
    def _rdap(_domain, **_kw):
        raise QueryError("First line of error\nSecond line\nThird line")

    def _whois(_domain):
        raise PywhoisError("WHOIS also unhappy")

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois(monkeypatch, _whois)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "error.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    # The combined error string keeps each side's first-line slice.
    assert "rdap: First line of error;" in analysis.error
    assert "Second line" not in analysis.error
    assert "whois: WHOIS also unhappy" in analysis.error


# ---------------------------------------------------------------------------
# Date / type edge cases — RDAP path
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analyzer_no_events(test_context, monkeypatch):
    """Registry exists for the TLD but omits creation/update events:
    domain metadata still populated, ages stay None.
    """
    rdap_result = _make_rdap_result(
        registration_date=None,
        last_changed_date=None,
        expiration_date=None,
    )
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.lookup_protocol == "rdap"
    assert analysis.error is None
    assert analysis.domain_name == "EXAMPLE.COM"
    assert analysis.registrar == "RESERVED-Internet Assigned Numbers Authority"
    assert analysis.datetime_created is None
    assert analysis.datetime_of_last_update is None
    assert analysis.datetime_expiration is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    assert analysis.datetime_of_analysis is not None


@pytest.mark.unit
def test_rdap_analyzer_invalid_date_types(test_context, monkeypatch, caplog):
    """If a future ``whoisit`` version returns event dates as strings
    (or anything other than datetime), we warn and keep going.
    """
    rdap_result = _make_rdap_result(
        registration_date="2020-01-01",
        last_changed_date="2024-01-01",
    )
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.error is None
    assert analysis.lookup_protocol == "rdap"
    assert analysis.datetime_created is None
    assert analysis.datetime_of_last_update is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    assert "unexpected registration_date format" in caplog.text
    assert "unexpected last_changed_date format" in caplog.text


@pytest.mark.unit
def test_rdap_analyzer_negative_time_delta(test_context, monkeypatch):
    """Future dates → age clamped to "0" (likely a tz/clock skew)."""
    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    rdap_result = _make_rdap_result(
        registration_date=future,
        last_changed_date=future,
    )
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "future.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.age_created_in_days == "0"
    assert analysis.age_last_updated_in_days == "0"


@pytest.mark.unit
def test_rdap_analyzer_naive_datetime_in_event(test_context, monkeypatch):
    """A naive datetime (no tzinfo) must be treated as UTC, not crash
    the subtraction against the tz-aware ``now``.
    """
    rdap_result = _make_rdap_result(
        registration_date=datetime(2000, 1, 1, 0, 0),  # naive!
        last_changed_date=datetime(2024, 1, 1, 0, 0),
    )
    _patch_rdap(monkeypatch, lambda _d, **_kw: rdap_result)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "naive.example")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.error is None
    assert analysis.age_created_in_days is not None
    assert analysis.age_created_in_days.isdigit()


# ---------------------------------------------------------------------------
# WHOIS fallback edge cases (carried over from the legacy WHOIS tests)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rdap_analyzer_whois_fallback_creation_date_list(test_context, monkeypatch):
    """``python-whois`` sometimes returns dates as lists. Take the first."""
    def _rdap(_domain, **_kw):
        raise UnsupportedError("TLD has no RDAP")

    _patch_rdap(monkeypatch, _rdap)
    whois_data = {
        "domain_name": ["TEST.COM", "TEST.COM"],
        "registrar": "Test Registrar",
        "creation_date": [
            datetime(2020, 1, 1, 12, 0, 0),
            datetime(2020, 1, 1, 12, 0, 0),
        ],
        "updated_date": [datetime(2023, 1, 1, 12, 0, 0)],
        "name_servers": ["ns1.test.com"],
        "text": "mock",
    }
    _patch_whois(monkeypatch, lambda _d: _MockWhoisResult(whois_data))

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "test.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.error is None
    assert analysis.lookup_protocol == "whois"
    assert analysis.domain_name == "TEST.COM"
    assert analysis.datetime_created is not None
    assert analysis.datetime_of_last_update is not None


@pytest.mark.unit
def test_rdap_analyzer_whois_fallback_no_dates(test_context, monkeypatch):
    def _rdap(_domain, **_kw):
        raise UnsupportedError("TLD has no RDAP")

    _patch_rdap(monkeypatch, _rdap)
    whois_data = {
        "domain_name": "NODATE.COM",
        "registrar": "No Date Registrar",
        "creation_date": None,
        "updated_date": None,
        "name_servers": ["ns1.nodate.com"],
        "text": "mock",
    }
    _patch_whois(monkeypatch, lambda _d: _MockWhoisResult(whois_data))

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "nodate.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)
    assert analysis.error is None
    assert analysis.lookup_protocol == "whois"
    assert analysis.domain_name == "NODATE.COM"
    assert analysis.registrar == "No Date Registrar"
    assert analysis.datetime_created is None
    assert analysis.datetime_of_last_update is None
    assert analysis.age_created_in_days is None
    assert analysis.age_last_updated_in_days is None
    assert analysis.datetime_of_analysis is not None


# ---------------------------------------------------------------------------
# Registrable-domain reduction — RDAP/WHOIS are registry protocols and only
# answer for registered domains, never subdomains. www.example.com must be
# queried as example.com or the registry returns a spurious 404.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "value,expected",
    [
        ("www.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.c.example.com", "example.com"),
        ("www.example.co.uk", "example.co.uk"),
        ("WWW.Example.COM", "example.com"),
        ("example.com.", "example.com"),
        # No identifiable public suffix → input returned unchanged.
        ("localhost", "localhost"),
        ("unknown.invalidtld", "unknown.invalidtld"),
    ],
)
def test_registrable_domain(value, expected):
    assert _registrable_domain(value) == expected


@pytest.mark.unit
def test_rdap_analyzer_subdomain_reduced_to_registrable(test_context, monkeypatch):
    """A subdomain FQDN must be queried as its registrable domain — RDAP
    has no record for the host itself.
    """
    queried = []

    def _rdap(domain, **_kw):
        queried.append(domain)
        return _make_rdap_result()

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "www.example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)

    assert queried == ["example.com"]
    assert analysis.lookup_protocol == "rdap"
    assert analysis.error is None
    assert analysis.domain_name == "EXAMPLE.COM"


@pytest.mark.unit
def test_rdap_analyzer_registrable_domain_passthrough(test_context, monkeypatch):
    """An observable that is already a registrable domain is queried as-is."""
    queried = []

    def _rdap(domain, **_kw):
        queried.append(domain)
        return _make_rdap_result()

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois_must_not_be_called(monkeypatch)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "example.com")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)

    assert queried == ["example.com"]


@pytest.mark.unit
def test_rdap_analyzer_whois_fallback_uses_registrable_domain(test_context, monkeypatch):
    """The WHOIS fallback path also queries the registrable domain, not
    the (subdomain) observable value.
    """
    def _rdap(_domain, **_kw):
        raise UnsupportedError("No RDAP service for TLD 'de'")

    queried = []

    def _whois(domain):
        queried.append(domain)
        return _MockWhoisResult({"domain_name": "example.de", "text": "mock"})

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois(monkeypatch, _whois)

    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, "login.example.de")

    analyzer = _make_analyzer(test_context)
    analyzer.root = root

    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(RdapAnalysis)

    assert queried == ["example.de"]
    assert analysis.lookup_protocol == "whois"


# ---------------------------------------------------------------------------
# lookup_domain_creation_date (standalone helper)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_creation_date_memo():
    from saq.modules.rdap import _reset_creation_date_memo_for_tests

    _reset_creation_date_memo_for_tests()
    yield
    _reset_creation_date_memo_for_tests()


@pytest.mark.unit
def test_lookup_creation_date_rdap_success(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    _patch_rdap(monkeypatch, lambda _domain, **_kw: _make_rdap_result())
    _patch_whois_must_not_be_called(monkeypatch)

    result = lookup_domain_creation_date("example.com")
    assert result.created == datetime(1995, 8, 14, 4, 0, tzinfo=timezone.utc)
    assert result.protocol == "rdap"
    assert result.error is None


@pytest.mark.unit
def test_lookup_creation_date_unsupported_falls_back_to_whois(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    def _rdap(_domain, **_kw):
        raise UnsupportedError("No RDAP service for TLD 'de'")

    created = datetime(2026, 7, 1, tzinfo=timezone.utc)
    _patch_rdap(monkeypatch, _rdap)
    # list-form creation_date: first entry wins (python-whois quirk)
    _patch_whois(
        monkeypatch,
        lambda _domain: _MockWhoisResult(
            {"creation_date": [created, datetime(2026, 7, 2, tzinfo=timezone.utc)]}
        ),
    )

    result = lookup_domain_creation_date("example.de")
    assert result.created == created
    assert result.protocol == "whois"
    assert result.error is None


@pytest.mark.unit
def test_lookup_creation_date_nxdomain_skips_whois(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    def _rdap(_domain, **_kw):
        raise ResourceDoesNotExist("domain does not exist")

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois_must_not_be_called(monkeypatch)

    result = lookup_domain_creation_date("no-such-domain.example")
    assert result.created is None
    assert result.protocol is None
    assert "domain not found" in result.error


@pytest.mark.unit
def test_lookup_creation_date_both_fail(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    def _rdap(_domain, **_kw):
        raise QueryError("rdap server error")

    def _whois(_domain):
        raise PywhoisError("no match for domain")

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois(monkeypatch, _whois)

    result = lookup_domain_creation_date("example.com")
    assert result.created is None
    assert result.protocol is None
    assert "rdap: rdap server error" in result.error
    assert "whois: no match for domain" in result.error


@pytest.mark.unit
def test_lookup_creation_date_bootstrap_failure_goes_to_whois(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    def _bootstrap():
        raise BootstrapError("bootstrap data unavailable")

    monkeypatch.setattr("saq.modules.rdap.whoisit.is_bootstrapped", lambda: False)
    monkeypatch.setattr("saq.modules.rdap.whoisit.bootstrap", _bootstrap)

    def _rdap_must_not_be_called(_domain, **_kw):
        raise AssertionError("whoisit.domain must not be called when bootstrap fails")

    monkeypatch.setattr("saq.modules.rdap.whoisit.domain", _rdap_must_not_be_called)

    created = datetime(2026, 6, 15, tzinfo=timezone.utc)
    _patch_whois(monkeypatch, lambda _domain: _MockWhoisResult({"creation_date": created}))

    result = lookup_domain_creation_date("example.com")
    assert result.created == created
    assert result.protocol == "whois"


@pytest.mark.unit
def test_lookup_creation_date_rdap_missing_date_falls_back(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    _patch_rdap(monkeypatch, lambda _domain, **_kw: _make_rdap_result(registration_date=None))
    created = datetime(2026, 5, 20, tzinfo=timezone.utc)
    _patch_whois(monkeypatch, lambda _domain: _MockWhoisResult({"creation_date": created}))

    result = lookup_domain_creation_date("example.com")
    assert result.created == created
    assert result.protocol == "whois"


@pytest.mark.unit
def test_lookup_creation_date_memoizes_success(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    calls = []

    def _rdap(domain, **_kw):
        calls.append(domain)
        return _make_rdap_result()

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois_must_not_be_called(monkeypatch)

    first = lookup_domain_creation_date("example.com")
    second = lookup_domain_creation_date("example.com")
    assert first == second
    assert calls == ["example.com"]


@pytest.mark.unit
def test_lookup_creation_date_does_not_memoize_failure(monkeypatch):
    from saq.modules.rdap import lookup_domain_creation_date

    calls = []

    def _rdap(domain, **_kw):
        calls.append(domain)
        raise QueryError("transient")

    def _whois(_domain):
        raise PywhoisError("no match")

    _patch_rdap(monkeypatch, _rdap)
    _patch_whois(monkeypatch, _whois)

    lookup_domain_creation_date("example.com")
    lookup_domain_creation_date("example.com")
    assert calls == ["example.com", "example.com"]
