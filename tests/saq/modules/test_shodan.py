import datetime
import json
import logging

import pytest
import requests
import shodan
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from saq import x509
from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import F_FILE, F_IPV4, F_SHA1
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis import FileHashAnalyzer
from saq.modules.shodan import DIRECTIVE_QUERY_SHODAN, SHODAN_REQUEST_TIMEOUT, ShodanAnalysis, ShodanAnalyzer
from saq.util.uuid import get_storage_dir


def _pem(common_name: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _sha1(pem: str) -> str:
    return x509.sha1(x509.load_cert(pem.encode()))


class FakeShodan:
    """Stands in for shodan.Shodan; set host_result / search_result / error per test."""

    host_result = None
    search_result = None
    error = None
    calls = []

    def __init__(self, api_key):
        self.api_key = api_key

    def host(self, value):
        FakeShodan.calls.append(("host", value))
        if FakeShodan.error:
            raise FakeShodan.error
        return FakeShodan.host_result

    def search(self, query):
        FakeShodan.calls.append(("search", query))
        if FakeShodan.error:
            raise FakeShodan.error
        return FakeShodan.search_result


@pytest.fixture
def fake_shodan(monkeypatch):
    FakeShodan.host_result = None
    FakeShodan.search_result = None
    FakeShodan.error = None
    FakeShodan.calls = []
    # the client is only built after the api key check, so this replaces it entirely
    monkeypatch.setattr("saq.modules.shodan.ShodanAnalyzer._get_shodan_client", lambda self: FakeShodan("key"))
    return FakeShodan


def _analyze(root_analysis, observable_type: str, value: str, directive: bool = True):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(observable_type, value)
    if directive:
        observable.add_directive(DIRECTIVE_QUERY_SHODAN)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("shodan", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root, root.get_observable(observable.uuid)


def _files(analysis):
    return {o.file_name: o for o in analysis.observables if o.type == F_FILE}


@pytest.mark.integration
def test_host(root_analysis, fake_shodan):
    leaf, issuer = _pem("www.example.com"), _pem("Example CA")
    fake_shodan.host_result = {
        "domains": ["example.com", "example.net"],
        "ports": [443, 8080],
        "vulns": ["CVE-2021-44228"],
        "data": [
            {"port": 443, "ssl": {"chain": [leaf, issuer]}},
            {"port": 8080},
        ],
    }

    root, observable = _analyze(root_analysis, F_IPV4, "198.51.100.7")

    assert fake_shodan.calls == [("host", "198.51.100.7")]
    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.dns == ["example.com", "example.net"]
    assert analysis.open_ports == [443, 8080]
    assert analysis.vulns == ["CVE-2021-44228"]
    assert analysis.error is None
    assert analysis.summary == "Shodan Results: dns (example.com,example.net) open ports (443,8080) vulns (CVE-2021-44228)"
    assert observable.has_tag("CVE-2021-44228")

    files = _files(analysis)
    results = files["198.51.100.7.shodan"]
    assert results.has_tag("shodan")
    assert any(FileHashAnalyzer.__name__ in name for name in results.excluded_analysis)
    with open(results.full_path) as fp:
        assert json.load(fp) == fake_shodan.host_result

    for index, pem in enumerate([leaf, issuer]):
        cert = files[f"198.51.100.7.{index}.x509"]
        assert cert.has_tag("x509")
        with open(cert.full_path) as fp:
            assert fp.read() == pem

    [detail] = [d for d in root.summary_details if d.header == "Shodan Analysis"]
    assert detail.content == (
        "198.51.100.7\n\n"
        "domains\n\t- example.com\n\t- example.net\n\n"
        "ports\n\t- 443\n\t- 8080\n\n"
        "vulns\n\t- CVE-2021-44228\n\n"
    )


@pytest.mark.integration
def test_host_without_vulns(root_analysis, fake_shodan):
    fake_shodan.host_result = {"domains": [], "ports": [22], "data": []}

    _, observable = _analyze(root_analysis, F_IPV4, "198.51.100.8")

    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.summary == "Shodan Results: dns () open ports (22)"


@pytest.mark.integration
def test_certificate(root_analysis, fake_shodan):
    wanted, other = _pem("wanted.example.com"), _pem("other.example.com")
    fake_shodan.search_result = {"matches": [
        {"ssl": {"chain": [other, wanted]}},
        {"port": 80},
    ]}
    fingerprint = _sha1(wanted)

    _, observable = _analyze(root_analysis, F_SHA1, fingerprint)

    assert fake_shodan.calls == [("search", f"ssl.cert.fingerprint:{fingerprint}")]
    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.summary == "Shodan Results: certificate"
    # only the certificate the fingerprint names, not the rest of its chain
    assert set(_files(analysis)) == {f"{fingerprint}.shodan", f"{fingerprint}.x509"}


@pytest.mark.integration
def test_query_error(root_analysis, fake_shodan, caplog):
    fake_shodan.error = shodan.APIError("Invalid API key")

    _, observable = _analyze(root_analysis, F_IPV4, "198.51.100.9")

    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.error == "Invalid API key"
    assert analysis.summary == "Shodan Query Error: Invalid API key"
    assert not _files(analysis)
    assert any(r.levelno == logging.WARNING and "unable to query shodan: Invalid API key" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_unexpected_results(root_analysis, fake_shodan, caplog):
    # a host result without its data list
    fake_shodan.host_result = {"domains": [], "ports": []}

    _, observable = _analyze(root_analysis, F_IPV4, "198.51.100.10")

    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.error == "'data'"
    # the results are still kept
    assert set(_files(analysis)) == {"198.51.100.10.shodan"}
    assert any(r.levelno == logging.WARNING and "unable to parse shodan results" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_requires_directive(root_analysis, fake_shodan):
    _, observable = _analyze(root_analysis, F_IPV4, "198.51.100.11", directive=False)

    assert not observable.get_and_load_analysis(ShodanAnalysis)
    assert fake_shodan.calls == []


@pytest.mark.integration
def test_missing_api_key(root_analysis, monkeypatch):
    monkeypatch.setattr(get_config().shodan, "api_key", "")

    _, observable = _analyze(root_analysis, F_IPV4, "198.51.100.12")

    analysis = observable.get_and_load_analysis(ShodanAnalysis)
    assert analysis.error == "missing api key for shodan"


@pytest.mark.unit
def test_client_requests_are_bounded(monkeypatch):
    """The shodan library passes no timeout to requests."""
    sent = []

    def _request(self, method, url, **kwargs):
        sent.append(kwargs)
        raise requests.ConnectionError("not sent")

    monkeypatch.setattr(requests.Session, "request", _request)
    monkeypatch.setattr(get_config().shodan, "api_key", "key")
    analyzer = ShodanAnalyzer(config=get_analysis_module_config("shodan"))

    with pytest.raises(shodan.APIError, match="Unable to connect"):
        analyzer._get_shodan_client().host("198.51.100.13")

    assert [kwargs["timeout"] for kwargs in sent] == [SHODAN_REQUEST_TIMEOUT]


@pytest.mark.unit
def test_uses_the_shodan_network_semaphore():
    # Shodan's API takes one query per second; etc/saq.shodan.default.yaml sizes this semaphore for it
    assert get_analysis_module_config("shodan").semaphore_name == "shodan"
