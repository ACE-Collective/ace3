import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from whois.exceptions import PywhoisError
from whoisit.errors import UnsupportedError

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER,
    ANALYSIS_MODULE_EMAIL_ANALYZER,
    ANALYSIS_MODULE_EMAIL_REPLY_TO_DOMAIN_AGE_ANALYZER,
    ANALYSIS_MODULE_NRD_ANALYZER,
    ANALYSIS_MODULE_RDAP_DOMAIN_AGE_ANALYZER,
    DIRECTIVE_ORIGINAL_EMAIL,
    F_EMAIL_REPLY_TO,
)
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email.address import AGE_SOURCE_NRD, EmailReplyToDomainAgeAnalysis
from saq.nrd import util as nrd_util
from saq.signatures.builtin import EMAIL_REPLY_TO_NEW_DOMAIN
from saq.util.uuid import get_storage_dir, storage_dir_from_uuid
from tests.saq.helpers import search_log, search_log_regex

FROM_DOMAIN = "vendor-example.com"
REPLY_TO_DOMAIN = "vendor-example.net"

# what the executor logs when a module raises (saq/engine/executor.py)
MODULE_FAILED = re.compile(r"^analysis module .* failed on ")


def _email(mail_from, reply_to=None):
    headers = [
        "From: Pat Buyer <" + mail_from + ">",
        "To: recipient@example.org",
        "Subject: Quote request",
        "Message-ID: <" + str(uuid.uuid4()) + "@vendor-example.com>",
        "Date: Fri, 06 Nov 2026 12:01:56 +0000",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
    ]
    if reply_to:
        headers.append("Reply-To: " + reply_to)
    return ("\n".join(headers) + "\n\nplease send your quotation process\n").encode("utf-8")


class _Registry:
    """Stands in for the RDAP registries (whoisit.domain): the registration date of each domain,
    and every domain it was asked about."""

    def __init__(self, registered: dict):
        self.registered = registered
        self.queried = []

    def __call__(self, domain, include_raw=False):
        self.queried.append(domain)
        if isinstance(self.registered[domain], Exception):
            raise self.registered[domain]

        return {
            "name": domain.upper(),
            "url": f"https://rdap.example.test/domain/{domain}",
            "nameservers": [],
            "registration_date": self.registered[domain],
            "entities": {},
            "raw": {"objectClassName": "domain", "ldhName": domain},
        }


@pytest.fixture
def registry(monkeypatch):
    now = datetime.now(timezone.utc)
    registry = _Registry({
        FROM_DOMAIN: now - timedelta(days=2200),
        REPLY_TO_DOMAIN: now - timedelta(days=2),
    })
    monkeypatch.setattr("whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("whoisit.bootstrap", lambda: True)
    monkeypatch.setattr("whoisit.domain", registry)

    def _no_whois(domain, *args, **kwargs):
        raise AssertionError(f"whois must not be queried for {domain}")

    monkeypatch.setattr("whois.whois", _no_whois)
    return registry


@pytest.fixture
def no_registration_date(monkeypatch, registry):
    """Neither RDAP nor WHOIS has the Reply-To domain's registration date, as for .de."""
    registry.registered[REPLY_TO_DOMAIN] = UnsupportedError("no RDAP service for this TLD")

    def _whois_fails(domain, *args, **kwargs):
        raise PywhoisError(f"no creation date for {domain}")

    monkeypatch.setattr("whois.whois", _whois_fails)


@pytest.fixture
def nrd_list(tmp_path, monkeypatch):
    """A newly registered domain list holding the Reply-To domain."""
    db_path = tmp_path / "nrd_index.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE nrd (domain TEXT PRIMARY KEY) WITHOUT ROWID")
        conn.execute("INSERT INTO nrd (domain) VALUES (?)", (REPLY_TO_DOMAIN,))
    conn.close()

    monkeypatch.setattr(nrd_util, "get_database_path", lambda: db_path)
    nrd_util._reset_connection_for_tests()
    yield db_path
    nrd_util._reset_connection_for_tests()


ALL_MODULES = (
    "file_type",
    ANALYSIS_MODULE_EMAIL_ANALYZER,
    ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER,
    ANALYSIS_MODULE_EMAIL_REPLY_TO_DOMAIN_AGE_ANALYZER,
    ANALYSIS_MODULE_RDAP_DOMAIN_AGE_ANALYZER,
    ANALYSIS_MODULE_NRD_ANALYZER,
)


def _analyze(tmpdir, raw_email, modules=ALL_MODULES):
    """Runs one email through the engine and returns the root as saved to disk, after checking that no
    module failed."""
    email_path = str(tmpdir / "email.rfc822")
    with open(email_path, "wb") as fp:
        fp.write(raw_email)

    root_uuid = str(uuid.uuid4())
    root = RootAnalysis(
        uuid=root_uuid,
        tool="tool",
        tool_instance="tool_instance",
        alert_type="mailbox",
        desc="reply-to domain age test",
        storage_dir=storage_dir_from_uuid(root_uuid),
        analysis_mode="test_groups")
    root.initialize_storage()
    root.add_file_observable(email_path).add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root.save()
    root.schedule()

    engine = Engine()
    for module in modules:
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # a module that raised leaves no analysis behind, which would pass every "not looked up" test
    assert search_log_regex(MODULE_FAILED) == []
    return load_root(get_storage_dir(root_uuid))


def _reply_to(root):
    observables = root.get_observables_by_type(F_EMAIL_REPLY_TO)
    assert len(observables) == 1
    return observables[0]


@pytest.mark.integration
def test_new_reply_to_domain_other_than_from_is_a_detection(tmpdir, registry):
    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN))

    reply_to = _reply_to(root)
    assert [d.signature_uuid for d in reply_to.detections] == [EMAIL_REPLY_TO_NEW_DOMAIN.uuid]
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.reply_to_domain == REPLY_TO_DOMAIN
    assert analysis.from_domain == FROM_DOMAIN
    assert analysis.age_in_days == 2
    assert datetime.fromisoformat(analysis.registered) == registry.registered[REPLY_TO_DOMAIN]
    # the From domain is never looked up: only the Reply-To domain is in question
    assert registry.queried == [REPLY_TO_DOMAIN]

    records = search_log("is on a new domain")
    assert len(records) == 1
    assert records[0].levelname == "INFO"
    assert records[0].root_uuid == root.uuid
    assert records[0].reply_to_domain == REPLY_TO_DOMAIN
    assert records[0].from_domain == FROM_DOMAIN


@pytest.mark.integration
def test_established_reply_to_domain_is_not_a_detection(tmpdir, registry):
    registry.registered[REPLY_TO_DOMAIN] = datetime.now(timezone.utc) - timedelta(days=8)

    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN))

    reply_to = _reply_to(root)
    assert reply_to.detections == []
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.age_in_days == 8
    assert analysis.is_new is False


@pytest.mark.integration
@pytest.mark.parametrize("reply_to", [
    "orders@" + FROM_DOMAIN,
    "pat@mail." + FROM_DOMAIN,
])
def test_reply_to_on_the_from_domain_is_not_looked_up(tmpdir, registry, reply_to):
    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, reply_to))

    reply_to = _reply_to(root)
    assert reply_to.detections == []
    assert not reply_to.get_analysis(EmailReplyToDomainAgeAnalysis)
    assert registry.queried == []


@pytest.mark.integration
def test_reply_to_domain_without_registration_date_falls_back_to_nrd_list(tmpdir, no_registration_date, nrd_list):
    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN))

    reply_to = _reply_to(root)
    assert [d.signature_uuid for d in reply_to.detections] == [EMAIL_REPLY_TO_NEW_DOMAIN.uuid]
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.age_source == AGE_SOURCE_NRD
    assert analysis.age_in_days is None
    assert "on the newly registered domain list" in reply_to.detections[0].description


@pytest.mark.integration
def test_reply_to_domain_without_registration_date_or_nrd_listing_is_not_a_detection(
        tmpdir, tmp_path, monkeypatch, no_registration_date):
    monkeypatch.setattr(nrd_util, "get_database_path", lambda: tmp_path / "no-nrd-list.db")
    nrd_util._reset_connection_for_tests()

    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN))

    reply_to = _reply_to(root)
    assert reply_to.detections == []
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.is_new is False
    assert analysis.age_source is None
    assert "no creation date" in analysis.lookup_error
    assert "registration date unknown" in analysis.generate_summary()


@pytest.mark.integration
def test_reply_to_domain_without_registration_date_and_nrd_disabled(tmpdir, no_registration_date):
    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN),
                    modules=tuple(m for m in ALL_MODULES if m != ANALYSIS_MODULE_NRD_ANALYZER))

    reply_to = _reply_to(root)
    assert reply_to.detections == []
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.is_new is False


@pytest.mark.integration
def test_email_without_from_is_not_looked_up(tmpdir, registry):
    raw_email = _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN).replace(
        b"From: Pat Buyer <pat@" + FROM_DOMAIN.encode() + b">\n", b"")

    root = _analyze(tmpdir, raw_email)

    reply_to = _reply_to(root)
    assert not reply_to.get_analysis(EmailReplyToDomainAgeAnalysis)
    assert registry.queried == []


@pytest.mark.integration
def test_reply_to_excluded_from_fqdn_extraction_is_not_looked_up(tmpdir, monkeypatch, registry):
    # as the site excludes its own addresses (signatures' "Skip FQDN extraction for our own e-mail addresses")
    fqdn_config = get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER)
    monkeypatch.setattr(fqdn_config, "observable_exclusions", {F_EMAIL_REPLY_TO: ["pat@" + REPLY_TO_DOMAIN]})

    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat@" + REPLY_TO_DOMAIN))

    reply_to = _reply_to(root)
    assert not reply_to.get_analysis(EmailReplyToDomainAgeAnalysis)
    assert registry.queried == []


@pytest.mark.integration
@pytest.mark.parametrize("from_domain,reply_to_domain,lookalike", [
    # a swapped suffix on a short name, which compare_domains misses
    ("acme.com", "acme.net", True),
    ("vendor-example.com", "vendor-exarnple.com", True),
    ("vendor-example.com", "quotes-desk.com", False),
])
def test_reply_to_domain_that_looks_like_the_from_domain(tmpdir, registry, from_domain, reply_to_domain, lookalike):
    registry.registered[reply_to_domain] = datetime.now(timezone.utc) - timedelta(days=1)

    root = _analyze(tmpdir, _email("pat@" + from_domain, "pat@" + reply_to_domain))

    reply_to = _reply_to(root)
    analysis = reply_to.get_and_load_analysis(EmailReplyToDomainAgeAnalysis)
    assert analysis.lookalike is lookalike
    assert reply_to.detections[0].description.endswith("and looks like it") is lookalike


@pytest.mark.integration
def test_reply_to_without_a_domain_is_not_looked_up(tmpdir, registry):
    root = _analyze(tmpdir, _email("pat@" + FROM_DOMAIN, "pat"))

    reply_to = _reply_to(root)
    assert not reply_to.get_analysis(EmailReplyToDomainAgeAnalysis)
    assert registry.queried == []


@pytest.mark.unit
def test_analysis_without_details_has_no_summary():
    assert EmailReplyToDomainAgeAnalysis().generate_summary() is None
