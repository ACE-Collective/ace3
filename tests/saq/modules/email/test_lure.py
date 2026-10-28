import logging
import os
from email.message import EmailMessage
from pathlib import Path

import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import ANALYSIS_TYPE_MAILBOX, DIRECTIVE_CRAWL, F_FILE, F_URL, AnalysisExecutionResult
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email import lure
from saq.modules.email.lure import (
    SOURCE_ATTACHMENT,
    SOURCE_BODY,
    SOURCE_QR,
    carried_urls,
    fold_carried_urls,
    is_http_url,
    Anchor,
    Candidate,
    CandidateCollector,
    LureURLAnalysis,
    LureURLAnalyzer,
    LureURLSettings,
    LureURLWeights,
    load_lure_settings,
    build_lure_urls,
    parse_body_anchors,
    reason_segments,
    score_candidates,
    sender_domains,
)
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.pdf import PDFAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.modules.file_analysis.url_extraction import URLExtractionAnalysis
from saq.modules.phishkit import PhishkitAnalysis
from saq.modules.adapter import AnalysisModuleAdapter
from saq.util.uuid import get_storage_dir
from tests.saq.test_util import create_test_context

SENDER = "billing@sender.example.com"
RECIPIENT = "recipient@internal.example.org"

LURE = "https://evil.example.net/doc/view?id=1"
PRIVACY = "https://www.sender.example.com/privacy"
UNSUBSCRIBE = "https://www.sender.example.com/unsubscribe?u=1"
LOGO = "https://cdn.sender.example.com/logo.png"

TRACKER = ("https://tracker.example.com/click/1?id=7"
           "&rUrl=https%3A%2F%2Fevil.example.net%2Flogin&rUrl=https%3A%2F%2Fdecoy.example.org%2Fhome")

LURE_HTML = f"""<html><body>
<img src="{LOGO}">
<p>A document has been shared with you.</p>
<table><tr><td bgcolor="#0078d4"><a href="{LURE}" style="color:#ffffff">Review Document</a></td></tr></table>
<p><a href="{PRIVACY}">Privacy</a> | <a href="{UNSUBSCRIBE}">Unsubscribe</a></p>
</body></html>"""

SETTINGS = LureURLSettings(
    call_to_action_keywords=["review", "view", "sign"],
    noise_keywords=["unsubscribe", "privacy"],
    benign_domains=["fonts.googleapis.com"],
)


#
# body parsing
#

@pytest.mark.unit
def test_parse_body_anchors():
    anchors = parse_body_anchors(LURE_HTML + """
        <a href="https://img.example.net/x"><img src="https://img.example.net/x.png" alt="Open"></a>
        <form action="https://form.example.net/post"><input type="submit"></form>
        <a class="btn-primary" href="https://button.example.net/">Sign</a>
        <a href="  ">empty</a>""")

    assert anchors[LURE] == Anchor(text="Review Document", button=True, position=0)
    assert anchors[PRIVACY] == Anchor(text="Privacy", button=False, position=1)
    assert anchors[UNSUBSCRIBE].position == 2
    assert anchors["https://img.example.net/x"].text == "[image: Open]"
    assert "https://form.example.net/post" in anchors
    assert anchors["https://button.example.net/"].button is True
    # an image is a resource, not a link
    assert LOGO not in anchors


#
# scoring
#

def _candidate(root, url, sources, **kwargs) -> Candidate:
    return Candidate(observable=root.add_observable_by_spec(F_URL, url), sources=set(sources), **kwargs)


@pytest.mark.unit
def test_score_candidates_prefers_the_call_to_action():
    root = RootAnalysis()
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True,
                                anchor=Anchor("Review Document", True))
    privacy = _candidate(root, PRIVACY, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Privacy", False))
    logo = _candidate(root, LOGO, [SOURCE_BODY], in_parsed_body=True)

    score_candidates([lure_candidate, privacy, logo], {"example.com"}, SETTINGS)

    assert lure_candidate.reasons == [
        "found in the email body",
        "clickable link with text 'Review Document'",
        "styled as a button",
        "call-to-action text (review)",
        "the only linked external domain",
    ]
    assert lure_candidate.score == 90
    assert privacy.score < 0
    assert "looks like a footer link (privacy)" in privacy.reasons
    assert "same domain as the sender (example.com)" in privacy.reasons
    assert logo.score < privacy.score
    assert "points at an image or static resource" in logo.reasons
    assert "not a clickable link in the body" in logo.reasons


@pytest.mark.unit
def test_score_candidates_uses_the_settings_weights():
    # a distinct power of two per weight, so a score says exactly which weights were applied, and no two weights
    # fire on the same set of candidates, so two weights trading places changes some score
    settings = LureURLSettings(
        call_to_action_keywords=["review"], noise_keywords=["unsubscribe"], benign_domains=["fonts.googleapis.com"],
        weights={"qr": 1, "body": 2, "attachment": 4, "clickable": 8, "button": 16, "call_to_action": 32,
                 "only_domain": 64, "unwrapped": 128, "detection": 256, "not_a_link": 512, "sender_domain": 1024,
                 "noise": 2048, "static": 4096, "benign": 8192})
    root = RootAnalysis()
    wrapper = "https://nam01.safelinks.protection.outlook.com/?url=x"
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review Document", True),
                                wrapped_by=wrapper)
    lure_candidate.observable.add_detection_point("known bad")
    plain_cta = _candidate(root, "https://f.example.org/x", [SOURCE_BODY], in_parsed_body=True,
                           anchor=Anchor("Review", False))
    flagged_button = _candidate(root, "https://g.example.info/x", [SOURCE_BODY], in_parsed_body=True,
                                anchor=Anchor("Open", True))
    flagged_button.observable.add_detection_point("known bad")
    plain_text_link = _candidate(root, "https://www.example.com/j", [SOURCE_BODY], wrapped_by=wrapper)
    plain_text_link.observable.add_detection_point("known bad")
    qr = _candidate(root, "https://qr.example.com/a", [SOURCE_QR], in_parsed_body=True)
    logo = _candidate(root, "https://www.example.com/logo.png", [SOURCE_BODY], in_parsed_body=True)
    pixel = _candidate(root, "https://www.example.com/pixel", [SOURCE_BODY], in_parsed_body=True)
    footer = _candidate(root, "https://www.example.com/unsubscribe", [SOURCE_ATTACHMENT],
                        attachments=["statement.pdf"], pdf_link=True)
    font = _candidate(root, "https://fonts.googleapis.com/css", [SOURCE_ATTACHMENT], attachments=["page.html"])

    # one at a time: only_domain depends on which other links are scored with a candidate
    for candidate in (lure_candidate, plain_cta, flagged_button, plain_text_link, qr, logo, pixel, footer, font):
        score_candidates([candidate], {"example.com"}, settings)

    # body + clickable + button + call_to_action + only_domain + unwrapped + detection
    assert lure_candidate.score == 506
    # body + clickable + call_to_action + only_domain
    assert plain_cta.score == 106
    # body + clickable + button + only_domain + detection
    assert flagged_button.score == 346
    # body + unwrapped + detection + sender_domain
    assert plain_text_link.score == 1410
    # qr + sender_domain
    assert qr.score == 1025
    # body + not_a_link + sender_domain + static
    assert logo.score == 5634
    # body + not_a_link + sender_domain
    assert pixel.score == 1538
    # attachment + clickable (a PDF link) + sender_domain + noise
    assert footer.score == 3084
    # attachment + benign
    assert font.score == 8196


@pytest.mark.unit
def test_score_candidates_other_signals():
    root = RootAnalysis()
    qr = _candidate(root, "https://qr.example.net/a", [SOURCE_QR], in_parsed_body=True)
    attached = _candidate(root, "https://attached.example.org/b", [SOURCE_ATTACHMENT], attachments=["statement.html"])
    wrapped = _candidate(root, "https://wrapped.example.info/c", [SOURCE_BODY],
                         wrapped_by="https://nam01.safelinks.protection.outlook.com/?url=x")
    wrapped.observable.add_detection_point("known bad")
    benign = _candidate(root, "https://fonts.googleapis.com/css", [SOURCE_BODY])

    score_candidates([qr, attached, wrapped, benign], set(), SETTINGS)

    # a QR code in an image is never a link in the body
    assert qr.reasons == ["decoded from a QR code"]
    assert attached.reasons == ["found in attachment statement.html"]
    assert "unwrapped from nam01.safelinks.protection.outlook.com/?url=x" in wrapped.reasons
    assert "has detection points" in wrapped.reasons
    assert "benign infrastructure domain" in benign.reasons
    assert benign.score < 0


@pytest.mark.unit
def test_score_candidates_pdf_link_carrying_urls():
    root = RootAnalysis()
    tracker = _candidate(root, TRACKER, [SOURCE_ATTACHMENT], attachments=["statement.pdf"], pdf_link=True,
                         carries=["https://evil.example.net/login", "https://decoy.example.org/home"])

    score_candidates([tracker], set(), SETTINGS)

    assert tracker.reasons == [
        "found in attachment statement.pdf",
        "clickable link in a PDF",
        "carries 2 URLs: evil.example.net/login, decoy.example.org/home",
        "the only linked external domain",
    ]
    assert tracker.score == 50
    assert tracker.highlights == [
        ["statement.pdf"],
        [],
        ["evil.example.net/login", "decoy.example.org/home"],
        [],
    ]


@pytest.mark.unit
def test_highlights_link_text():
    root = RootAnalysis()
    candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review Document", True))

    score_candidates([candidate], set(), SETTINGS)

    assert candidate.highlights[candidate.reasons.index("clickable link with text 'Review Document'")] == [
        "Review Document"]
    assert len(candidate.highlights) == len(candidate.reasons)


@pytest.mark.unit
def test_reason_segments():
    assert reason_segments("carries 2 URLs: a.example.com/x, b.example.com/y", ["a.example.com/x", "b.example.com/y"]) == [
        ("carries 2 URLs: ", False), ("a.example.com/x", True), (", ", False), ("b.example.com/y", True)]
    assert reason_segments("found in attachment x.pdf", ["x.pdf"]) == [("found in attachment ", False), ("x.pdf", True)]
    # a value that is not in the reason, or empty, is skipped
    assert reason_segments("styled as a button", ["nope", ""]) == [("styled as a button", False)]
    assert reason_segments("plain", []) == [("plain", False)]


@pytest.mark.unit
@pytest.mark.parametrize("value, expected", [
    ("https://evil.example.net/login", True),
    ("HTTP://evil.example.net/", True),
    ("mailto:user@example.com", False),
    # urlparse raises on these, and an attacker writes the link
    ("http://[x/", False),
    ("https://a.example.com]/x", False),
])
def test_is_http_url(value, expected):
    assert is_http_url(value) is expected


@pytest.mark.unit
def test_only_external_domain_counts_links_only():
    root = RootAnalysis()
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review", False))
    # the logo comes from a CDN, which is not a link the recipient follows
    cdn_logo = _candidate(root, "https://cdn.example.org/logo.png", [SOURCE_BODY], in_parsed_body=True)

    score_candidates([lure_candidate, cdn_logo], set(), SETTINGS)

    assert "the only linked external domain" in lure_candidate.reasons


@pytest.mark.unit
def test_carried_urls():
    assert carried_urls(TRACKER) == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert carried_urls("https://example.com/?q=hello&next=/relative") == []
    assert carried_urls("http://[::1") == []


@pytest.mark.unit
def test_fold_carried_urls():
    root = RootAnalysis()
    tracker = _candidate(root, TRACKER, [SOURCE_BODY], anchor=Anchor("View", False))
    evil = _candidate(root, "https://evil.example.net/login", [SOURCE_BODY])
    decoy = _candidate(root, "https://decoy.example.org/home", [SOURCE_BODY])
    other = _candidate(root, "https://other.example.com/", [SOURCE_BODY])

    # the link in the email is the tracker; what it carries is part of it
    assert fold_carried_urls([evil, tracker, decoy, other]) == [tracker, other]
    assert tracker.carries == ["https://evil.example.net/login", "https://decoy.example.org/home"]


@pytest.mark.unit
def test_fold_carried_urls_chain():
    root = RootAnalysis()
    lure_url = "https://evil.example.net/login"
    inner = "https://inner.example.org/r?to=https%3A%2F%2Fevil.example.net%2Flogin"
    outer = "https://outer.example.com/c?u=https%3A%2F%2Finner.example.org%2Fr%3Fto%3Dhttps%253A%252F%252Fevil.example.net%252Flogin"
    for order in ([outer, inner, lure_url], [lure_url, inner, outer]):
        candidates = [_candidate(root, url, [SOURCE_BODY]) for url in order]

        # only the link the recipient clicks is left, whichever order the URLs came in
        [remaining] = fold_carried_urls(candidates)
        assert remaining.observable.value == outer
        assert remaining.carries == [inner]


@pytest.mark.unit
def test_rank_key_is_stable():
    root = RootAnalysis()
    first = _candidate(root, "https://z.example.com/", [SOURCE_BODY], anchor=Anchor("one", False, position=0))
    second = _candidate(root, "https://a.example.com/", [SOURCE_BODY], anchor=Anchor("two", False, position=2))
    no_anchor_z = _candidate(root, "https://z.example.net/", [SOURCE_BODY])
    no_anchor_a = _candidate(root, "https://a.example.net/", [SOURCE_BODY])

    # equal scores: by position in the body, then by value, never by the order they came in
    ranked = sorted([no_anchor_z, second, no_anchor_a, first], key=lambda c: c.rank_key)
    assert ranked == [first, second, no_anchor_a, no_anchor_z]


@pytest.mark.unit
def test_sender_domains():
    analysis = EmailAnalysis()
    analysis.email = {"from_address": "Billing <billing@mail.sender.example.com>", "return_path": "<bounce@bounces.example.org>"}
    assert sender_domains(analysis) == {"example.com", "example.org"}

    assert sender_domains(EmailAnalysis()) == set()


#
# candidate collection over a tree built by hand
#

def _file(analysis, tmp_path: Path, name: str, content: str = "x"):
    path = tmp_path / name
    path.write_text(content)
    return analysis.add_file_observable(str(path))


def _extracted(file_observable, *urls):
    analysis = URLExtractionAnalysis()
    file_observable.add_analysis(analysis)
    return [analysis.add_observable_by_spec(F_URL, url) for url in urls]


def _email_tree(root_analysis, tmp_path, html=None):
    email_file = _file(root_analysis, tmp_path, "message.email.rfc822", "From: x")
    email_analysis = EmailAnalysis()
    email_file.add_analysis(email_analysis)
    body = None
    if html is not None:
        body = _file(email_analysis, tmp_path, "message.email.rfc822.unknown_text_html_000.html", html)
    return email_file, email_analysis, body


@pytest.mark.integration
def test_collector_sources(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE, LOGO)

    # a QR code in an inline image
    image = _file(email_analysis, tmp_path, "image001.png", "png")
    qr = QRCodeAnalysis()
    image.add_analysis(qr)
    qr_text = _file(qr, tmp_path, "image001.png.qrcode", "https://qr.example.net/a\n")
    _extracted(qr_text, "https://qr.example.net/a")

    # a link in an attachment
    attachment = _file(email_analysis, tmp_path, "statement.html", "<a href='https://attached.example.org/b'>b</a>")
    _extracted(attachment, "https://attached.example.org/b")

    # what a crawl found after the click is not part of the lure
    crawl = PhishkitAnalysis()
    body.add_analysis(crawl)
    crawl.add_observable_by_spec(F_URL, "https://after.example.net/the-click")

    collector = CandidateCollector()
    candidates = {c.observable.value: c for c in collector.collect(email_analysis)}

    assert set(candidates) == {LURE, LOGO, "https://qr.example.net/a", "https://attached.example.org/b"}
    assert candidates[LURE].sources == {SOURCE_BODY}
    assert candidates[LURE].anchor == Anchor("Review Document", True)
    assert candidates[LOGO].in_parsed_body and candidates[LOGO].anchor is None
    assert candidates["https://qr.example.net/a"].sources == {SOURCE_QR}
    assert candidates["https://attached.example.org/b"].sources == {SOURCE_ATTACHMENT}
    assert candidates["https://attached.example.org/b"].attachments == ["statement.html"]
    assert collector.has_inner_email is False


@pytest.mark.integration
def test_collector_pdf_link_carrying_urls(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached statement</p>")
    pdf = _file(email_analysis, tmp_path, "statement.pdf", "%PDF-1.4")
    pdf_analysis = PDFAnalysis()
    pdf.add_analysis(pdf_analysis)
    # the PDF's link annotation is the tracker; urlfinderlib also extracts what it carries
    annotations = _file(pdf_analysis, tmp_path, "statement.pdf.annotation_uris.txt", TRACKER)
    annotations.add_yara_meta("type", "document.pdf.annotation_uris")
    _extracted(annotations, TRACKER, "https://evil.example.net/login", "https://decoy.example.org/home")
    # the same URLs found again in the PDF's raw objects are not links
    objects = _file(pdf_analysis, tmp_path, "statement.pdf.pdfparser", "objects " + TRACKER)
    _extracted(objects, TRACKER, "http://www.example.com/ns/metadata")

    candidates = {c.observable.value: c for c in CandidateCollector().collect(email_analysis)}

    # what the tracker carries is folded into it: the tracker is the link in the PDF
    assert set(candidates) == {TRACKER, "http://www.example.com/ns/metadata"}
    tracker = candidates[TRACKER]
    assert tracker.pdf_link is True
    assert tracker.carries == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert tracker.attachments == ["statement.pdf"]
    assert candidates["http://www.example.com/ns/metadata"].pdf_link is False

    score_candidates(list(candidates.values()), set(), SETTINGS)
    assert tracker.score > candidates["http://www.example.com/ns/metadata"].score


@pytest.mark.integration
def test_collector_skips_inner_email(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see attached</p>")
    inner = _file(email_analysis, tmp_path, "message.email.rfc822.email.rfc822", "From: y")
    inner_analysis = EmailAnalysis()
    inner.add_analysis(inner_analysis)
    inner_body = _file(inner_analysis, tmp_path, "inner.email.rfc822.unknown_text_html_000.html", LURE_HTML)
    _extracted(inner_body, LURE)
    # EmailAnalyzer extracts the inner email's parts into the outer email too
    outer_copy = _file(email_analysis, tmp_path, "message.email.rfc822.unknown_text_html_001.html", LURE_HTML)
    _extracted(outer_copy, LURE)

    collector = CandidateCollector()

    assert collector.collect(email_analysis) == []
    assert collector.has_inner_email is True


@pytest.mark.integration
def test_collector_unparseable_body(root_analysis, tmp_path, monkeypatch, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)

    def _fail(html):
        raise ValueError("bad markup")

    monkeypatch.setattr(lure, "parse_body_anchors", _fail)
    with caplog.at_level(logging.WARNING):
        [candidate] = CandidateCollector(root_analysis.uuid).collect(email_analysis)

    # the URL is still a candidate, only without its anchor
    assert candidate.observable.value == LURE
    assert candidate.anchor is None
    assert not candidate.in_parsed_body
    [record] = [r for r in caplog.records if "unable to parse email body" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root_analysis.uuid


@pytest.mark.integration
def test_collector_body_too_large(root_analysis, tmp_path, monkeypatch, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    monkeypatch.setattr(lure, "MAX_BODY_BYTES", 10)

    with caplog.at_level(logging.INFO):
        [candidate] = CandidateCollector().collect(email_analysis)

    assert candidate.anchor is None
    assert "too large to parse for lure links" in caplog.text


@pytest.mark.integration
def test_collector_missing_body(root_analysis, tmp_path, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    Path(body.full_path).unlink()

    with caplog.at_level(logging.WARNING):
        [candidate] = CandidateCollector(root_analysis.uuid).collect(email_analysis)

    assert candidate.anchor is None
    [record] = [r for r in caplog.records if "unable to read email body" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root_analysis.uuid


def _module(root):
    return AnalysisModuleAdapter(LureURLAnalyzer(
        context=create_test_context(root=root), config=get_analysis_module_config("lure_url_analyzer")))


@pytest.mark.integration
def test_module_skips_a_url_urlparse_rejects(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, "http://[x/", LURE)

    # one malformed link the attacker wrote must not cost the email its lure
    assert _module(root_analysis).execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert "http://[x/" not in [c["url"] for c in analysis.candidates]


@pytest.mark.integration
def test_module_rescores_when_a_later_final_pass_adds_urls(root_analysis, tmp_path, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached sheet</p>")
    module = _module(root_analysis)

    # nothing to score yet, and the analysis stays open
    assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE
    assert not email_file.get_analysis(LureURLAnalysis)

    # a module that also works in final analysis (xlmdeobfuscator) adds the lure afterwards
    sheet = _file(email_analysis, tmp_path, "invoice.xls", "sheet")
    [lure_url] = _extracted(sheet, LURE)
    with caplog.at_level(logging.INFO):
        assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE
        # a pass that changes nothing does not log the lure again
        assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert not analysis.completed
    assert lure_url.has_directive(DIRECTIVE_CRAWL)
    assert caplog.text.count(f"is {LURE}") == 1


def _settings_file(tmp_path, monkeypatch, text: str) -> Path:
    path = tmp_path / "lure_url.yaml"
    path.write_text(text)
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", str(path))
    return path


@pytest.mark.integration
def test_module_crawl_primary_off_and_max_candidates(root_analysis, tmp_path, monkeypatch):
    _settings_file(tmp_path, monkeypatch, "crawl_primary: false\nmax_candidates: 2\n")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    urls = _extracted(body, LURE, PRIVACY, UNSUBSCRIBE, LOGO)

    _module(root_analysis).execute_final_analysis(email_file)

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert len(analysis.candidates) == 2
    assert not any(url.has_directive(DIRECTIVE_CRAWL) for url in urls)


@pytest.mark.unit
def test_shipped_settings_file_holds_the_builtin_defaults():
    assert get_analysis_module_config("lure_url_analyzer").config_path == "etc/lure_url.yaml"
    settings = load_lure_settings("etc/lure_url.yaml")

    # the file deployments copy into analyst_data must start from the same values ACE uses without it
    assert settings == LureURLSettings()
    assert "fonts.gstatic.com" in settings.benign_domains
    assert settings.weights.qr == 35 and settings.weights.benign == -50
    assert settings.min_primary_score == 1


@pytest.mark.unit
def test_settings_file_keys_left_out_keep_their_defaults(tmp_path):
    path = tmp_path / "lure_url.yaml"
    path.write_text("benign_domains: [example.net]\nnoise_keywords:\nweights:\n  qr: 50\n")

    settings = load_lure_settings(str(path))

    assert settings.benign_domains == ["example.net"]
    assert settings.noise_keywords == []
    assert "invoice" in settings.call_to_action_keywords
    assert settings.weights.qr == 50
    assert settings.weights.body == 20
    assert settings.max_candidates == 5


@pytest.mark.unit
def test_settings_file_blank_weights_keep_their_defaults(tmp_path):
    # an analyst who comments out every weight leaves `weights:` with nothing under it
    path = tmp_path / "lure_url.yaml"
    path.write_text("weights:\n")

    assert load_lure_settings(str(path)).weights == LureURLWeights()


@pytest.mark.unit
@pytest.mark.parametrize("text", [
    "benign_domain: [example.net]\n",
    "weights:\n  qrr: 50\n",
    "max_candidates: 0\n",
    "benign_domains: [\n",
    "- not a mapping\n",
])
def test_settings_file_that_does_not_load(tmp_path, caplog, text):
    path = tmp_path / "lure_url.yaml"
    path.write_text(text)

    assert load_lure_settings(str(path)) is None

    [record] = [r for r in caplog.records if "unable to load lure url settings" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.path == str(path)


@pytest.mark.integration
def test_module_reloads_the_settings_file_and_keeps_the_last_good_one(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(get_config().global_settings, "check_watched_files_frequency", 0)
    path = _settings_file(tmp_path, monkeypatch, "min_primary_score: 1000\n")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE, PRIVACY, UNSUBSCRIBE, LOGO)
    module = _module(root_analysis)

    def edit(text: str, mtime: int):
        path.write_text(text)
        # the watcher notices a change by its mtime, which can be unchanged within one tick
        os.utime(path, (mtime, mtime))
        module.wrapped_module.check_watched_files()
        module.execute_final_analysis(email_file)
        return email_file.get_analysis(LureURLAnalysis).primary

    module.execute_final_analysis(email_file)
    assert email_file.get_analysis(LureURLAnalysis).primary is None

    # a bad edit is rejected whole, and the tuning already in effect stays (the defaults would
    # call LURE the primary)
    assert edit("min_primary_score: [\n", 1_000_000) is None
    assert any(r.levelno == logging.ERROR and "unable to load lure url settings" in r.getMessage()
               for r in caplog.records)

    with caplog.at_level(logging.INFO):
        assert edit("min_primary_score: 1\n", 2_000_000)["url"] == LURE
    assert f"loaded lure url settings from {path}" in caplog.text


@pytest.mark.integration
def test_module_missing_settings_file_uses_the_builtin_defaults(root_analysis, tmp_path, monkeypatch, caplog):
    missing = tmp_path / "missing.yaml"
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", str(missing))
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    [lure_url] = _extracted(body, LURE)

    _module(root_analysis).execute_final_analysis(email_file)

    assert email_file.get_analysis(LureURLAnalysis).primary["url"] == LURE
    assert lure_url.has_directive(DIRECTIVE_CRAWL)
    [record] = [r for r in caplog.records if "does not exist" in r.getMessage()]
    # the traceback is what gets the record an error report
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.path == str(missing)


@pytest.mark.integration
def test_module_blank_config_path_uses_the_builtin_defaults(root_analysis, tmp_path, monkeypatch):
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", "")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    module = _module(root_analysis)

    module.execute_final_analysis(email_file)

    assert email_file.get_analysis(LureURLAnalysis).primary["url"] == LURE
    assert module.wrapped_module.watched_files == {}

@pytest.mark.unit
def test_lure_module_runs_only_on_alerts():
    # an email becomes an alert in correlation mode; scoring and crawling every collected email
    # in email mode would detonate the links of benign mail
    assert "lure_url_analyzer" in get_config().get_module_group_config("correlation").modules
    assert "lure_url_analyzer" not in get_config().get_module_group_config("email").modules


@pytest.mark.unit
def test_build_lure_urls_skips_a_broken_entry(caplog):
    root = RootAnalysis()
    email_file = root.add_observable_by_spec(F_URL, "https://placeholder.example.com/")
    analysis = LureURLAnalysis()
    email_file.add_analysis(analysis)
    analysis.primary = {"url": LURE}

    with caplog.at_level(logging.WARNING):
        assert build_lure_urls(root) == []

    [record] = [r for r in caplog.records if "unable to build the lure url entry" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root.uuid and record.observable_uuid == email_file.uuid


#
# the engine, on synthetic emails
#

def _message(subject: str, sender: str = SENDER, text: str = "see the html part", html: str = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = RECIPIENT
    message["Subject"] = subject
    message["Message-ID"] = f"<{subject.replace(' ', '-')}@example.com>"
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def _analyze(root_analysis, tmp_path: Path, message: EmailMessage, extra_modules=()):
    path = tmp_path / "message.email.rfc822"
    path.write_bytes(bytes(message))
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    email_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in ("file_type", "email_analyzer", "url_extraction", "lure_url_analyzer") + tuple(extra_modules):
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    email_observable = root.get_observable(email_observable.uuid)
    return root, email_observable.get_and_load_analysis(LureURLAnalysis)


@pytest.mark.integration
def test_engine_picks_the_button(root_analysis, tmp_path):
    root, analysis = _analyze(root_analysis, tmp_path, _message("shared document", html=LURE_HTML))

    assert analysis.primary["url"] == LURE
    assert "styled as a button" in analysis.primary["reasons"]
    assert analysis.summary.startswith(f"Lure URL Analysis: {LURE}")
    ranked = [c["url"] for c in analysis.candidates]
    assert ranked[0] == LURE
    assert PRIVACY in ranked and UNSUBSCRIBE in ranked

    primary = root.get_observable(analysis.primary["observable_uuid"])
    assert primary.value == LURE
    assert primary.has_directive(DIRECTIVE_CRAWL)
    for observable in root.get_observables_by_type(F_URL):
        if observable.value != LURE:
            assert not observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.integration
def test_engine_unwraps_safelinks(root_analysis, tmp_path):
    wrapper = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2Flogin&data=05&reserved=0"
    html = f'<p>Your mailbox is full.</p><a href="{wrapper}" class="button">Verify now</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("mailbox full", html=html), ("protected_url_analyzer",))

    assert analysis.primary["url"] == "https://evil.example.net/login"
    assert analysis.primary["anchor_text"] == "Verify now"
    assert any(r.startswith("unwrapped from nam01.safelinks.protection.outlook.com") for r in analysis.primary["reasons"])
    assert wrapper not in [c["url"] for c in analysis.candidates]


@pytest.mark.integration
def test_engine_click_tracker_is_the_lure(root_analysis, tmp_path):
    html = f'<p>Your statement is ready.</p><a href="{TRACKER}">View statement</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("statement", html=html))

    assert analysis.primary["url"] == TRACKER
    assert analysis.primary["anchor_text"] == "View statement"
    assert analysis.primary["carries"] == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert "carries 2 URLs: evil.example.net/login, decoy.example.org/home" in analysis.primary["reasons"]
    # what the tracker carries is not ranked on its own
    assert [c["url"] for c in analysis.candidates] == [TRACKER]
    [tracker] = [o for o in root.get_observables_by_type(F_URL) if o.value == TRACKER]
    assert tracker.has_directive(DIRECTIVE_CRAWL)
    for observable in root.get_observables_by_type(F_URL):
        if observable.value != TRACKER:
            assert not observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.integration
def test_engine_reported_email_prefers_the_inner_email(root_analysis, tmp_path):
    report = _message("FW: shared document", sender="reporter@internal.example.org",
                      text="Is this legit? https://helpdesk.example.info/report-phish")
    report.add_attachment(_message("shared document", html=LURE_HTML))

    root, outer = _analyze(root_analysis, tmp_path, report)

    assert outer.has_inner_email is True
    assert outer.primary["url"] == "https://helpdesk.example.info/report-phish"

    entries = build_lure_urls(root)
    assert [entry.primary["url"] for entry in entries] == [LURE, "https://helpdesk.example.info/report-phish"]
    assert entries[0].subject == "shared document"


@pytest.mark.integration
def test_engine_no_urls(root_analysis, tmp_path):
    root, analysis = _analyze(root_analysis, tmp_path, _message("hello", text="no links here"))

    assert analysis is False or analysis is None


@pytest.mark.integration
def test_engine_footer_links_only_have_no_primary(root_analysis, tmp_path):
    html = f'<p>Thanks for your order.</p><a href="{UNSUBSCRIBE}">Unsubscribe</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("order", html=html))

    assert analysis.primary is None
    assert analysis.candidates[0]["url"] == UNSUBSCRIBE
    assert analysis.summary == "Lure URL Analysis: no lure URL identified"
    assert not any(o.has_directive(DIRECTIVE_CRAWL) for o in root.get_observables_by_type(F_URL))
    assert build_lure_urls(root) == []
