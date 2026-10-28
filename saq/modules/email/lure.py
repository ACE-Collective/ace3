"""Picks the URL a phishing email lures its recipient to (docs/LURE_URL.md)."""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional, Type, override
from urllib.parse import parse_qsl, urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from urlfinderlib.url import URL

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.constants import DIRECTIVE_CRAWL, F_FILE, F_URL, AnalysisExecutionResult
from saq.email import get_email_domain, normalize_email_address
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.html_js_extraction import parse_document
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.modules.phishkit import PhishkitAnalysis
from saq.modules.phishkit_chain import display_url
from saq.modules.url.protected import ProtectedURLAnalysis
from saq.nrd.util import registrable_domain
from saq.util import abs_path
from saq.util.networking import is_subdomain

KEY_PRIMARY = "primary"
KEY_CANDIDATES = "candidates"
KEY_HAS_INNER_EMAIL = "has_inner_email"
KEY_SUBJECT = "subject"

SOURCE_BODY = "body"
SOURCE_QR = "qr"
SOURCE_ATTACHMENT = "attachment"

# the email body parts are the unnamed text parts EmailAnalyzer extracts
BODY_PART_MARKERS = (".unknown_text_html", ".unknown_text_plain")
NON_PART_YARA_TYPES = ("email.headers", "email.combined")
# pdf.py writes a PDF's link annotations, the PDF equivalent of <a href>, to a file of this type
PDF_LINK_ANNOTATIONS_YARA_TYPE = "document.pdf.annotation_uris"

# a body larger than this is not parsed for its anchors
MAX_BODY_BYTES = 5 * 1024 * 1024
ANCHOR_TEXT_MAX_LEN = 100

STATIC_EXTENSIONS = (".png", ".gif", ".jpg", ".jpeg", ".bmp", ".svg", ".ico", ".webp", ".tiff",
                     ".css", ".woff", ".woff2", ".ttf", ".eot")
BUTTON_STYLE_PATTERN = re.compile(r"(background(-color)?\s*:|padding\s*:|border-radius\s*:)", re.I)

DEFAULT_CALL_TO_ACTION_KEYWORDS = [
    "view", "review", "open", "sign", "verify", "download", "access", "confirm", "click", "login",
    "log in", "update", "secure", "document", "pay", "invoice", "shared"]
DEFAULT_NOISE_KEYWORDS = ["unsubscribe", "privacy", "terms", "preferences", "opt-out", "optout", "cookie", "legal"]
DEFAULT_BENIGN_DOMAINS = ["fonts.googleapis.com", "fonts.gstatic.com"]


class LureURLWeights(BaseModel):
    """How much each signal adds to (or takes from) a candidate's score."""

    # a misspelled weight would otherwise be dropped silently and keep its default
    model_config = ConfigDict(extra="forbid")

    qr: int = 35
    body: int = 20
    attachment: int = 15
    clickable: int = 25
    button: int = 15
    call_to_action: int = 20
    only_domain: int = 10
    unwrapped: int = 5
    detection: int = 30
    not_a_link: int = -15
    sender_domain: int = -20
    noise: int = -30
    static: int = -40
    benign: int = -50


class LureURLSettings(BaseModel):
    """The analyst-editable settings file referenced by the module's ``config_path``
    (``etc/lure_url.yaml`` documents every key). A key left out of the file keeps its default."""

    model_config = ConfigDict(extra="forbid")

    call_to_action_keywords: list[str] = Field(
        default_factory=lambda: list(DEFAULT_CALL_TO_ACTION_KEYWORDS),
        description="Anchor text words that ask the recipient to click.")
    noise_keywords: list[str] = Field(
        default_factory=lambda: list(DEFAULT_NOISE_KEYWORDS),
        description="Words in a link or its text that mark it as an unsubscribe, privacy or footer link.")
    benign_domains: list[str] = Field(
        default_factory=lambda: list(DEFAULT_BENIGN_DOMAINS),
        description="Domains (and their subdomains) that are never the lure.")
    max_candidates: int = Field(default=5, ge=1, description="How many ranked candidates to keep, the primary included.")
    crawl_primary: bool = Field(default=True, description="Add the crawl directive to the primary lure URL.")
    min_primary_score: int = Field(default=1, description="A candidate needs at least this score to be called the primary lure URL.")
    weights: LureURLWeights = Field(default_factory=LureURLWeights)

    @field_validator("call_to_action_keywords", "noise_keywords", "benign_domains", mode="before")
    @classmethod
    def _none_is_empty(cls, value):
        # a key left with nothing under it parses as None
        return [] if value is None else value

    @field_validator("weights", mode="before")
    @classmethod
    def _none_is_default(cls, value):
        return {} if value is None else value


def load_lure_settings(config_path: str) -> Optional[LureURLSettings]:
    """Load the settings file. Returns None when it cannot be read or does not validate."""
    path = abs_path(config_path)
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return LureURLSettings.model_validate(yaml.safe_load(fp) or {})
    except Exception:
        logging.exception(f"unable to load lure url settings {path}; the settings already in effect are kept",
                          extra={"path": path})

    return None


class LureURLConfig(AnalysisModuleConfig):
    config_path: str = Field(
        default="etc/lure_url.yaml",
        description="Path to the analyst-editable settings file, relative to SAQ_HOME; blank uses the built-in defaults.")


@dataclass
class Anchor:
    text: str
    button: bool
    # where the link is in the body, the tie-break between equal scores
    position: int = 0


@dataclass
class Candidate:
    observable: Observable
    sources: set[str] = field(default_factory=set)
    attachments: list[str] = field(default_factory=list)
    wrapped_by: Optional[str] = None
    # the candidate URLs this one carries in its query string, e.g. a click tracker's destinations
    carries: list[str] = field(default_factory=list)
    pdf_link: bool = False
    # set when a body part was parsed: whether the URL is a link there, and its anchor
    in_parsed_body: bool = False
    anchor: Optional[Anchor] = None
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    # per reason, the values in it the alert page shows in bold (link text, attachment, carried URLs)
    highlights: list[list[str]] = field(default_factory=list)

    @property
    def rank_key(self) -> tuple:
        # extraction order is not stable (urlfinderlib returns a set), so ties go by position in
        # the body, then by value
        return (-self.score, self.anchor.position if self.anchor else float("inf"), self.observable.value)

    def to_dict(self) -> dict:
        return {
            "url": self.observable.value,
            "observable_uuid": self.observable.uuid,
            "score": self.score,
            "sources": sorted(self.sources),
            "anchor_text": self.anchor.text if self.anchor else None,
            "carries": self.carries,
            "reasons": self.reasons,
            "highlights": self.highlights,
        }


class LureURLAnalysis(Analysis):
    """Which URL is this email luring its recipient to?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_PRIMARY: None,
            KEY_CANDIDATES: [],
            KEY_HAS_INNER_EMAIL: False,
            KEY_SUBJECT: None,
        }

    @override
    @property
    def display_name(self) -> str:
        return "Lure URL Analysis"

    @property
    def primary(self) -> Optional[dict]:
        return self.details.get(KEY_PRIMARY) if self.details else None

    @primary.setter
    def primary(self, value: Optional[dict]):
        self.details[KEY_PRIMARY] = value

    @property
    def candidates(self) -> list[dict]:
        return self.details.get(KEY_CANDIDATES, []) if self.details else []

    @candidates.setter
    def candidates(self, value: list[dict]):
        self.details[KEY_CANDIDATES] = value

    @property
    def has_inner_email(self) -> bool:
        return bool(self.details.get(KEY_HAS_INNER_EMAIL)) if self.details else False

    @has_inner_email.setter
    def has_inner_email(self, value: bool):
        self.details[KEY_HAS_INNER_EMAIL] = value

    def generate_summary(self) -> Optional[str]:
        if not self.primary:
            return f"{self.display_name}: no lure URL identified"

        return f"{self.display_name}: {self.primary['url']} ({'; '.join(self.primary['reasons'])})"


def is_body_part(observable: Observable) -> bool:
    return any(marker in (observable.file_name or "") for marker in BODY_PART_MARKERS)


def normalize_url(value: str) -> str:
    try:
        return URL(value).value or value
    except Exception:
        # urlfinderlib rejects some values; the raw value still matches itself
        return value


def is_http_url(value: str) -> bool:
    try:
        return urlparse(value).scheme.lower() in ("http", "https")
    except ValueError:
        # e.g. "http://[x/": a URL observable is not validated, and an attacker writes the link
        return False


def is_link(candidate: "Candidate") -> bool:
    """Whether the recipient can follow this URL from the email, as opposed to an image or resource."""
    return bool(candidate.anchor or candidate.pdf_link or SOURCE_QR in candidate.sources
                or (SOURCE_BODY in candidate.sources and not candidate.in_parsed_body))


def _is_button(tag) -> bool:
    for node in (tag, tag.parent):
        if node is None or not hasattr(node, "get"):
            continue
        if node.get("role") == "button":
            return True
        if any("btn" in c.lower() or "button" in c.lower() for c in (node.get("class") or [])):
            return True
        if BUTTON_STYLE_PATTERN.search(node.get("style") or ""):
            return True
        if node.get("bgcolor"):
            return True
    return False


def parse_body_anchors(html: str) -> dict[str, Anchor]:
    """Returns the body's clickable links, keyed by their normalized URL, first one wins."""
    anchors: dict[str, Anchor] = {}
    position = 0
    soup = parse_document(html)
    for tag in soup.find_all(["a", "area", "form"]):
        href = tag.get("action") if tag.name == "form" else tag.get("href")
        if not href or not href.strip():
            continue

        text = tag.get_text(" ", strip=True)
        if not text:
            image = tag.find("img")
            if image is not None:
                text = f"[image{': ' + image.get('alt') if image.get('alt') else ''}]"
        anchor = Anchor(text=text[:ANCHOR_TEXT_MAX_LEN], button=_is_button(tag), position=position)
        position += 1
        for key in {href.strip(), normalize_url(href.strip())}:
            anchors.setdefault(key, anchor)

    return anchors


def _read_body(observable: Observable, root_uuid: Optional[str]) -> Optional[str]:
    path = observable.full_path
    try:
        if os.path.getsize(path) > MAX_BODY_BYTES:
            logging.info(f"email body {path} is too large to parse for lure links")
            return None
        with open(path, "rb") as fp:
            return fp.read().decode("utf-8", errors="ignore")
    except OSError:
        logging.exception(f"unable to read email body {path} in {root_uuid} for lure links",
                          extra={"root_uuid": root_uuid, "observable_uuid": observable.uuid, "path": path})
        return None


def carried_urls(url: str) -> list[str]:
    """Returns the http(s) URLs carried in url's query string, e.g. a click tracker's ?u=..."""
    try:
        query = urlparse(url).query
    except ValueError:
        # not a URL urlparse can split, so it carries nothing
        return []
    return [value.strip() for _, value in parse_qsl(query)
            if value.strip().lower().startswith(("http://", "https://"))]


def fold_carried_urls(candidates: list[Candidate]) -> list[Candidate]:
    """Folds the URLs a candidate carries in its query string into that candidate.

    urlfinderlib extracts the URLs inside a click tracker's query string as URLs of their own,
    but the link in the email, the lure, is the tracker. Where it sends the recipient is the
    crawl's business, not this module's.
    """
    by_value: dict[str, Candidate] = {}
    for candidate in candidates:
        by_value.setdefault(candidate.observable.value, candidate)
        by_value.setdefault(normalize_url(candidate.observable.value), candidate)

    # a carried URL sits percent-encoded inside its carrier, so it is always the shorter of the
    # two and carrying cannot form a cycle; in a chain (tracker -> tracker -> lure) only the
    # outermost link is left
    folded: set[str] = set()
    for carrier in candidates:
        for value in carried_urls(carrier.observable.value):
            carried = by_value.get(value) or by_value.get(normalize_url(value))
            if carried is None or carried is carrier or carried.observable.value in carrier.carries:
                continue
            folded.add(carried.observable.uuid)
            carrier.carries.append(carried.observable.value)

    return [c for c in candidates if c.observable.uuid not in folded]


class CandidateCollector:
    """Walks one email's subtree for the URLs it carries, recording where each came from.

    Crawl output (PhishkitAnalysis) is skipped: those URLs come after the click. A nested email
    is skipped too: it gets its own LureURLAnalysis.
    """

    def __init__(self, root_uuid: Optional[str] = None):
        self.root_uuid = root_uuid
        self.candidates: dict[str, Candidate] = {}
        self.wrappers: set[str] = set()
        self.visited: set[tuple[str, str]] = set()
        self.has_inner_email = False

    def collect(self, email_analysis: EmailAnalysis) -> list[Candidate]:
        anchors: dict[str, Anchor] = {}
        parsed_body = False
        parts = [o for o in email_analysis.observables
                 if o.type == F_FILE and not any(o.has_yara_meta("type", t) for t in NON_PART_YARA_TYPES)]

        # EmailAnalyzer also extracts an attached email's parts into this email, and those
        # belong to the inner email's lure, not this one's
        inner_parts = set()
        for part in parts:
            inner_analysis = part.get_analysis(EmailAnalysis)
            if inner_analysis:
                self.has_inner_email = True
                inner_parts.add(part.value)
                inner_parts.update(o.value for o in inner_analysis.observables if o.type == F_FILE)

        for part in parts:
            if part.value in inner_parts:
                continue

            if is_body_part(part):
                if ".unknown_text_html" in part.file_name:
                    html = _read_body(part, self.root_uuid)
                    if html is not None:
                        try:
                            anchors.update(parse_body_anchors(html))
                            parsed_body = True
                        except Exception:
                            # the URLs are still scored, only without their anchors
                            logging.exception(f"unable to parse email body {part.full_path} in {self.root_uuid} for lure links",
                                              extra={"root_uuid": self.root_uuid, "observable_uuid": part.uuid,
                                                     "path": part.full_path})
                self._walk(part, SOURCE_BODY, None, None, False)
            else:
                self._walk(part, SOURCE_ATTACHMENT, part.file_name, None, False)

        result = [c for c in self.candidates.values() if c.observable.uuid not in self.wrappers]
        for candidate in result:
            if SOURCE_BODY not in candidate.sources or not parsed_body:
                continue
            candidate.in_parsed_body = True
            for value in (candidate.wrapped_by, candidate.observable.value):
                if value is None:
                    continue
                anchor = anchors.get(value) or anchors.get(normalize_url(value))
                if anchor:
                    candidate.anchor = anchor
                    break

        return fold_carried_urls(result)

    def _walk(self, observable: Observable, source: str, attachment: Optional[str], wrapped_by: Optional[str],
              pdf_link: bool):
        # recorded on every visit: urlfinderlib also extracts the URL inside a wrapper directly,
        # so the visit through the wrapper may not be the first
        if observable.type == F_URL:
            self._record(observable, source, attachment, wrapped_by, pdf_link)

        key = (observable.uuid, source)
        if key in self.visited:
            return
        self.visited.add(key)

        if observable.type == F_URL:
            protected = observable.get_analysis(ProtectedURLAnalysis)
            if protected:
                for child in protected.observables:
                    if child.type == F_URL:
                        self.wrappers.add(observable.uuid)
                        self._walk(child, source, attachment, wrapped_by or observable.value, pdf_link)
            return

        if observable.type != F_FILE:
            return

        link_annotations = observable.has_yara_meta("type", PDF_LINK_ANNOTATIONS_YARA_TYPE)
        for analysis in observable.all_analysis:
            if isinstance(analysis, (PhishkitAnalysis, EmailAnalysis)):
                continue
            child_source = SOURCE_QR if isinstance(analysis, QRCodeAnalysis) else source
            for child in analysis.observables:
                self._walk(child, child_source, attachment, None, link_annotations)

    def _record(self, observable: Observable, source: str, attachment: Optional[str], wrapped_by: Optional[str],
                pdf_link: bool):
        candidate = self.candidates.get(observable.uuid)
        if candidate is None:
            candidate = Candidate(observable=observable)
            self.candidates[observable.uuid] = candidate
        candidate.sources.add(source)
        if attachment and attachment not in candidate.attachments:
            candidate.attachments.append(attachment)
        if wrapped_by and not candidate.wrapped_by:
            candidate.wrapped_by = wrapped_by
        candidate.pdf_link = candidate.pdf_link or pdf_link


def _matching_keyword(keywords: list[str], *values: Optional[str]) -> Optional[str]:
    for value in values:
        if not value:
            continue
        value = value.lower()
        for keyword in keywords:
            if keyword.lower() in value:
                return keyword
    return None


def score_candidates(candidates: list[Candidate], sender_domains: set[str], settings: LureURLSettings):
    """Scores each candidate in place, recording a reason for every signal that applied."""
    linked_domains = {registrable_domain(c.observable.value) for c in candidates if is_link(c)}
    linked_domains.discard("")
    external_domains = linked_domains - sender_domains

    for candidate in candidates:
        score = 0
        reasons = []
        highlights = []

        def signal(weight: int, reason: str, *values: str):
            nonlocal score
            score += weight
            reasons.append(reason)
            highlights.append(list(values))

        url = candidate.observable.value
        parsed = urlparse(url)
        domain = registrable_domain(url)
        anchor_text = candidate.anchor.text if candidate.anchor else None
        weights = settings.weights

        if SOURCE_QR in candidate.sources:
            signal(weights.qr, "decoded from a QR code")
        if SOURCE_BODY in candidate.sources:
            signal(weights.body, "found in the email body")
        elif SOURCE_ATTACHMENT in candidate.sources:
            signal(weights.attachment, f"found in attachment {', '.join(candidate.attachments)}",
                   *candidate.attachments)

        if candidate.anchor:
            signal(weights.clickable, "clickable link" + (f" with text '{anchor_text}'" if anchor_text else ""),
                   *([anchor_text] if anchor_text else []))
            if candidate.anchor.button:
                signal(weights.button, "styled as a button")
            keyword = _matching_keyword(settings.call_to_action_keywords, anchor_text)
            if keyword:
                signal(weights.call_to_action, f"call-to-action text ({keyword})")
        elif candidate.pdf_link:
            signal(weights.clickable, "clickable link in a PDF")
        elif candidate.in_parsed_body and SOURCE_QR not in candidate.sources:
            signal(weights.not_a_link, "not a clickable link in the body")

        if candidate.wrapped_by:
            signal(weights.unwrapped, f"unwrapped from {display_url(candidate.wrapped_by)}")
        if candidate.carries:
            carried = [display_url(url, 60) for url in candidate.carries]
            signal(0, f"carries {len(carried)} URL{'' if len(carried) == 1 else 's'}: {', '.join(carried)}", *carried)
        if candidate.observable.has_detection_points():
            signal(weights.detection, "has detection points")
        if domain and external_domains == {domain}:
            signal(weights.only_domain, "the only linked external domain")

        if parsed.path.lower().endswith(STATIC_EXTENSIONS):
            signal(weights.static, "points at an image or static resource")
        keyword = _matching_keyword(settings.noise_keywords, url, anchor_text)
        if keyword:
            signal(weights.noise, f"looks like a footer link ({keyword})")
        if domain and domain in sender_domains:
            signal(weights.sender_domain, f"same domain as the sender ({domain})")
        if parsed.hostname and any(is_subdomain(parsed.hostname, d) for d in settings.benign_domains):
            signal(weights.benign, "benign infrastructure domain")

        candidate.score = score
        candidate.reasons = reasons
        candidate.highlights = highlights


def reason_segments(reason: str, values: list[str]) -> list[tuple[str, bool]]:
    """Splits a reason into (text, bold) pieces around the values it highlights, in order."""
    segments = []
    rest = reason
    for value in values:
        index = rest.find(value) if value else -1
        if index < 0:
            continue
        if index:
            segments.append((rest[:index], False))
        segments.append((value, True))
        rest = rest[index + len(value):]
    if rest:
        segments.append((rest, False))
    return segments


def _with_reason_segments(candidate: dict) -> dict:
    # an analysis saved before highlights were recorded has none, and renders plain
    highlights = candidate.get("highlights") or []
    reasons = candidate.get("reasons") or []
    return {**candidate, "reason_segments": [
        reason_segments(reason, highlights[i] if i < len(highlights) else []) for i, reason in enumerate(reasons)]}


def sender_domains(email_analysis: EmailAnalysis) -> set[str]:
    domains = set()
    for value in (email_analysis.mail_from_address, email_analysis.return_path):
        address = normalize_email_address(value)
        domain = get_email_domain(address) if address else None
        if domain:
            domains.add(registrable_domain(domain))
    domains.discard("")
    return domains


class LureURLAnalyzer(AnalysisModule):
    config: LureURLConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._settings = LureURLSettings()
        self._settings_watched = False

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return LureURLConfig

    def _load_settings(self):
        # a file that fails to load keeps the settings already in effect, so a bad edit does not
        # undo the analysts' tuning
        settings = load_lure_settings(self.config.config_path)
        if settings is not None:
            self._settings = settings
            logging.info(f"loaded lure url settings from {abs_path(self.config.config_path)}")

    @property
    def settings(self) -> LureURLSettings:
        if not self._settings_watched and self.config.config_path:
            self._settings_watched = True
            path = abs_path(self.config.config_path)
            # the file watcher skips a missing file without a word
            try:
                os.stat(path)
            except OSError:
                logging.exception(f"lure url settings file {path} does not exist or cannot be read; using the built-in defaults until it does",
                                  extra={"path": path})
            # loads the settings now if the file exists, and again whenever it changes
            self.watch_file(path, self._load_settings)

        return self._settings

    @property
    def generated_analysis_type(self):
        return LureURLAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: Observable) -> AnalysisExecutionResult:
        if not _file.get_analysis(EmailAnalysis):
            return AnalysisExecutionResult.COMPLETED

        # scored in final analysis, once every part has had its URLs extracted
        return AnalysisExecutionResult.INCOMPLETE

    def execute_final_analysis(self, _file: Observable) -> AnalysisExecutionResult:
        """Scores the email's candidates on every final pass.

        The analysis is never sealed (INCOMPLETE, as ObservableModifierAnalyzer does): a module
        that works in final analysis too, such as xlmdeobfuscator, adds URLs after the first final
        pass, and the engine calls this again in the next one. A pass that changes nothing adds
        nothing, so the engine still stops.
        """
        email_analysis = _file.get_and_load_analysis(EmailAnalysis)
        if not email_analysis:
            return AnalysisExecutionResult.COMPLETED

        root = self.get_root()
        collector = CandidateCollector(root.uuid)
        candidates = [c for c in collector.collect(email_analysis) if is_http_url(c.observable.value)]
        if not candidates:
            logging.debug(f"no lure url candidates in {_file}")
            return AnalysisExecutionResult.INCOMPLETE

        settings = self.settings
        score_candidates(candidates, sender_domains(email_analysis), settings)
        ranked = sorted(candidates, key=lambda c: c.rank_key)
        primary = ranked[0] if ranked[0].score >= settings.min_primary_score else None

        analysis = _file.get_and_load_analysis(LureURLAnalysis) or self.create_analysis(_file)
        # kept re-runnable: AnalysisModule.accepts() skips an observable whose analysis is completed
        analysis.completed = False
        previous = analysis.primary["observable_uuid"] if analysis.primary else None
        analysis.details = {
            KEY_PRIMARY: primary.to_dict() if primary else None,
            KEY_CANDIDATES: [c.to_dict() for c in ranked[:settings.max_candidates]],
            KEY_HAS_INNER_EMAIL: collector.has_inner_email,
            # stored so the alert page need not load the email's analysis for it
            KEY_SUBJECT: email_analysis.decoded_subject or email_analysis.subject,
        }
        analysis.summary = analysis.generate_summary()

        if primary:
            if settings.crawl_primary:
                primary.observable.add_directive(DIRECTIVE_CRAWL)
            if primary.observable.uuid != previous:
                logging.info(
                    f"lure url for {_file} in {root} is {primary.observable.value} (score {primary.score})",
                    extra={"root_uuid": root.uuid, "observable_uuid": primary.observable.uuid,
                           "url": primary.observable.value, "lure_score": primary.score})

        return AnalysisExecutionResult.INCOMPLETE


@dataclass
class LureURLEntry:
    """One email's primary lure URL, as the alert page shows it."""
    email: Observable
    subject: Optional[str]
    primary: dict
    observable: Optional[Observable]
    runners_up: list[dict]


def build_lure_urls(root: RootAnalysis) -> list[LureURLEntry]:
    """Returns the primary lure URL of every email in the tree, innermost emails first.

    An email that carries another email is usually the report an analyst or a user forwarded,
    so the lure is in the email it carries.
    """
    entries = []
    for analysis in root.all_analysis:
        if not isinstance(analysis, LureURLAnalysis) or analysis.observable is None:
            continue
        try:
            analysis.load_details()
            if not analysis.primary:
                continue
            observable = root.get_observable(analysis.primary["observable_uuid"])
            entries.append((analysis.has_inner_email, LureURLEntry(
                email=analysis.observable,
                subject=analysis.details.get(KEY_SUBJECT),
                primary=_with_reason_segments(analysis.primary),
                observable=observable,
                runners_up=[_with_reason_segments(c) for c in analysis.candidates
                            if c["observable_uuid"] != analysis.primary["observable_uuid"]],
            )))
        except Exception:
            # the alert page renders without this entry rather than failing
            logging.exception(f"unable to build the lure url entry for {analysis.observable} in {root.uuid}",
                              extra={"root_uuid": root.uuid, "observable_uuid": analysis.observable.uuid})

    return [entry for _, entry in sorted(entries, key=lambda e: e[0])]
