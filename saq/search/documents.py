"""Turns an alert into the small set of documents worth indexing.

An alert yields on the order of five to thirty documents: the alert header, one per analyst
comment, one holding every detection description, one per text-bearing analysis (email, command
line, extracted document text, ...) and one per llm_context_document. Nothing is emitted for the
observable graph itself -- identifiers are served by the lexical lane straight out of mysql, and
embedding templated "X observed Y" records is what made the previous index useless (docs/SEARCH.md).

Per-analysis extraction is pluggable: register_extractor(AnalysisClass) attaches a function that
returns the text for that analysis class. saq.search.extractors registers the built-in ones;
integrations register their own the same way.
"""

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Optional

from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.constants import F_FILE
from saq.database.model import Alert, Comment
from saq.search.types import KIND_ALERT, KIND_ANALYSIS, KIND_COMMENT, KIND_CONTEXT, KIND_DETECTION

ALERT_HEADER_KEY = "header"
DETECTIONS_KEY = "detections"

_WHITESPACE_RE = re.compile(r"[ \t\r\f\v]+")
_BLANK_LINES_RE = re.compile(r"\n\s*\n+")


@dataclass(frozen=True)
class SearchDocument:
    """One indexable piece of text about an alert.

    kind + key identify the document within its alert and are stable across re-indexing (they
    feed the qdrant point id), so a re-index is an idempotent upsert rather than a churn.
    """

    kind: str
    key: str
    text: str
    title: Optional[str] = None
    analysis_uuid: Optional[str] = None
    observable_uuid: Optional[str] = None
    # a title that carries content (an email subject) is embedded with the first chunk; a generic
    # label ("command line") is only for display -- embedding it would make every document of that
    # type look alike
    embed_title: bool = True


@dataclass(frozen=True)
class ExtractContext:
    root: RootAnalysis
    max_document_bytes: int

    def read_file_observable(self, observable) -> str:
        """Reads the text of a file observable up to the byte cap ("" when missing)."""
        return read_text_file(getattr(observable, "full_path", None), self.max_document_bytes)


@dataclass(frozen=True)
class Extracted:
    """One piece of text an extractor found. label=True marks the title as a generic label
    (shown to the analyst, not embedded)."""

    title: Optional[str]
    text: str
    label: bool = False


# an extractor returns zero or more Extracted (or bare (title, text) pairs) for one analysis
Extractor = Callable[[Analysis, ExtractContext], Iterable[Extracted | tuple[Optional[str], str]]]

_EXTRACTORS: dict[type, Extractor] = {}


def register_extractor(analysis_class: type) -> Callable[[Extractor], Extractor]:
    """Registers fn as the text extractor for analysis_class (and, via the MRO, its subclasses)."""

    def decorator(fn: Extractor) -> Extractor:
        _EXTRACTORS[analysis_class] = fn
        return fn

    return decorator


def find_extractor(analysis: Analysis) -> Optional[Extractor]:
    for klass in type(analysis).__mro__:
        if klass in _EXTRACTORS:
            return _EXTRACTORS[klass]

    return None


def registered_extractors() -> dict[type, Extractor]:
    return dict(_EXTRACTORS)


def normalize_text(text: Optional[str]) -> str:
    """Collapses runs of horizontal whitespace and blank lines; returns "" for None."""
    if not text:
        return ""

    text = _WHITESPACE_RE.sub(" ", str(text))
    text = _BLANK_LINES_RE.sub("\n", text)
    return "\n".join(line.strip() for line in text.split("\n")).strip()


def read_text_file(path: Optional[str], max_bytes: int) -> str:
    """Reads up to max_bytes of path as utf-8 (undecodable bytes dropped); "" when unreadable."""
    if not path:
        return ""

    try:
        with open(path, "rb") as fp:
            return fp.read(max_bytes).decode("utf-8", errors="ignore")
    except OSError as e:
        logging.debug(f"unable to read {path}: {e}")
        return ""


def find_file_observables(analysis: Analysis, predicate: Callable = lambda observable: True) -> list:
    """The file observables produced by analysis that satisfy predicate."""
    return [o for o in analysis.observables if o.type == F_FILE and predicate(o)]


def _header_lines(pairs: Iterable[tuple[str, Optional[object]]]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in pairs if value not in (None, "", [], {}))


def alert_document(alert: Optional[Alert], root: RootAnalysis) -> Optional[SearchDocument]:
    """The alert header: what the alert is, where it came from, and the analyst-facing instructions."""
    # the description leads (it is not repeated as an embedded title); alert type and tool are
    # short and searchable, while tool instance and queue are boilerplate shared by every alert
    # and stay in the payload only
    description = (alert.description if alert is not None else root.description) or ""
    pairs = [
        ("alert type", alert.alert_type if alert is not None else root.alert_type),
        ("tool", alert.tool if alert is not None else root.tool),
        ("instructions", root.instructions),
    ]

    lines = [description, _header_lines(pairs)]
    for detail in root.summary_details or []:
        header = normalize_text(getattr(detail, "header", None))
        content = normalize_text(getattr(detail, "content", None))
        if content:
            lines.append(f"{header}: {content}" if header else content)

    text = normalize_text("\n".join(lines))
    if not text:
        return None

    return SearchDocument(kind=KIND_ALERT, key=ALERT_HEADER_KEY, title=description or None, text=text, embed_title=False)


def comment_documents(comments: Iterable[Comment]) -> list[SearchDocument]:
    result = []
    for comment in comments:
        text = normalize_text(comment.comment)
        if not text:
            continue

        user = getattr(comment, "user", None)
        title = getattr(user, "gui_display", None) if user is not None else None
        result.append(SearchDocument(kind=KIND_COMMENT, key=str(comment.comment_id), title=title, text=text))

    return result


def detection_document(root: RootAnalysis) -> Optional[SearchDocument]:
    """Every distinct detection description on the tree, in one document ("why this alerted")."""
    seen: set[str] = set()
    lines: list[str] = []
    for detection in list(root.detections) + list(root.all_detection_points):
        description = normalize_text(getattr(detection, "description", None))
        if description and description not in seen:
            seen.add(description)
            lines.append(description)

    if not lines:
        return None

    return SearchDocument(kind=KIND_DETECTION, key=DETECTIONS_KEY, title="detections", text="\n".join(lines), embed_title=False)


def context_documents(root: RootAnalysis) -> list[SearchDocument]:
    """Free-form documents modules attached with add_llm_context_document()."""
    result = []
    for node in list(root.all_analysis) + list(root.all_observables):
        for index, document in enumerate(getattr(node, "llm_context_documents", None) or []):
            text = normalize_text(document)
            if not text:
                continue

            analysis_uuid = node.uuid if isinstance(node, Analysis) else None
            observable_uuid = None if isinstance(node, Analysis) else node.uuid
            result.append(SearchDocument(
                kind=KIND_CONTEXT,
                key=f"{node.uuid}:{index}",
                text=text,
                analysis_uuid=analysis_uuid,
                observable_uuid=observable_uuid,
            ))

    return result


def _load_details(analysis: Analysis, max_document_bytes: int) -> bool:
    """Loads the analysis details unless they are known to exceed the byte cap."""
    size = getattr(analysis, "details_size", None)
    if isinstance(size, int) and not isinstance(size, bool) and size > max_document_bytes:
        logging.debug(f"skipping details of {analysis} ({size} bytes > {max_document_bytes})")
        return False

    # always ask: many analysis classes initialize `details` with default keys, so a truthy dict
    # does not mean the details on disk have been read. load_details() is a no-op when there is
    # no external details file (an analysis built in memory keeps what it has).
    load_details = getattr(analysis, "load_details", None)
    if load_details is None:
        return False

    try:
        load_details()
    except Exception as e:
        logging.warning(f"unable to load details for {analysis}: {e}")
        return False

    return True


def ensure_builtin_extractors() -> None:
    """Registers the built-in extractors (idempotent)."""
    # deferred: the built-in extractors import the analysis modules, and saq.modules (through the
    # observable presenters and the v2 API application, whose search router imports this
    # package) is still initializing when this module is first imported -- a module-level import
    # would be circular
    import saq.search.extractors  # noqa: F401


def analysis_documents(root: RootAnalysis, context: ExtractContext) -> list[SearchDocument]:
    ensure_builtin_extractors()
    result = []
    for analysis in root.all_non_root_analysis:
        extractor = find_extractor(analysis)
        if extractor is None:
            continue

        _load_details(analysis, context.max_document_bytes)

        try:
            extracted = list(extractor(analysis, context))
        except Exception as e:
            logging.warning(f"search extractor failed for {analysis}: {e}")
            continue

        for index, item in enumerate(extracted):
            if not isinstance(item, Extracted):
                item = Extracted(title=item[0], text=item[1])
            title, text = item.title, item.text
            text = normalize_text(text)
            if not text:
                continue

            if len(text.encode("utf-8")) > context.max_document_bytes:
                text = text.encode("utf-8")[:context.max_document_bytes].decode("utf-8", errors="ignore")

            key = analysis.uuid if index == 0 else f"{analysis.uuid}:{index}"
            observable = getattr(analysis, "observable", None)
            result.append(SearchDocument(
                kind=KIND_ANALYSIS,
                key=key,
                title=normalize_text(title) or None,
                text=text,
                analysis_uuid=analysis.uuid,
                observable_uuid=observable.uuid if observable is not None else None,
                embed_title=not item.label,
            ))

    return result


def extract_documents(
    alert: Optional[Alert],
    root: RootAnalysis,
    comments: Iterable[Comment] = (),
    *,
    max_document_bytes: int,
) -> list[SearchDocument]:
    """Every document for an alert, in a stable order."""
    context = ExtractContext(root=root, max_document_bytes=max_document_bytes)
    documents: list[SearchDocument] = []

    header = alert_document(alert, root)
    if header:
        documents.append(header)

    documents.extend(comment_documents(comments))

    detections = detection_document(root)
    if detections:
        documents.append(detections)

    documents.extend(analysis_documents(root, context))
    documents.extend(context_documents(root))

    # a duplicate (kind, key) would collide on the point id; keep the first
    seen: set[tuple[str, str]] = set()
    unique = []
    for document in documents:
        if (document.kind, document.key) in seen:
            continue
        seen.add((document.kind, document.key))
        unique.append(document)

    return unique
