"""The crawl chains on the alert page: where each phishkit scan went, hop by hop.

The scanner records the main frame's navigations in metrics.json under
"navigation" (phishkit/scanner.py, Scanner.navigation_chain), and PhishkitAnalysis
keeps metrics.json in its details. This turns them into what
app/templates/analysis/crawl_chains.html renders, linking each hop to its URL
observable in the tree. A scan recorded before the scanner wrote "navigation" has
no chain and is left out.
"""

import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from urlfinderlib.url import URL

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.constants import F_FILE, F_URL
from saq.modules.phishkit import PhishkitAnalysis

# how a hop was reached, keyed by the scanner's "via"
VIA_LABELS = {
    "start": "start",
    "redirect": "HTTP redirect",
    "script": "script",
    "parser": "markup",
    "other": "navigation",
}

DISPLAY_URL_MAX_LEN = 100

SCREENSHOT_FILE_NAME = "screenshot.png"


def display_url(url: str, max_len: int = DISPLAY_URL_MAX_LEN) -> str:
    """Returns url without its scheme, cut to max_len in the middle.

    The middle, not the end: two hops of a chain often share a long prefix and
    differ only in a trailing parameter (an OAuth authorize URL and its reload
    with one more flag), and the host at the front is what is read first.
    """
    value = url.split("://", 1)[-1] if url.startswith(("http://", "https://")) else url
    if len(value) > max_len:
        tail = max_len // 3
        return value[:max_len - tail] + "..." + value[-tail:]
    return value


@dataclass
class CrawlHop:
    url: str
    # "start", "redirect", or how a new navigation began ("script", "parser", "other")
    via: str
    status: Optional[int]
    # the net error that ended the hop, e.g. "net::ERR_HTTP_RESPONSE_CODE_FAILURE"
    error: Optional[str]
    # "proxy" or "direct"; None for a URL with no host
    route: Optional[str]
    # the URL observable with this value, which the hop links to
    observable: Optional[Observable]

    @property
    def via_label(self) -> str:
        return VIA_LABELS.get(self.via, self.via)

    @property
    def display_url(self) -> str:
        return display_url(self.url)

    @property
    def failed(self) -> bool:
        return bool(self.error) or (isinstance(self.status, int) and self.status >= 400)


@dataclass
class CrawlChain:
    # the crawled URL or the rendered file
    target: Observable
    # which way the scan went, e.g. "via proxy" or "direct: the proxy refused <host>"
    route: str
    # per-hop routes are shown only when the scan ran through the proxy
    show_routes: bool
    hops: list[CrawlHop]
    # the URL Chrome ended up showing, when it is not the last hop's
    final_page: Optional[str]
    screenshot: Optional[Observable]

    @property
    def target_display(self) -> str:
        if self.target.type == F_FILE:
            return getattr(self.target, "file_name", None) or str(self.target.value)
        return display_url(str(self.target.value))


def describe_route(proxy_status: Optional[dict]) -> str:
    """Returns which way a scan went, from the proxy.json the manager wrote."""
    if not proxy_status or not proxy_status.get("configured"):
        return "direct"
    if proxy_status.get("final_route") == "proxy":
        return "via proxy"

    reason = proxy_status.get("fallback_reason")
    details = proxy_status.get("fallback_details") or {}
    if reason == "error_pattern":
        host = urlparse(details.get("failed_url") or "").netloc
        return f"direct: the proxy refused {host}" if host else "direct: the proxy failed"
    if reason == "status_code":
        return f"direct: the proxy returned {details.get('matched_status_code')}"
    if reason == "timeout":
        return "direct: the proxy attempt timed out"
    return "direct"


def _find_url_observable(url: str, url_observables: dict[str, Observable]) -> Optional[Observable]:
    observable = url_observables.get(url)
    if observable is not None:
        return observable
    # PhishkitAnalyzer adds URLs as urlfinderlib normalizes them
    try:
        return url_observables.get(URL(url).value)
    except Exception:
        return None


def _load_metrics(analysis: PhishkitAnalysis) -> Optional[dict]:
    # a root read from disk carries only the summary of each analysis; the details
    # (metrics.json among them) are loaded on request
    if analysis.metrics is None and analysis.external_details_path is not None:
        analysis.load_details()
    return analysis.metrics


def _build_chain(analysis: PhishkitAnalysis, url_observables: dict[str, Observable]) -> Optional[CrawlChain]:
    metrics = _load_metrics(analysis)
    if not isinstance(metrics, dict) or not metrics.get("navigation"):
        return None

    target = analysis.observable
    hops = []
    for hop in metrics["navigation"]:
        url = hop.get("url") or ""
        if hop.get("via") == "start" and target.type == F_URL:
            observable = target
        else:
            observable = _find_url_observable(url, url_observables)
        hops.append(CrawlHop(
            url=url,
            via=hop.get("via") or "other",
            status=hop.get("status"),
            error=hop.get("error"),
            route=hop.get("route"),
            observable=observable,
        ))

    # a rendered file that never navigated anywhere has no chain to show
    if target.type == F_FILE and len(hops) < 2:
        return None

    final_page = None
    document_url = metrics.get("document_url")
    if document_url and document_url != hops[-1].url:
        if document_url.startswith("chrome-error://"):
            final_page = "Chrome's error page"
        else:
            final_page = display_url(document_url)

    screenshot = None
    for observable in analysis.observables:
        if observable.type == F_FILE and getattr(observable, "file_name", None) == SCREENSHOT_FILE_NAME:
            screenshot = observable
            break

    proxy_status = analysis.proxy_status
    return CrawlChain(
        target=target,
        route=describe_route(proxy_status),
        show_routes=bool(proxy_status and proxy_status.get("final_route") == "proxy"),
        hops=hops,
        final_page=final_page,
        screenshot=screenshot,
    )


def build_crawl_chains(root: RootAnalysis) -> list[CrawlChain]:
    """Returns one CrawlChain per phishkit scan in the tree that recorded its navigation."""
    url_observables: dict[str, Observable] = {}
    for observable in root.get_observables_by_type(F_URL):
        url_observables.setdefault(str(observable.value), observable)

    chains = []
    for analysis in root.all_analysis:
        if not isinstance(analysis, PhishkitAnalysis) or analysis.observable is None:
            continue
        try:
            chain = _build_chain(analysis, url_observables)
        except Exception as e:
            # the alert page renders without the card rather than failing
            logging.warning("unable to build the crawl chain for %s: %s", analysis, e)
            continue
        if chain is not None:
            chains.append(chain)

    return chains
