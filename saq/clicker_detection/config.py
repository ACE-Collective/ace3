# vim: sw=4:ts=4:et:cc=120

"""Loading and interpreting the analyst-editable clicker detection search config.

The config maps each source (``splunk``, later ``logscale``, ...) to a set of searches
keyed by observable type (``url``, ``fqdn``). Each search defines the query, time
window, field-to-observable mappings, how to render result rows as ClickerEvents, and
the on-hit response. Example::

    splunk:
      enabled: true
      searches:
        url:
          query: |
            index=<your_url_click_index> sourcetype="<your_url_click_sourcetype>" Url="<O_VALUE>" <TIMESPEC>
            | table Timestamp AccountUpn ActionType Url NetworkMessageId
          time_ranges: { TIMESPEC: { duration_before: "07:00:00:00", duration_after: "00:01:00:00" } }
          use_index_time: false
          observable_mapping:
            - { field: AccountUpn, type: email_address, display_type: Clicker }
          event_mapping: { timestamp: Timestamp, user: AccountUpn, action_type: ActionType, url: Url }
          on_hit: { escalate_action_types: [ClickAllowed], add_detection_point: true, crawl_clicked_url: true }

This module is imported by both the analysis module (which watches the file for live
reload) and the Flask "Open in <source>" observable action (which builds a search URL
without needing the module to have run).
"""

import logging
import os
import re
import urllib.parse
from datetime import timedelta
from typing import Optional
from urlfinderlib.url import URL, URLList

import yaml

from saq.configuration.config import get_splunk_config
from saq.constants import F_URL
from saq.environment import get_base_dir
from saq.splunk import encode_splunk_query_link, splunk_gui_path
from saq.util import create_timedelta, local_time

SOURCE_SPLUNK = "splunk"

# Time-window tokens substituted into queries; stripped when building a GUI link
# (the window is supplied as URL params instead).
_TIMESPEC_TOKEN_RE = re.compile(r"<[A-Z_]*TIMESPEC>")

# Fallback window used for a GUI link when a search defines no time_ranges.
_DEFAULT_BEFORE = timedelta(days=7)
_DEFAULT_AFTER = timedelta(hours=1)


def resolve_config_path(config_path: str) -> str:
    """Resolve a clicker config path (relative to SAQ_HOME) to an absolute path."""
    if os.path.isabs(config_path):
        return config_path
    return os.path.join(get_base_dir(), config_path)


def load_clicker_config(config_path: str) -> dict:
    """Load and parse the clicker detection config YAML. Returns ``{}`` on any error
    (missing file, parse error) so callers degrade to a clean no-op."""
    path = resolve_config_path(config_path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logging.debug("clicker detection config not found: %s", path)
        return {}
    except Exception as e:
        logging.warning("failed to load clicker detection config %s: %s", path, e)
        return {}


def get_searches_for(config: dict, source: str, observable_type: str) -> list[tuple[str, dict]]:
    """Return every enabled ``(name, search_def)`` for a source that applies to this
    observable type, in config order.

    Searches are keyed by name and each declares the observable types it covers via
    ``observable_types``. Returns [] when the config is empty or the source is
    missing/disabled.
    """
    source_cfg = (config or {}).get(source) or {}
    if not source_cfg.get("enabled", False):
        return []

    result: list[tuple[str, dict]] = []
    for name, search_def in (source_cfg.get("searches") or {}).items():
        if not isinstance(search_def, dict):
            continue
        if observable_type in (search_def.get("observable_types") or []):
            result.append((name, search_def))
    return result


def _max_window(time_ranges: Optional[dict]) -> tuple[timedelta, timedelta]:
    """Return the widest (before, after) timedeltas across the configured time ranges,
    falling back to a sensible default when none are configured."""
    before = timedelta(0)
    after = timedelta(0)
    for tr in (time_ranges or {}).values():
        tr_before = tr.get("duration_before") if isinstance(tr, dict) else tr
        tr_after = tr.get("duration_after") if isinstance(tr, dict) else None
        if tr_before:
            before = max(before, create_timedelta(tr_before))
        if tr_after:
            after = max(after, create_timedelta(tr_after))
    if before == timedelta(0) and after == timedelta(0):
        return _DEFAULT_BEFORE, _DEFAULT_AFTER
    return before, after


def _escape_value(value: str) -> str:
    """Escape backslashes/quotes the same way SplunkAPIAnalyzer does."""
    value = value.replace("\\", "\\\\")
    return value.replace('"', '\\"').replace("'", "\\'")


def get_clicker_match_values(observable) -> list[str]:
    """Return all values a clicker search should match for this observable.

    For a url observable that means the original URL plus every urlfinderlib "child URL"
    permutation (decoded base64 query params, tracking-link redirects, etc.) — so a single
    "Check for clickers" covers the form the user actually clicked, not just the observable.
    For any other type (e.g. fqdn) there are no child URLs, so it's just the value.

    Pure string/decoding work (no network I/O). urlfinderlib can raise on some malformed
    inputs (e.g. a base64-padding bug on certain mandrillapp URLs), so we guard and fall
    back to the single value.
    """
    if observable.type != F_URL:
        return [observable.value]

    try:
        values = URLList([URL(observable.value)]).get_all_urls()
        return sorted(values) if values else [observable.value]
    except Exception as e:
        logging.warning("urlfinderlib child-url extraction failed for %s: %s", observable.value, e)
        return [observable.value]


def clicker_match_values(observable, search_def: dict) -> list[str]:
    """All values a search should match for this observable.

    Starts from the URL permutations (`get_clicker_match_values`). When the search sets
    ``match_url_encoded``, also appends the percent-encoded form of each value
    (`urllib.parse.quote(v, safe="")`). That's needed for sources where an emailed URL is
    stored SafeLinks-wrapped and percent-encoded (e.g. CrowdStrike `CommandLine`):
    ``https%3A%2F%2F...``. Order-stable and deduped.
    """
    values = get_clicker_match_values(observable)
    if not search_def.get("match_url_encoded"):
        return values

    encoded = [urllib.parse.quote(v, safe="") for v in values]
    out: list[str] = []
    seen: set[str] = set()
    for v in values + encoded:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def splunk_value_expansion(values: list[str], escape_fn=_escape_value) -> str:
    """Render match values as a Splunk OR-group: ``("v1" OR "v2" ...)`` (escaped, quoted).

    This is the Splunk-specific formatting; ``get_clicker_match_values`` stays source-agnostic
    so a future Logscale module can format the same value list its own way.
    """
    return "(" + " OR ".join(f'"{escape_fn(v)}"' for v in values) + ")"


def _build_one_splunk_url(search_def: dict, observable, *, api_name: str = "default",
                          anchor_time=None) -> Optional[str]:
    """Build a Splunk web search URL for one search definition + observable."""
    query = search_def.get("query")
    if not query:
        return None

    use_index_time = bool(search_def.get("use_index_time", False))

    # <O_VALUE> expands to a quoted OR-group of all URL permutations (incl. the original).
    query = query.replace("<O_VALUE>", splunk_value_expansion(clicker_match_values(observable, search_def)))
    query = query.replace("<O_TYPE>", observable.type)
    # The window is supplied as URL params, so drop the inline timespec tokens.
    query = _TIMESPEC_TOKEN_RE.sub("", query)

    anchor = anchor_time or observable.time or local_time()
    before, after = _max_window(search_def.get("time_ranges"))
    start = anchor - before
    end = anchor + after

    resolved_api = search_def.get("api_name") or api_name
    splunk_config = get_splunk_config(resolved_api)
    gui_path = splunk_gui_path(getattr(splunk_config, "app_context", None))
    return encode_splunk_query_link(splunk_config.host, gui_path, query, start, end, use_index_time)


def build_splunk_clicker_search_urls(config: dict, observable, *, api_name: str = "default",
                                     anchor_time=None) -> list[dict]:
    """Build a Splunk web search URL for every enabled Splunk clicker search that applies to
    ``observable`` — returns ``[{"name": ..., "url": ...}, ...]`` (empty if none).

    Used by the "Open in Splunk" observable action so analysts can open each underlying
    search themselves, before/without running detection.
    """
    out: list[dict] = []
    for name, search_def in get_searches_for(config, SOURCE_SPLUNK, observable.type):
        url = _build_one_splunk_url(search_def, observable, api_name=api_name, anchor_time=anchor_time)
        if url:
            out.append({"name": name, "url": url})
    return out
