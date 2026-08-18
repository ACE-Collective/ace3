# vim: sw=4:ts=4:et:cc=120

"""Source-agnostic clicker-detection orchestration shared by all sources (Splunk, Logscale, ...).

A concrete analyzer combines :class:`ClickerDetectionMixin` with a source's async API analyzer
(e.g. ``SplunkAPIAnalyzer``, ``LogscaleAPIAnalyzer``) and implements three small hooks:

- ``_expand_value_clause(values)`` — format the match-value list into the source's query clause
  (Splunk: a quoted OR-group; Logscale: a regex alternation).
- ``_build_search_link()`` — a URL that opens the current search in the source's UI.
- ``_reset_job_slot(analysis)`` — clear the source's async-job state between searches.

Everything else — watching the analyst config, running every applicable search sequentially across
the delay/resume cycle, extracting observables, publishing ClickerEvents, and the on-hit response —
lives here and is identical across sources.
"""

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, Field

from saq.analysis.module_path import MODULE_PATH
from saq.clicker_detection.config import (
    clicker_match_values,
    get_clicker_match_values,
    get_searches_for,
    load_clicker_config,
    resolve_config_path,
)
from saq.clicker_detection.timeline import ClickerEvent
from saq.constants import AnalysisExecutionResult, DIRECTIVE_CRAWL, F_URL
from saq.error.reporting import report_exception
from saq.modules.api_analysis import AnalysisDelay
from saq.observables.mapping import ObservableMapping
from saq.query.extraction import extract_observables_from_event
from saq.signatures.builtin import URL_CLICKER
from saq.util import create_timedelta, parse_event_time


def parse_clicker_timestamp(ts) -> Optional[datetime]:
    """Best-effort parse of a click timestamp into tz-aware UTC.

    Handles ACE's own formats plus source formats like MS Defender's ISO8601 with a trailing Z and
    >6 fractional-second digits (which datetime can't parse directly). Returns None if nothing works.
    """
    if ts is None or ts == "":
        return None
    # numeric epoch (e.g. Logscale @timestamp is ms since epoch, sometimes as a string)
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.strip().isdigit()):
            num = int(ts)
            seconds = num / 1000 if num > 1_000_000_000_000 else num  # 13-digit ms vs 10-digit s
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception:
        pass
    try:
        return parse_event_time(ts)
    except Exception:
        pass
    try:
        # normalize Z -> +00:00 and trim fractional seconds to 6 digits
        s = re.sub(r'(\.\d{6})\d+', r'\1', ts.strip().replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        return datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except Exception:
        return None


class ClickerConfigMixin(BaseModel):
    """Config fields shared by every source's clicker analyzer config.

    The query/time_ranges/observable_mapping come from the analyst-editable clicker config file
    (per source + observable type), NOT from saq config. The placeholder ``query`` just satisfies
    BaseAPIAnalyzer.__init__/verify_environment; the real query is loaded per search at run time.
    """
    query: str = Field(default="search index=_internal | head 0")
    config_path: str = Field(
        default="etc/clicker_detection.yaml",
        description="Path to the clicker detection search config, relative to SAQ_HOME.",
    )
    source: str = Field(
        default="splunk",
        description="Top-level key in the clicker config holding this module's searches (e.g. 'splunk', 'logscale').",
    )


class ClickerDetectionAnalysisMixin:
    """Mixin for a source's clicker Analysis class: turns stored event dicts into ClickerEvents."""

    def generate_summary(self):
        # The multi-search clicker flow stores results in details["clicker_events"], not in
        # query_results, so the inherited BaseAPIAnalysis.generate_summary would always fall through
        # to its "(no results or error??)" branch. Summarize this module's own click count instead.
        label = self.query_summary or "URL Clicks"
        source = self.details.get("clicker_source")
        if source:
            label = f"{label} ({source.capitalize()})"
        if self.query_error:
            return f"{label}: ERROR: {self.query_error}"
        events = self.details.get("clicker_events") or []
        if not events:
            return f"{label}: no clicks found"
        count = len(events)
        return f"{label}: {count} click{'' if count == 1 else 's'} found"

    def get_clicker_error(self) -> Optional[str]:
        """The search error for this source's clicker run, if any (for the URL Clicks card).

        Lets the unified view surface 'a search errored' distinctly from 'ran clean, no clicks'.
        """
        return self.query_error or None

    def get_clicker_events(self) -> list[ClickerEvent]:
        events: list[ClickerEvent] = []
        for raw in self.details.get("clicker_events", []) or []:
            events.append(ClickerEvent(
                source=raw.get("source", "unknown"),
                timestamp=parse_clicker_timestamp(raw.get("timestamp")),
                user=raw.get("user"),
                action_type=raw.get("action_type"),
                url=raw.get("url"),
                searched_value=raw.get("searched_value"),
                network_message_id=raw.get("network_message_id"),
                portal_url=raw.get("portal_url"),
            ))
        return events


class ClickerDetectionMixin:
    """Source-agnostic clicker-detection orchestration. Combine with a source API analyzer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False
        self._clicker_config: dict = {}
        self._active_search_def: dict = {}
        self._active_mappings: list[ObservableMapping] = []

    # ---- config loading / watching ----

    def _config_abs_path(self) -> str:
        return resolve_config_path(self.config.config_path)

    def _load_clicker_config(self):
        self._clicker_config = load_clicker_config(self.config.config_path)

    def _ensure_initialized(self):
        if not self._initialized:
            # watch_file loads the config immediately and reloads it on change.
            self.watch_file(self._config_abs_path(), self._load_clicker_config)
            self._initialized = True

    def custom_requirement(self, observable) -> bool:
        # Only run when at least one enabled search applies to this source + observable type, so the
        # module cleanly no-ops when the (default, empty) config has nothing set for this source.
        self._ensure_initialized()
        return bool(get_searches_for(self._clicker_config, self.config.source, observable.type))

    def _search_def_by_name(self, observable_type: str, name: str) -> Optional[dict]:
        for search_name, search_def in get_searches_for(self._clicker_config, self.config.source, observable_type):
            if search_name == name:
                return search_def
        return None

    # ---- source-specific hooks (concrete class must implement) ----

    def _expand_value_clause(self, values: list[str]) -> str:
        raise NotImplementedError

    def _build_search_link(self) -> Optional[str]:
        raise NotImplementedError

    def _reset_job_slot(self, analysis) -> None:
        raise NotImplementedError

    # ---- orchestration ----

    def _prepare_search(self, observable, search_def: dict) -> None:
        """Set up target_query / time ranges / mappings for one search definition."""
        self._active_search_def = search_def

        # <O_VALUE> expands to the source's match clause over all URL permutations (and, when the
        # search sets match_url_encoded, their percent-encoded variants) so one search matches
        # whichever form the user actually clicked.
        values = clicker_match_values(observable, search_def)
        query = search_def["query"].replace("<O_VALUE>", self._expand_value_clause(values))

        self.target_query_base = query
        self.target_query = self.target_query_base
        self.use_index_time = bool(search_def.get("use_index_time", False))

        self.multi_values_base = sorted(set(re.findall(r'(<O_VALUE\d+>)', self.target_query_base)))
        self.multi_values = []

        self.additional_time_ranges = {}
        for token_name, tr in (search_def.get("time_ranges") or {}).items():
            before = tr.get("duration_before") if isinstance(tr, dict) else tr
            after = tr.get("duration_after") if isinstance(tr, dict) else None
            self.additional_time_ranges[token_name] = {
                'duration_before': create_timedelta(before) if before else timedelta(0),
                'duration_after': create_timedelta(after) if after else timedelta(0),
            }

        self._active_mappings = [
            ObservableMapping(**m) for m in (search_def.get("observable_mapping") or [])
        ]

        # token substitution (<O_VALUE> already expanded, <O_TIMESPEC>/<TIMESPEC>, escaping) via the
        # source's API analyzer base.
        super().build_target_query(observable)

        # Node-level "Open in <source>" button (e.g. "Open in Splunk" / "Open in Logscale"). The
        # source's base fill_*_timespec only sets gui_link for <O_TIMESPEC>; clicker searches use
        # <TIMESPEC>, so set it here uniformly for every source from the per-search link hook. With
        # multiple searches the last one wins; the URL Clicks panel's per-row links cover each search.
        try:
            gui_link = self._build_search_link()
        except Exception:
            logging.error("failed to build clicker gui link")
            report_exception()
            gui_link = None
        if gui_link:
            self.analysis.details["gui_link"] = gui_link
            self.analysis.details["gui_link_label"] = f"Open in {self.config.source.capitalize()}"

    def continue_analysis(self, observable, analysis, **kwargs) -> AnalysisExecutionResult:
        """Run every applicable search sequentially, accumulating ClickerEvents.

        Each search is its own async job; we reuse the source's single-job machinery one search at a
        time (resetting the job slot between searches via the hook) and delay the work item until each
        job completes, surviving across resumes via analysis.details.
        """
        self.analysis = analysis

        # first pass: snapshot the ordered plan of applicable searches
        if analysis.details.get("clicker_plan") is None:
            self._ensure_initialized()
            plan = [name for name, _ in get_searches_for(
                self._clicker_config, self.config.source, observable.type)]
            analysis.details["clicker_plan"] = plan
            analysis.details["clicker_index"] = 0
            analysis.details["clicker_source"] = self.config.source
            analysis.details["clicker_events"] = []
            analysis.details["matched_url_count"] = len(get_clicker_match_values(observable))
            analysis.query_start = time.time()

        self._ensure_initialized()
        plan = analysis.details["clicker_plan"]

        while analysis.details["clicker_index"] < len(plan):
            name = plan[analysis.details["clicker_index"]]
            search_def = self._search_def_by_name(observable.type, name)
            if search_def is None:
                # search was removed from the config mid-flight; skip it
                self._reset_job_slot(analysis)
                analysis.details["clicker_index"] += 1
                continue

            self._prepare_search(observable, search_def)

            try:
                results = self.execute_query()
            except AnalysisDelay:
                if analysis.query_elapsed < self.query_timeout:
                    return self.delay_analysis(observable, analysis, seconds=self.async_delay_seconds)
                logging.warning("%s clicker search %s timed out", self.config.source, name)
                results = None
            except Exception as e:
                logging.error("clicker search %s failed: %s", name, e)
                results = None

            if results is not None:
                self.process_query_results(results, analysis, observable)
                self._collect_search_events(analysis, observable, results, search_def, name)

            self._reset_job_slot(analysis)
            analysis.details["clicker_index"] += 1

        return AnalysisExecutionResult.COMPLETED

    def extract_result_observables(self, analysis, result, observable=None, result_time=None) -> None:
        # Same as the base extractor but uses the per-search mappings loaded from the watched clicker
        # config rather than static saq config.
        extracted, _file_contents, _relationships = extract_observables_from_event(
            result, self._active_mappings, result_time,
            value_filter=self.filter_observable_value,
        )
        for ext in extracted:
            analysis.add_observable(ext.observable)
            self.process_field_mapping(analysis, ext.observable, result, ext.matched_field, result_time)

    def _collect_search_events(self, analysis, observable, results, search_def: dict, name: str) -> None:
        """Turn one search's result rows into ClickerEvents and run its on_hit response."""
        rows = results if isinstance(results, list) else []
        event_mapping = search_def.get("event_mapping", {}) or {}
        on_hit = search_def.get("on_hit", {}) or {}
        source_label = f"{self.config.source}:{name}"

        try:
            portal_url = self._build_search_link()
        except Exception:
            logging.error("failed to build clicker search link")
            report_exception()
            portal_url = None

        def _field(row, key):
            field_name = event_mapping.get(key)
            return row.get(field_name) if field_name else None

        new_events = [{
            "source": source_label,
            "portal_url": portal_url,
            "timestamp": _field(row, "timestamp"),
            "user": _field(row, "user"),
            "action_type": _field(row, "action_type"),
            "url": _field(row, "url"),
            "searched_value": observable.value,
            "network_message_id": _field(row, "network_message_id"),
        } for row in rows]
        analysis.details.setdefault("clicker_events", []).extend(new_events)

        # A "hit" means the user actually reached the site. Sources with an allowed/blocked signal use
        # escalate_action_types; sources without one (e.g. proxy/process logs) set escalate_on_any so
        # any returned row counts.
        if on_hit.get("escalate_on_any", False):
            hits = new_events
        else:
            escalate_action_types = set(on_hit.get("escalate_action_types") or [])
            hits = [e for e in new_events if e.get("action_type") in escalate_action_types] if escalate_action_types else []
        if not hits:
            return

        if on_hit.get("add_detection_point", False):
            users = sorted({e["user"] for e in hits if e.get("user")})
            who = ", ".join(users) if users else "unknown user"
            analysis.add_detection_point(
                f"URL clicker identified via {name} ({who})",
                signature_uuid=URL_CLICKER.uuid,
            )

        if on_hit.get("crawl_clicked_url", False):
            self._escalate_crawl(analysis, observable, hits)

    def _escalate_crawl(self, analysis, observable, hits) -> None:
        """url observable: crawl + Phishkit-analyze the observable itself. fqdn observable: surface the
        distinct clicked URLs as url observables for visibility/pivoting, but do NOT add the crawl
        directive — a busy domain could surface many clicked URLs and flood Phishkit."""
        from saq.modules.phishkit import PhishkitAnalysis

        if observable.type != F_URL:
            seen = set()
            for e in hits:
                url = e.get("url")
                if not url or url in seen:
                    continue
                seen.add(url)
                analysis.add_observable_by_spec(F_URL, url)  # extracted for visibility, but NOT crawled
            return

        observable.add_directive(DIRECTIVE_CRAWL)
        # If Phishkit was previously skipped on this URL (because it lacked the crawl directive),
        # clear the "skipped" sentinel so it runs now. If it already ran, leave it.
        if observable.get_analysis(PhishkitAnalysis) is False:
            observable._analysis.pop(MODULE_PATH(PhishkitAnalysis), None)
