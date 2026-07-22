# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import copy
import datetime
import logging
import os
import os.path
import re
from tempfile import mkstemp
from typing import Callable, Optional, TypeVar

import pytz
from pydantic import Field, model_validator

from saq.analysis.observable import Observable
from saq.analysis.root import KEY_PLAYBOOK_URL, KEY_TRANSACTION_ID, RootAnalysis, Submission
from saq.collectors.hunter import Hunt, read_persistence_data, write_persistence_data
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_SIGNATURE_ID, SUMMARY_DETAIL_FORMAT_JINJA, TIMESPEC_TOKEN
from saq.environment import get_temp_dir
from saq.gui.alert import KEY_ALERT_TEMPLATE, KEY_ICON_CONFIGURATION
from saq.logging import DEFAULT_TRANSACTION_ID, get_transaction_id
from saq.observables.generator import create_observable
from saq.observables.mapping import (
    ObservableMapping,
    RelationshipMapping,
)
from saq.query.config import BaseQueryConfig, SummaryDetailConfig, load_query_from_file
from saq.query.template_rendering import (
    UndefinedError,
    render_event_template,
    render_event_template_multi,
    render_event_templates_multi,
)
from saq.query.extraction import (
    compute_dedup_key,
    event_has_required_fields,
    extract_observables_from_event,
    render_sd_content,
    render_sd_header,
)
from saq.query.summary_detail_rendering import render_jinja_template
from saq.collectors.hunter.correlation.schema import (
    CorrelateConfig,
    ConditionConfig,
    StepConfig,
    TransformConfig,
)
from saq.collectors.hunter.correlation.trace import CorrelationTrace
from saq.util import abs_path, create_timedelta, local_time

QUERY_DETAILS_SEARCH_ID = "search_id"
QUERY_DETAILS_SEARCH_LINK = "search_link"
QUERY_DETAILS_QUERY = "query"
QUERY_DETAILS_EVENTS = "events"
QUERY_DETAILS_CORRELATION_TRACE = "correlation_trace"
QUERY_DETAILS_ORIGINAL_EVENTS = "original_events"
QUERY_DETAILS_HUNT_METADATA = "hunt_metadata"
QUERY_DETAILS_HUNT_PROVENANCE = "hunt_provenance"

# Cap for the auto-derived event summary string (header chip text)
_EVENT_SUMMARY_MAX_LEN = 160

# Label used for observables produced by the hunt's initial (pre-correlation) query.
HUNT_PROVENANCE_INITIAL_LABEL = "Initial Query"


def collect_correlate_steps(logic_steps: list[StepConfig]) -> list[tuple[Optional[str], str]]:
    """Walk a correlation logic tree and return, in document order, one
    (description, property_name) pair per transform step that writes a named
    property onto the event.

    Transforms can be nested inside conditional steps, so this recurses through
    ConditionConfig.execute / else_ branches. The returned order is what the
    provenance step indices (1..N; 0 is the initial query) are assigned from.
    """
    collected: list[tuple[Optional[str], str]] = []

    def _walk(steps: list[StepConfig]) -> None:
        for step_config in steps:
            inner = step_config.step
            if isinstance(inner, TransformConfig):
                if inner.method == "property" and inner.property_name:
                    collected.append((step_config.description, inner.property_name))
            elif isinstance(inner, ConditionConfig):
                _walk(inner.execute)
                if inner.else_:
                    _walk(inner.else_)

    _walk(logic_steps)
    return collected

T = TypeVar("T")

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)


class QueryHuntConfig(HuntConfig, BaseQueryConfig):
    model_config = {"extra": "forbid"}

    time_range: Optional[str] = Field(
        default=None,
        description="The time range to query over. Can also be specified via time_ranges.TIMESPEC."
    )
    max_time_range: Optional[str] = Field(default=None, description="The maximum time range to query over.")
    full_coverage: bool = Field(..., description="Whether to run the query over the full coverage of the time range.")
    use_index_time: bool = Field(..., description="Whether to use the index time as the time of the query.")
    offset: Optional[str] = Field(default=None, description="An optional offset to run the query at.")
    group_by: Optional[str] = Field(default=None, description="The field to group the results by.")
    description_field: Optional[str] = Field(default=None, description="The event field to use for the alert description suffix. If not set, the group_by field value is used.")
    query_file_path: Optional[str] = Field(alias="search", default=None, description="The path to the search query file.")
    max_result_count: Optional[int] = Field(default_factory=lambda: get_config().query_hunter.max_result_count, description="The maximum number of results to return.")
    query_timeout: Optional[str] = Field(default_factory=lambda: get_config().query_hunter.query_timeout, description="The timeout for the query (in HH:MM:SS format).")
    auto_append: str = Field(default="", description="The string to append to the query after the time spec. By default this is an empty string.")
    dedup_key: Optional[str] = Field(default=None, description="Optional Jinja2 template for deduplication. When set, submissions get a key enabling the DuplicateSubmissionFilter to suppress duplicates.")
    correlate: Optional[CorrelateConfig] = Field(default=None, description="Optional correlation configuration for advanced event processing.")

    @model_validator(mode='after')
    def validate_time_range_source(self):
        """Ensure time_range is available from either time_range or time_ranges.TIMESPEC."""
        has_time_range = self.time_range is not None
        has_timespec_in_time_ranges = (
            self.time_ranges is not None
            and TIMESPEC_TOKEN in self.time_ranges
            and self.time_ranges[TIMESPEC_TOKEN].duration_before is not None
        )
        if not has_time_range and not has_timespec_in_time_ranges:
            raise ValueError(
                "Either 'time_range' or 'time_ranges' with a TIMESPEC entry must be specified"
            )
        return self

class QueryHunt(Hunt):
    """Abstract class that represents a hunt against a search system that queries data over a time range."""

    config: QueryHuntConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # allows hyperlink to search results
        self.search_id: Optional[str] = None
        # might need to url_encode the link instead, store that here
        self.search_link: Optional[str] = None

        # when the query is loaded from a file this trackes the last time the file was modified
        self.query_last_mtime = None

        # the query loaded from file (if specified)
        self.loaded_query: Optional[str] = None

        # the query with all runtime tokens (e.g. TIMESPEC) resolved to actual values
        self.resolved_query: Optional[str] = None

        # the unmutated event list captured before correlation runs
        # (only populated when self.config.correlate is set)
        self.original_query_results: Optional[list[dict]] = None

    @property
    def time_range(self) -> Optional[datetime.timedelta]:
        # Prefer time_ranges.TIMESPEC when time_ranges is configured, since time_range
        # may come from an included config file's default rather than the hunt itself.
        if self.config.time_ranges and TIMESPEC_TOKEN in self.config.time_ranges:
            return create_timedelta(self.config.time_ranges[TIMESPEC_TOKEN].duration_before)
        if self.config.time_range is not None:
            return create_timedelta(self.config.time_range)
        return None

    @property
    def max_time_range(self) -> Optional[datetime.timedelta]:
        if self.config.max_time_range:
            return create_timedelta(self.config.max_time_range)
        else:
            return None

    @property
    def full_coverage(self) -> bool:
        return self.config.full_coverage

    @property
    def use_index_time(self) -> bool:
        return self.config.use_index_time

    @property
    def offset(self) -> Optional[datetime.timedelta]:
        if self.config.offset:
            return create_timedelta(self.config.offset)
        else:
            return None

    @property
    def group_by(self) -> Optional[str]:
        return self.config.group_by

    @property
    def description_field(self) -> Optional[str]:
        return self.config.description_field

    @property
    def dedup_key(self) -> Optional[str]:
        return self.config.dedup_key

    @property
    def query_file_path(self) -> Optional[str]:
        return self.config.query_file_path

    @property
    def query(self) -> str:
        # query set inline in the config?
        if self.config.query is not None:
            result = self.config.query
        elif self.loaded_query is not None:
            result = self.loaded_query
        elif self.query_file_path is not None:
            self.loaded_query = self.load_query_from_file(self.query_file_path)
            result = self.loaded_query
        else:
            raise ValueError(f"no query specified for hunt {self}")

        if self.config.query_prefix:
            result = self.config.query_prefix + "\n" + result
        if self.config.query_suffix:
            result = result.rstrip() + "\n" + self.config.query_suffix

        return result

    @property
    def observable_mapping(self) -> list[ObservableMapping]:
        return self.config.observable_mapping

    @property
    def max_result_count(self) -> Optional[int]:
        return self.config.max_result_count

    @property
    def query_timeout(self) -> Optional[datetime.timedelta]:
        if self.config.query_timeout:
            return create_timedelta(self.config.query_timeout)
        else:
            return None

    def execute_query(self, start_time: datetime.datetime, end_time: datetime.datetime, *args, **kwargs) -> Optional[list[Submission]]:
        """Called to execute the query over the time period given by the start_time and end_time parameters.
           Returns a list of zero or more Submission objects."""
        raise NotImplementedError()

    @property
    def last_end_time(self) -> Optional[datetime.datetime]:
        """The last end_time value we used as the ending point of our search range.
           Note that this is different than the last_execute_time, which was the last time we executed the search."""
        # if we don't already have this value then load it from the sqlite db
        if hasattr(self, '_last_end_time'):
            return self._last_end_time
        else:
            self._last_end_time = read_persistence_data(self.type, self.name, 'last_end_time')
            if self._last_end_time is not None and self._last_end_time.tzinfo is None:
                self._last_end_time = pytz.utc.localize(self._last_end_time)
            return self._last_end_time

    @last_end_time.setter
    def last_end_time(self, value: datetime.datetime):
        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        value = value.astimezone(pytz.utc)

        self._last_end_time = value
        write_persistence_data(self.type, self.name, 'last_end_time', value)

    @property
    def start_time(self) -> datetime.datetime:
        """Returns the starting time of this query based on the last time we searched."""
        # if this hunt is configured for full coverage, then the starting time for the search
        # will be equal to the ending time of the last executed search
        if self.full_coverage:
            # have we not executed this search yet?
            if self.last_end_time is None:
                return local_time() - self.time_range
            else:
                return self.last_end_time
        else:
            # if we're not doing full coverage then we don't worry about the last end time
            return local_time() - self.time_range

    @property
    def end_time(self) -> datetime.datetime:
        """Returns the ending time of this query based on the start time and the hunt configuration."""
        now = local_time()
        if self.full_coverage:
            # have we not executed this search yet?
            if self.last_end_time is None:
                return now
            else:
                normal_end = self.last_end_time + self.time_range

                # if the normal end would be in the future, cap at now
                if normal_end >= now:
                    return now

                # we are behind; advance as far as possible without exceeding max_time_range
                if self.max_time_range is not None:
                    max_end = self.last_end_time + self.max_time_range
                    # do not search past now or past the maximum allowed range
                    return now if now < max_end else max_end

                # no max_time_range configured; catch up fully to now
                return now
        else:
            # if we're not doing full coverage then we don't worry about the last end time
            return now

    @property
    def ready(self) -> bool:
        """Returns True if the hunt is ready to execute, False otherwise."""
        # if it's already running then it's not ready to run again
        if self.running:
            return False

        # if we haven't executed it yet then it's ready to go
        if self.last_executed_time is None:
            return True

        # if the end of the last search was less than the time the search actually started
        # then we're trying to play catchup and we need to execute again immediately
        #if self.last_end_time is not None and local_time() - self.last_end_time >= self.time_range:
            #logging.warning("full coverage hunt %s is trying to catch up last execution time %s last end time %s",
                #self, self.last_executed_time, self.last_end_time)
            #return True

        logging.debug(f"hunt {self} local time {local_time()} last execution time {self.last_executed_time} next execution time {self.next_execution_time}")
        return local_time() >= self.next_execution_time

    def load_query_from_file(self, path: str) -> str:
        return load_query_from_file(path)
    
    def load_hunt_config(self, path: str) -> tuple[QueryHuntConfig, set[str]]:
        return load_from_yaml(path, QueryHuntConfig)

    def load_hunt(self, path: str) -> QueryHuntConfig:
        super().load_hunt(path)

        if self.config.query_file_path:
            self.loaded_query = self.load_query_from_file(self.config.query_file_path)

        return self.config    

    @property
    def is_modified(self) -> bool:
        return self.yaml_is_modified or self.query_is_modified

    @property
    def query_is_modified(self) -> bool:
        """Returns True if this query was loaded from file and that file has been modified since we loaded it."""
        if self.query_file_path is None:
            return False

        try:
            return self.query_last_mtime != os.path.getmtime(abs_path(self.query_file_path))
        except FileNotFoundError:
            return True
        except Exception as e:
            logging.error(f"unable to check last modified time of {self.query_file_path}: {e}")
            return False

    # start_time and end_time are optionally arguments
    # to allow manual command line hunting (for research purposes)
    def execute(self, start_time=None, end_time=None, *args, **kwargs):

        offset_start_time = target_start_time = start_time if start_time is not None else self.start_time
        offset_end_time = target_end_time = end_time if end_time is not None else self.end_time
        query_result = None

        try:
            # the optional offset allows hunts to run at some offset of time
            if not self.manual_hunt and self.offset:
                offset_start_time -= self.offset
                offset_end_time -= self.offset

            query_result = self.execute_query(offset_start_time, offset_end_time, *args, **kwargs)

            # record the actual query window so correlation (process_query_results)
            # can anchor a stream transform's relative time_range to it
            self._correlation_hunt_start_time = offset_start_time
            self._correlation_hunt_end_time = offset_end_time

            return self.process_query_results(query_result, **kwargs)

        finally:
            # if we're not manually hunting then record the last end time
            if not self.manual_hunt and query_result is not None:
                self.last_end_time = target_end_time

    def formatted_query(self):
        """Formats query to a readable string with the timestamps used at runtime properly substituted.
           Return None if one cannot be extracted."""
        return None

    def extract_event_timestamp(self, query_result: dict) -> Optional[datetime.datetime]:
        """Given a JSON object that represents a single row/entry from a query result, return a datetime.datetime
           object that represents the actual time of the event.
           Return None if one cannot be extracted."""
        return None

    def wrap_event(self, event):
        """Subclasses can override this function to return an event object with additional capabilities.
        By default this returns the event that is passed in."""
        return event

    def _render_name(self, event: dict) -> str:
        """Renders self.name as a Jinja2 template against the given event.

        Falls back to the raw config name when the template has no Jinja markers
        (fast path) or when rendering fails."""
        raw_name = self.name
        if "{{" not in raw_name and "{%" not in raw_name:
            return raw_name

        rendered = render_jinja_template(raw_name, event, strict=False)
        if rendered is None:
            logging.warning(
                "falling back to raw name for hunt uuid=%s name=%s due to template render failure",
                self.uuid, raw_name,
            )
            return raw_name
        return rendered

    def create_root_analysis(self, event: dict) -> RootAnalysis:
        import uuid as uuidlib
        root_uuid = str(uuidlib.uuid4())
        extensions = {}
        if self.playbook_url:
            try:
                url_value = render_event_template(self.playbook_url, event, strict=True)
            except UndefinedError:
                url_value = None
            if url_value:
                extensions[KEY_PLAYBOOK_URL] = url_value

        if self.icon_configuration:
            extensions[KEY_ICON_CONFIGURATION] = self.icon_configuration.model_dump()

        if self.alert_template:
            extensions[KEY_ALERT_TEMPLATE] = self.alert_template

        # record the transaction id of the hunt execution that produced this root
        # the default sentinel means we're running outside of one, in which case
        # there is nothing useful to correlate on
        current_transaction_id = get_transaction_id()
        if current_transaction_id and current_transaction_id != DEFAULT_TRANSACTION_ID:
            extensions[KEY_TRANSACTION_ID] = current_transaction_id

        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=os.path.join(get_temp_dir(), root_uuid),
            desc=self._render_name(event),
            instructions=self.description,
            analysis_mode=self.analysis_mode,
            tool=f'hunter-{self.type}',
            tool_instance=self.tool_instance,
            alert_type=self.alert_type,
            details={
                QUERY_DETAILS_SEARCH_ID: self.search_id if self.search_id else None,
                QUERY_DETAILS_SEARCH_LINK: self.search_link if self.search_link else None,
                QUERY_DETAILS_QUERY: self.resolved_query or self.formatted_query(),
                QUERY_DETAILS_EVENTS: [],
            },
            event_time=None,
            queue=self.queue,
            extensions=extensions)

        root.initialize_storage()

        # only hunts running in the default correlation mode alert on submission; hunts
        # in other analysis modes are not alerts until analysis adds a detection point,
        # so attaching one here would incorrectly promote them to alerts immediately
        if self.analysis_mode == ANALYSIS_MODE_CORRELATION:
            # attribute this hunt-originated alert to the hunt signature (the hunt's uuid)
            # and its tracked repo commit (signature_version). passed explicitly so it is
            # not resolved to the built-in ACE_VERSION default.
            root.add_detection_point(
                "hunt {} ({}) matched".format(self.name, self.type),
                signature_uuid=self.uuid,
                signature_version=self.signature_version)

        for tag in self.tags:
            try:
                tag_values = render_event_template_multi(tag, event, strict=True)
            except UndefinedError:
                continue
            for tag_value in tag_values:
                if tag_value:
                    root.add_tag(tag_value)

        if self.config.correlate is not None:
            root.add_tag('correlated')

        for pivot_link in self.pivot_links:
            try:
                rows = render_event_templates_multi(
                    [pivot_link["url"], pivot_link["text"]], event, strict=True,
                )
            except UndefinedError:
                continue
            for url_value, text_value in rows:
                if not url_value or not text_value:
                    continue
                root.add_pivot_link(url_value, pivot_link.get("icon", None), text_value)

        return root

    def _process_summary_details(self, query_results: list[dict], event_submission_map: dict[int, list[Submission]]):
        """Process all summary_details definitions against the query results."""
        for sd_config in self.config.summary_details:
            if sd_config.grouped:
                self._process_grouped_summary_detail(sd_config, query_results, event_submission_map)
            else:
                self._process_ungrouped_summary_detail(sd_config, query_results, event_submission_map)

    def _process_ungrouped_summary_detail(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Add one SummaryDetail per event per submission for this definition."""
        count: dict[int, int] = {}  # submission id -> count
        seen_keys: dict[int, set[tuple]] = {}  # submission id -> set of dedup keys

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue

            # required fields check
            if sd_config.required_fields is not None:
                if not event_has_required_fields(event, sd_config.required_fields):
                    continue

            # render content
            content = render_sd_content(sd_config, event)
            if content is None:
                continue

            # render header
            header_ok, header = render_sd_header(sd_config, event)
            if not header_ok:
                continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)

                # per-submission dedup check
                if sd_config.dedup_fields is not None:
                    if sub_id not in seen_keys:
                        seen_keys[sub_id] = set()
                    dedup_key = compute_dedup_key(event, sd_config.dedup_fields)
                    if dedup_key in seen_keys[sub_id]:
                        continue
                    seen_keys[sub_id].add(dedup_key)

                current_count = count.get(sub_id, 0)
                if current_count >= sd_config.limit:
                    if current_count == sd_config.limit:
                        logging.warning(
                            "summary detail limit (%s) reached for definition content=%s in hunt %s",
                            sd_config.limit, sd_config.content, self.name,
                        )
                        count[sub_id] = current_count + 1
                    continue
                submission.root.add_summary_detail(header=header, content=content, format=sd_config.format)
                count[sub_id] = current_count + 1

    def _collect_grouped_events(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
        transform_event: Callable[[dict], Optional[T]],
    ) -> tuple[dict[int, list[T]], dict[int, Submission], dict[int, dict]]:
        """Shared collection loop for grouped summary details.

        Iterates query results, applies required_fields filtering, per-submission
        dedup, and limit enforcement.  The ``transform_event`` callback converts
        each qualifying event into the item to collect (or returns ``None`` to skip).

        Returns ``(collected, sub_lookup, first_events)`` where *collected* maps
        submission id to the list of transformed items, *sub_lookup* maps
        submission id to the :class:`Submission` object, and *first_events* maps
        submission id to the first contributing event dict (for header resolution).
        """
        collected: dict[int, list[T]] = {}
        sub_lookup: dict[int, Submission] = {}
        first_events: dict[int, dict] = {}
        seen_keys: dict[int, set[tuple]] = {}
        limit_warned: dict[int, bool] = {}

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue
            if sd_config.required_fields is not None:
                if not event_has_required_fields(event, sd_config.required_fields):
                    continue

            item = transform_event(event)
            if item is None:
                continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)
                sub_lookup[sub_id] = submission
                if sub_id not in collected:
                    collected[sub_id] = []
                    seen_keys[sub_id] = set()
                    limit_warned[sub_id] = False

                # dedup check
                if sd_config.dedup_fields is not None:
                    dedup_key = compute_dedup_key(event, sd_config.dedup_fields)
                    if dedup_key in seen_keys[sub_id]:
                        continue
                    seen_keys[sub_id].add(dedup_key)

                # per-submission limit enforcement
                if len(collected[sub_id]) >= sd_config.limit:
                    if not limit_warned[sub_id]:
                        logging.warning(
                            "summary detail limit (%s) reached for grouped definition content=%s in hunt %s",
                            sd_config.limit, sd_config.content, self.name,
                        )
                        limit_warned[sub_id] = True
                    continue

                collected[sub_id].append(item)
                if sub_id not in first_events:
                    first_events[sub_id] = event

        return collected, sub_lookup, first_events

    def _resolve_header(self, sd_config: SummaryDetailConfig, first_event: dict) -> Optional[str]:
        """Resolve a summary detail header from the first contributing event."""
        if sd_config.header is None:
            return None
        header_ok, header = render_sd_header(sd_config, first_event)
        return header if header_ok else None

    def _process_grouped_summary_detail(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Collect content from all events and add one combined SummaryDetail per submission."""
        if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
            self._process_grouped_summary_detail_jinja(sd_config, query_results, event_submission_map)
        else:
            self._process_grouped_summary_detail_default(sd_config, query_results, event_submission_map)

    def _process_grouped_summary_detail_jinja(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Jinja grouped mode: collect qualifying events per submission, render once per submission."""
        collected, sub_lookup, first_events = self._collect_grouped_events(
            sd_config, query_results, event_submission_map,
            transform_event=lambda e: e,
        )

        for sub_id, events in collected.items():
            if not events:
                continue

            # A missing field under strict mode raises UndefinedError. Mirror every other
            # summary-detail path and skip just this block (rather than killing the hunt).
            try:
                content = render_jinja_template(
                    sd_config.content,
                    {"events": events},
                    strict=(sd_config.required_fields is None),
                )
            except UndefinedError:
                logging.error(
                    "grouped jinja summary detail skipped (missing field) for content=%s in hunt %s",
                    sd_config.content, self.name, exc_info=True,
                )
                continue

            if content is None or not content.strip():
                continue

            header = self._resolve_header(sd_config, first_events[sub_id])
            sub_lookup[sub_id].root.add_summary_detail(
                header=header, content=content, format=sd_config.format,
            )

    def _process_grouped_summary_detail_default(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Non-Jinja grouped mode: per-event render + join."""
        collected, sub_lookup, first_events = self._collect_grouped_events(
            sd_config, query_results, event_submission_map,
            transform_event=lambda e: render_sd_content(sd_config, e),
        )

        for sub_id, lines in collected.items():
            if not lines:
                continue
            header = self._resolve_header(sd_config, first_events[sub_id])
            sub_lookup[sub_id].root.add_summary_detail(
                header=header, content="\n".join(lines), format=sd_config.format,
            )

    def _extract_event_summary(self, event: dict, observables: list) -> Optional[str]:
        """Build a short, human-readable one-line summary for a single event.

        Used in the correlation trace UI to label collapsed event rows so analysts
        can scan multiple events without expanding each one. Pulls from the hunt's
        existing config (description_field, group_by), from observables that were
        already extracted for this event, and the per-event timestamp via
        extract_event_timestamp — no new YAML knobs.

        Dedup: a hunt's description_field often already contains the user / email
        / msg_id that group_by and observables would surface separately. Skip a
        candidate if it's a substring of any existing part (case-insensitive);
        if a candidate fully supersedes an existing part, replace the shorter one
        with the more informative longer one. This keeps the header line useful
        for telling sibling events apart instead of repeating the shared value.

        Time goes last so an analyst always sees it as the trailing field — this
        is the difference-of-last-resort for siblings whose other fields all match
        (e.g. multiple records emitted seconds apart for the same user).
        """
        parts: list[str] = []

        def _add(value):
            if value is None:
                return
            if isinstance(value, list):
                value = value[0] if value else None
                if value is None:
                    return
            text = str(value).strip()
            if not text:
                return
            text_cf = text.casefold()
            indices_to_remove = []
            for i, existing in enumerate(parts):
                existing_cf = existing.casefold()
                if text_cf == existing_cf or text_cf in existing_cf:
                    return
                if existing_cf in text_cf:
                    indices_to_remove.append(i)
            for i in reversed(indices_to_remove):
                parts.pop(i)
            parts.append(text)

        if self.description_field and self.description_field in event:
            _add(event[self.description_field])
        if self.group_by and self.group_by != "ALL" and self.group_by in event:
            _add(event[self.group_by])

        for obs in observables:
            if getattr(obs, "type", None) == F_SIGNATURE_ID:
                continue
            _add(getattr(obs, "value", None))
            if len(parts) >= 4:
                break

        try:
            evt_time = self.extract_event_timestamp(event)
        except Exception:
            evt_time = None
        if evt_time is not None:
            try:
                _add(evt_time.strftime("%H:%M:%S"))
            except Exception:
                pass

        if not parts:
            return None

        summary = " · ".join(parts)
        if len(summary) > _EVENT_SUMMARY_MAX_LEN:
            summary = summary[: _EVENT_SUMMARY_MAX_LEN - 1] + "…"
        return summary

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        # Run correlation if configured
        event_action_overrides: dict[int, any] = {}

        # snapshot the raw events before any processing (correlation mutates them in place;
        # grouping/wrapping happens below) so the validator can report exactly what the data
        # source returned. captured for correlate hunts (always) and manual/validate runs (so
        # non-correlate hunts get a faithful top-level original_events too); skipped for normal
        # production runs that never read it.
        if self.config.correlate is not None or self.manual_hunt:
            self.original_query_results = copy.deepcopy(query_results)

        if self.config.correlate is not None:
            from saq.collectors.hunter.correlation.engine import CorrelationEngine
            engine = CorrelationEngine(
                correlate_config=self.config.correlate,
                predefined_commands=getattr(self.config, "_predefined_commands", []),
                hunt_start_time=getattr(self, "_correlation_hunt_start_time", local_time()),
                hunt_end_time=getattr(self, "_correlation_hunt_end_time", local_time()),
                max_result_count=self.max_result_count,
                hunt_source_type=self.type,
                correlate_replay=getattr(self, "_correlate_replay_results", None),
                hunt_name=self.name,
                hunt_uuid=self.uuid,
            )
            result = engine.execute(query_results)
            self.correlation_trace = result.trace
            # captured rendered query results, exposed so the validator can save them
            # for fast offline replay (see validate.py --save-correlate-results)
            self.correlate_query_results = {"version": 1, "queries": result.captured_queries}

            # emit one INFO log line per trace entry so detection engineers can monitor
            # filtering and performance of correlated hunts in real time
            if self.correlation_trace is not None:
                for event_trace in self.correlation_trace.event_traces:
                    logging.info(
                        f"correlation trace hunt={self.name} type={self.type} uuid={self.uuid} "
                        f"event_index={event_trace.event_index} outcome={event_trace.outcome} "
                        f"steps={len(event_trace.steps)}"
                    )
                for stream_event in self.correlation_trace.stream_events:
                    logging.info(
                        f"correlation stream event hunt={self.name} type={self.type} uuid={self.uuid} "
                        f"event_type={stream_event.event_type} at_event_index={stream_event.at_event_index} "
                        f"detail={stream_event.detail}"
                    )

            if result.discarded:
                return []
            query_results = result.events
            event_action_overrides = result.event_actions
            alert_event_origin_indices = result.alert_event_origin_indices
        else:
            alert_event_origin_indices = []

        submissions: list[Submission] = [] # of Submission objects

        def _create_submission(event: dict):
            return Submission(self.create_root_analysis(event))

        def _compute_dedup_key(event: dict) -> Optional[str]:
            if not self.dedup_key:
                return None
            try:
                value = render_event_template(self.dedup_key, event, strict=True)
            except UndefinedError:
                return None
            if not value:
                return None
            return f"{self.uuid}:{value}"

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # this is used to keep track of which observables need to have relationship mapped
        relationship_tracking: dict[Observable, list[RelationshipMapping]] = {}

        # maps event index to the submission(s) it belongs to (for summary detail processing)
        event_submission_map: dict[int, list[Submission]] = {}

        # captures the deduped observable list for each post-correlation event index so
        # the correlation-trace UI can render a per-event summary line without re-extracting.
        per_event_observables: dict[int, list] = {}

        # Step-provenance scaffolding for correlated hunts: which hunt step produced
        # which observable. Step 0 is the initial query; steps 1..N are the correlation
        # logic's named-property transforms in document order. We classify each extracted
        # observable by the first path segment of its matched_field (e.g.
        # "correlate_ip_mscs_logs.0.myUserAgent" -> "correlate_ip_mscs_logs" -> the step
        # that writes that property; anything else -> the initial query). Keyed by
        # (type, value) because add_observable() dedups on those and keeps the first
        # instance's uuid, so uuid isn't stable until observables are added to a root.
        ordered_provenance_steps: list[dict] = []
        correlate_property_to_step: dict[str, int] = {}
        provenance_by_value: dict[tuple[str, str], set[int]] = {}
        if self.config.correlate is not None:
            ordered_provenance_steps.append(
                {"index": 0, "label": HUNT_PROVENANCE_INITIAL_LABEL, "property_name": None}
            )
            for i, (description, property_name) in enumerate(
                collect_correlate_steps(self.config.correlate.logic), start=1
            ):
                ordered_provenance_steps.append({
                    "index": i,
                    "label": description or f"Correlated step {i}",
                    "property_name": property_name,
                })
                correlate_property_to_step[property_name] = i

        # map results to observables
        for event_index, event in enumerate(query_results):
            event_time = self.extract_event_timestamp(event) or local_time()
            event = self.wrap_event(event)

            # use shared extraction pipeline
            extracted, file_contents, event_relationships = extract_observables_from_event(
                event, self.observable_mapping, event_time,
                global_ignored_patterns=self.config._ignored_value_patterns if self.config.ignored_values else None,
            )

            # record step provenance per extracted observable before dedup collapses them
            if self.config.correlate is not None:
                for ext in extracted:
                    first_segment = ext.matched_field.split(".")[0]
                    step_index = correlate_property_to_step.get(first_segment, 0)
                    provenance_by_value.setdefault(
                        (ext.observable.type, ext.observable.value), set()
                    ).add(step_index)

            # deduplicate observables (shared extraction may return duplicates across mappings)
            observables: list[Observable] = []
            for ext in extracted:
                if ext.observable not in observables:
                    observables.append(ext.observable)

            per_event_observables[event_index] = observables

            # merge relationship tracking
            relationship_tracking.update(event_relationships)

            signature_id_observable = create_observable(F_SIGNATURE_ID, self.uuid)

            if signature_id_observable is not None:
                signature_id_observable.display_value = self._render_name(event)
                observables.append(signature_id_observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission(event)
                submission.key = _compute_dedup_key(event)
                submission.root.event_time = event_time

                # Apply correlation overrides
                if event_index in event_action_overrides:
                    override = event_action_overrides[event_index]
                    if override.queue_override:
                        submission.root.queue = override.queue_override
                    if override.analysis_mode_override:
                        submission.root.analysis_mode = override.analysis_mode_override

                if self.description_field is not None and self.description_field in event:
                    description_value = event[self.description_field]
                    if isinstance(description_value, list):
                        description_value = description_value[0] if description_value else ""
                    if description_value:
                        submission.root.description += f': {description_value}'

                for observable in observables:
                    submission.root.add_observable(observable)

                for file_content in file_contents:
                    fd, temp_file_path = mkstemp(dir=get_temp_dir())
                    os.write(fd, file_content.content)
                    os.close(fd)

                    file_obs = submission.root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True, volatile=file_content.volatile)
                    if file_obs:
                        for directive in file_content.directives:
                            file_obs.add_directive(directive)
                        for tag in file_content.tags:
                            file_obs.add_tag(tag)
                        if file_content.display_type is not None:
                            file_obs.display_type = file_content.display_type
                    # note: display_value is not set for FileObservable as it's read-only

                submission.root.details[QUERY_DETAILS_EVENTS].append(event)
                submissions.append(submission)
                event_submission_map[event_index] = [submission]

            # if we are grouping then we start pulling all the data into groups
            else:
                # if we're grouping all results together then there's only a single group
                grouping_targets = ["ALL" if self.group_by == "ALL" else event[self.group_by]]
                if self.group_by != "ALL":
                    if isinstance(event[self.group_by], list):
                        grouping_targets = event[self.group_by]

                for grouping_target in grouping_targets:
                    if grouping_target not in event_grouping:
                        event_grouping[grouping_target] = _create_submission(event)
                        event_grouping[grouping_target].key = _compute_dedup_key(event)
                        # associate the submission with its group value so the manager can record
                        # per-group last_alert_time without re-deriving the grouping
                        event_grouping[grouping_target].group_value = grouping_target
                        if grouping_target != "ALL":
                            if self.description_field is not None and self.description_field in event:
                                description_value = event[self.description_field]
                                if isinstance(description_value, list):
                                    description_value = description_value[0] if description_value else grouping_target
                                event_grouping[grouping_target].root.description += f': {description_value}'
                            else:
                                event_grouping[grouping_target].root.description += f': {grouping_target}'
                        submissions.append(event_grouping[grouping_target])

                    for observable in observables:
                        if observable not in event_grouping[grouping_target].root.observables:
                            event_grouping[grouping_target].root.add_observable(observable)

                    for file_content in file_contents:
                        fd, temp_file_path = mkstemp(dir=get_temp_dir())
                        os.write(fd, file_content.content)
                        os.close(fd)

                        file_obs = event_grouping[grouping_target].root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True, volatile=file_content.volatile)
                        if file_obs:
                            for directive in file_content.directives:
                                file_obs.add_directive(directive)
                            for tag in file_content.tags:
                                file_obs.add_tag(tag)
                            if file_content.display_type is not None:
                                file_obs.display_type = file_content.display_type
                        # note: display_value is not set for FileObservable as it's read-only

                    event_grouping[grouping_target].root.details[QUERY_DETAILS_EVENTS].append(event)
                    event_submission_map.setdefault(event_index, []).append(event_grouping[grouping_target])

                    # for grouped events, the overall event time is the earliest event time in the group
                    # this won't really matter if the observables are temporal
                    if event_grouping[grouping_target].root.event_time is None:
                        event_grouping[grouping_target].root.event_time = event_time
                    elif event_time < event_grouping[grouping_target].root.event_time:
                        event_grouping[grouping_target].root.event_time = event_time

            # apply relationships to the observables
            for submission in submissions:
                for observable in submission.root.observables:
                    if observable in relationship_tracking:
                        for relationship_mapping in relationship_tracking[observable]:
                            try:
                                target_values = render_event_template_multi(
                                    relationship_mapping.target.value, event, strict=True,
                                )
                            except UndefinedError:
                                logging.warning(
                                    f"skipping relationship in hunt {self.name}: target value "
                                    f"'{relationship_mapping.target.value}' references field "
                                    f"missing from event"
                                )
                                continue
                            for potential_target_value in target_values:
                                if not potential_target_value:
                                    continue
                                target_observable = submission.root.get_observable_by_spec(relationship_mapping.target.type, potential_target_value)
                                if target_observable is not None:
                                    observable.add_relationship(relationship_mapping.type, target_observable)

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.root.description += f' ({len(submission.root.details.get(QUERY_DETAILS_EVENTS, []))} event{"" if len(submission.root.details.get(QUERY_DETAILS_EVENTS, [])) == 1 else "s"})'

        self._process_summary_details(query_results, event_submission_map)

        # Attach hunt_metadata to every submission so the trace UI can render hunt context
        # (name, group_by/group_value for the grouping banner) without inferring it from data.
        for submission in submissions:
            # Render the hunt name (which may itself be a Jinja template) against the
            # submission's first event — the same event that produced its rendered
            # description (see create_root_analysis) — so the Correlation Trace UI shows
            # the evaluated name rather than the raw template.
            events = submission.root.details.get(QUERY_DETAILS_EVENTS) or []
            rendered_name = self._render_name(events[0]) if events else self.name
            submission.root.details[QUERY_DETAILS_HUNT_METADATA] = {
                "name": rendered_name,
                "uuid": self.uuid,
                "type": self.type,
                "group_by": self.group_by,
                "group_value": getattr(submission, "group_value", None),
                "description_field": self.description_field,
                "frequency": str(self.frequency) if self.frequency else None,
            }

        # Attach correlation trace to each submission's details for alert persistence.
        # Each alert should see the EventTraces that contributed to it (origins) plus any
        # filter/stop EventTraces from the same group_by value (extra_origins) — so an
        # analyst sees the rejection context for "this user / this msg_id / etc." without
        # importing unrelated events from sibling alerts in the same run. Stream events
        # stay shared (timeouts/resets are hunt-run-level context).
        if hasattr(self, "correlation_trace") and self.correlation_trace is not None:
            submission_origin_indices: dict[int, set[int]] = {}
            # Per-submission map from a pre-correlation event_index to that event's position in
            # the submission's details["events"] list. Lets the trace UI surface the full
            # structured property value (untruncated) by indexing back into details["events"].
            events_pos_by_origin: dict[int, dict[int, int]] = {}
            for post_correlation_index in sorted(event_submission_map):
                if post_correlation_index >= len(alert_event_origin_indices):
                    continue
                origin_index = alert_event_origin_indices[post_correlation_index]
                for submission in event_submission_map[post_correlation_index]:
                    submission_origin_indices.setdefault(id(submission), set()).add(origin_index)
                    sub_pos_map = events_pos_by_origin.setdefault(id(submission), {})
                    if origin_index not in sub_pos_map:
                        sub_pos_map[origin_index] = len(sub_pos_map)

            # reverse mapping from pre-correlation event_index (used by EventTrace) back to
            # the post-correlation index (used by query_results / per_event_observables).
            origin_to_post = {origin: post for post, origin in enumerate(alert_event_origin_indices)}

            # Build extra_origins for grouped hunts: filter/stop event_traces whose
            # original event shares the alert's group_by value get included so analysts
            # can see what was rejected for the same key. Ungrouped hunts get nothing
            # extra (no natural mapping); discard kills the run; alert/error/timeout are
            # already covered by `origins` since the engine routes them onto the alert.
            extra_origins_by_sub: dict[int, set[int]] = {}
            if (
                self.original_query_results is not None
                and self.group_by is not None
            ):
                if self.group_by == "ALL":
                    for et in self.correlation_trace.event_traces:
                        if et.outcome not in ("filter", "stop"):
                            continue
                        if et.event_index >= len(self.original_query_results):
                            continue
                        for submission in submissions:
                            extra_origins_by_sub.setdefault(id(submission), set()).add(et.event_index)
                else:
                    submissions_by_group: dict[any, list[Submission]] = {}
                    for sub in submissions:
                        gv = getattr(sub, "group_value", None)
                        if gv is not None:
                            submissions_by_group.setdefault(gv, []).append(sub)
                    for et in self.correlation_trace.event_traces:
                        if et.outcome not in ("filter", "stop"):
                            continue
                        if et.event_index >= len(self.original_query_results):
                            continue
                        orig = self.original_query_results[et.event_index]
                        if not isinstance(orig, dict):
                            continue
                        gv_raw = orig.get(self.group_by)
                        if gv_raw is None:
                            continue
                        gvs = gv_raw if isinstance(gv_raw, list) else [gv_raw]
                        for gv in gvs:
                            for sub in submissions_by_group.get(gv, []):
                                extra_origins_by_sub.setdefault(id(sub), set()).add(et.event_index)

            for submission in submissions:
                origins = submission_origin_indices.get(id(submission), set())
                extra_origins = extra_origins_by_sub.get(id(submission), set())
                pos_map = events_pos_by_origin.get(id(submission), {})
                scoped_event_traces = []
                for et in self.correlation_trace.event_traces:
                    if et.event_index not in origins and et.event_index not in extra_origins:
                        continue
                    summary = None
                    post_idx = origin_to_post.get(et.event_index)
                    if et.event_index in origins and post_idx is not None and post_idx < len(query_results):
                        summary = self._extract_event_summary(
                            query_results[post_idx],
                            per_event_observables.get(post_idx, []),
                        )
                    elif (
                        et.event_index in extra_origins
                        and self.original_query_results is not None
                        and et.event_index < len(self.original_query_results)
                        and isinstance(self.original_query_results[et.event_index], dict)
                    ):
                        summary = self._extract_event_summary(
                            self.original_query_results[et.event_index], [],
                        )
                    scoped_event_traces.append(et.model_copy(update={
                        "summary": summary,
                        "events_position": pos_map.get(et.event_index),
                    }))
                per_alert_trace = CorrelationTrace(
                    event_traces=scoped_event_traces,
                    stream_events=self.correlation_trace.stream_events,
                )
                submission.root.details[QUERY_DETAILS_CORRELATION_TRACE] = per_alert_trace.model_dump()

        # Attach the pre-correlation events to each correlated alert so hunt authors can inspect
        # what came back from the data source before correlation filtered/transformed it.
        if self.config.correlate is not None and self.original_query_results is not None:
            for submission in submissions:
                submission.root.details[QUERY_DETAILS_ORIGINAL_EVENTS] = self.original_query_results

        # Attach step provenance to each correlated alert so the GUI can group the
        # Analysis Overview by the hunt step that produced each observable. We walk each
        # submission's own observable store and resolve provenance by (type, value) so the
        # uuid->steps map only covers observables actually present in that alert. The
        # ordered step list (shared across submissions) carries the labels the UI renders.
        if self.config.correlate is not None:
            for submission in submissions:
                obs_map: dict[str, list[int]] = {}
                for obs in submission.root.observable_store.values():
                    steps = provenance_by_value.get((obs.type, obs.value))
                    if steps:
                        obs_map[obs.uuid] = sorted(steps)
                submission.root.details[QUERY_DETAILS_HUNT_PROVENANCE] = {
                    "steps": ordered_provenance_steps,
                    "observables": obs_map,
                }

        # filter out groups whose suppression window has not yet elapsed.
        # the hunt is run as a whole because we cannot know which groups are present
        # until after the query executes; suppression then drops the per-group alerts.
        # manual_hunt runs (e.g. the validate-hunt API) ignore suppression entirely so
        # the analyst sees the hunt's true output, unaffected by production alert history.
        if self.group_by is not None and self.suppression is not None and self.manual_hunt:
            logging.debug(
                "ignoring suppression for hunt %s (uuid=%s, type=%s) - manual hunt / validation run",
                self.name, self.uuid, self.type,
            )
        elif self.group_by is not None and self.suppression is not None:
            kept = []
            for submission in submissions:
                group_value = getattr(submission, "group_value", None)
                if group_value is not None and self.is_group_suppressed(group_value):
                    logging.info(
                        "suppressed alert for hunt %s (uuid=%s, type=%s) group_by=%s group_value=%s",
                        self.name, self.uuid, self.type, self.group_by, group_value,
                    )
                    continue
                kept.append(submission)
            submissions = kept

        return submissions
