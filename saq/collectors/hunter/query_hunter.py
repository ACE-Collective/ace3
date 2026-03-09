# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import datetime
import logging
import os
import os.path
import re
from tempfile import mkstemp
from typing import Optional

import pytz
from pydantic import Field, model_validator

from saq.analysis.observable import Observable
from saq.analysis.root import KEY_PLAYBOOK_URL, RootAnalysis, Submission
from saq.collectors.hunter import Hunt, read_persistence_data, write_persistence_data
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration.config import get_config
from saq.constants import F_SIGNATURE_ID, TIMESPEC_TOKEN
from saq.environment import get_temp_dir
from saq.gui.alert import KEY_ALERT_TEMPLATE, KEY_ICON_CONFIGURATION
from saq.observables.generator import create_observable
from saq.observables.mapping import (
    ObservableMapping,
    RelationshipMapping,
)
from saq.query.config import BaseQueryConfig, SummaryDetailConfig, load_query_from_file
from saq.query.event_processing import (
    contains_unresolved_placeholders,
    interpolate_event_value,
)
from saq.query.extraction import extract_observables_from_event
from saq.util import abs_path, create_timedelta, local_time

QUERY_DETAILS_SEARCH_ID = "search_id"
QUERY_DETAILS_SEARCH_LINK = "search_link"
QUERY_DETAILS_QUERY = "query"
QUERY_DETAILS_EVENTS = "events"

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

class QueryHuntConfig(HuntConfig, BaseQueryConfig):
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
    dedup_key: Optional[str] = Field(default=None, description="Optional interpolation template for deduplication. Uses ${field} syntax. When set, submissions get a key enabling the DuplicateSubmissionFilter to suppress duplicates.")

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
            return self.config.query

        # have we already loaded the query from file?
        if self.loaded_query is not None:
            return self.loaded_query

        if self.query_file_path is not None:
            self.loaded_query = self.load_query_from_file(self.query_file_path)
            return self.loaded_query
        else:
            raise ValueError(f"no query specified for hunt {self}")

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
        # if this hunt is configured for full coverage, then the ending time for the search
        # will be equal to the ending time of the last executed search plus the total range of the search
        now = local_time()
        if self.full_coverage:
            # have we not executed this search yet?
            if self.last_end_time is None:
                return now
            else:
                # if the difference in time between the end of the range and now is larger than 
                # the time_range, then we switch to using the max_time_range, if it is configured
                if self.max_time_range is not None:
                    extended_end_time = self.last_end_time + self.max_time_range
                    if now - (self.last_end_time + self.time_range) > self.time_range:
                        return now if extended_end_time > now else extended_end_time
                return now if (self.last_end_time + self.time_range) > now else self.last_end_time + self.time_range
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

    def create_root_analysis(self, event: dict) -> RootAnalysis:
        import uuid as uuidlib
        root_uuid = str(uuidlib.uuid4())
        extensions = {}
        if self.playbook_url:
            for url_value in interpolate_event_value(self.playbook_url, event):
                extensions.update({
                    KEY_PLAYBOOK_URL: url_value,
                })

        if self.icon_configuration:
            extensions[KEY_ICON_CONFIGURATION] = self.icon_configuration.model_dump()

        if self.alert_template:
            extensions[KEY_ALERT_TEMPLATE] = self.alert_template

        #instructions_list = interpolate_event_value(self.instructions, event)
        #if not instructions_list:
            #instructions = None
        #else:
            ## otherwise just use the first instruction
            #instructions = instructions_list[0]

        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=os.path.join(get_temp_dir(), root_uuid),
            desc=self.name,
            instructions=self.description,
            analysis_mode=self.analysis_mode,
            tool=f'hunter-{self.type}',
            tool_instance=self.tool_instance,
            alert_type=self.alert_type,
            details={
                QUERY_DETAILS_SEARCH_ID: self.search_id if self.search_id else None,
                QUERY_DETAILS_SEARCH_LINK: self.search_link if self.search_link else None,
                QUERY_DETAILS_QUERY: self.formatted_query(),
                QUERY_DETAILS_EVENTS: [],
            },
            event_time=None,
            queue=self.queue,
            extensions=extensions)

        root.initialize_storage()

        for tag in self.tags:
            for tag_value in interpolate_event_value(tag, event):
                root.add_tag(tag_value)

        for pivot_link in self.pivot_links:
            for pivot_link_url_value in interpolate_event_value(pivot_link["url"], event):
                for pivot_link_text_value in interpolate_event_value(pivot_link["text"], event):
                    root.add_pivot_link(pivot_link_url_value, pivot_link.get("icon", None), pivot_link_text_value)

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

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue

            # interpolate content
            content_values = interpolate_event_value(sd_config.content, event)
            if not content_values:
                continue
            content = content_values[0]
            if contains_unresolved_placeholders(content):
                continue

            # interpolate header
            header = None
            if sd_config.header is not None:
                header_values = interpolate_event_value(sd_config.header, event)
                if not header_values:
                    continue
                header = header_values[0]
                if contains_unresolved_placeholders(header):
                    continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)
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

    def _process_grouped_summary_detail(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Collect content from all events and add one combined SummaryDetail per submission."""
        # submission id -> list of content strings
        collected: dict[int, list[str]] = {}
        # submission id -> header (from first contributing event)
        headers: dict[int, Optional[str]] = {}
        # submission id -> submission object
        sub_lookup: dict[int, Submission] = {}
        # submission id -> whether we've already logged the limit warning
        limit_warned: dict[int, bool] = {}

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue

            content_values = interpolate_event_value(sd_config.content, event)
            if not content_values:
                continue
            content = content_values[0]
            if contains_unresolved_placeholders(content):
                continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)
                sub_lookup[sub_id] = submission

                if sub_id not in collected:
                    collected[sub_id] = []
                    limit_warned[sub_id] = False

                if len(collected[sub_id]) >= sd_config.limit:
                    if not limit_warned[sub_id]:
                        logging.warning(
                            "summary detail limit (%s) reached for grouped definition content=%s in hunt %s",
                            sd_config.limit, sd_config.content, self.name,
                        )
                        limit_warned[sub_id] = True
                    continue

                collected[sub_id].append(content)

                # resolve header from first contributing event
                if sub_id not in headers:
                    if sd_config.header is not None:
                        header_values = interpolate_event_value(sd_config.header, event)
                        if header_values and not contains_unresolved_placeholders(header_values[0]):
                            headers[sub_id] = header_values[0]
                        else:
                            headers[sub_id] = None
                    else:
                        headers[sub_id] = None

        # add the combined summary details
        for sub_id, lines in collected.items():
            if not lines:
                continue
            submission = sub_lookup[sub_id]
            submission.root.add_summary_detail(
                header=headers.get(sub_id),
                content="\n".join(lines),
                format=sd_config.format,
            )

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        submissions: list[Submission] = [] # of Submission objects

        def _create_submission(event: dict):
            return Submission(self.create_root_analysis(event))

        def _compute_dedup_key(event: dict) -> Optional[str]:
            if not self.dedup_key:
                return None
            values = interpolate_event_value(self.dedup_key, event)
            if not values:
                return None
            value = values[0]
            if contains_unresolved_placeholders(value):
                return None
            return f"{self.uuid}:{value}"

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # this is used to keep track of which observables need to have relationship mapped
        relationship_tracking: dict[Observable, list[RelationshipMapping]] = {}

        # maps event index to the submission(s) it belongs to (for summary detail processing)
        event_submission_map: dict[int, list[Submission]] = {}

        # map results to observables
        for event_index, event in enumerate(query_results):
            event_time = self.extract_event_timestamp(event) or local_time()
            event = self.wrap_event(event)

            # use shared extraction pipeline
            extracted, file_contents, event_relationships = extract_observables_from_event(
                event, self.observable_mapping, event_time,
                global_ignored_patterns=self.config._ignored_value_patterns if self.config.ignored_values else None,
            )

            # deduplicate observables (shared extraction may return duplicates across mappings)
            observables: list[Observable] = []
            for ext in extracted:
                if ext.observable not in observables:
                    observables.append(ext.observable)

            # merge relationship tracking
            relationship_tracking.update(event_relationships)

            signature_id_observable = create_observable(F_SIGNATURE_ID, self.uuid)

            if signature_id_observable is not None:
                signature_id_observable.display_value = self.name
                observables.append(signature_id_observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission(event)
                submission.key = _compute_dedup_key(event)
                submission.root.event_time = event_time

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
                            for potential_target_value in interpolate_event_value(relationship_mapping.target.value, event):
                                if contains_unresolved_placeholders(potential_target_value):
                                    logging.warning(
                                        f"skipping relationship in hunt {self.name}: target value "
                                        f"'{relationship_mapping.target.value}' resolved to '{potential_target_value}' "
                                        f"which contains unresolved field references (field missing from event)"
                                    )
                                    continue
                                target_observable = submission.root.get_observable_by_spec(relationship_mapping.target.type, potential_target_value)
                                if target_observable is not None:
                                    observable.add_relationship(relationship_mapping.type, target_observable)

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.root.description += f' ({len(submission.root.details.get(QUERY_DETAILS_EVENTS, []))} event{"" if len(submission.root.details.get(QUERY_DETAILS_EVENTS, [])) == 1 else "s"})'

        self._process_summary_details(query_results, event_submission_map)

        return submissions
