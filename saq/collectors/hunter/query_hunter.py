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

from glom import PathAccessError
from pydantic import BaseModel, Field, model_validator

from saq.analysis.observable import Observable
from saq.analysis.root import KEY_PLAYBOOK_URL, RootAnalysis, Submission
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.decoder import DecoderType, decode_value
from saq.collectors.hunter.event_processing import FIELD_LOOKUP_TYPE_KEY, extract_event_value, interpolate_event_value
from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration.config import get_config
from saq.constants import F_FILE, F_SIGNATURE_ID
from saq.environment import get_temp_dir
from saq.gui.alert import KEY_ALERT_TEMPLATE, KEY_ICON_CONFIGURATION
from saq.observables.generator import create_observable

import pytz

from saq.collectors.hunter import Hunt, write_persistence_data, read_persistence_data
from saq.util import local_time, create_timedelta, abs_path

QUERY_DETAILS_SEARCH_ID = "search_id"
QUERY_DETAILS_SEARCH_LINK = "search_link"
QUERY_DETAILS_QUERY = "query"
QUERY_DETAILS_EVENTS = "events"

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

class RelationshipMappingTarget(BaseModel):
    type: str = Field(..., description="The type of target to create")
    value: str = Field(..., description="The value of the target")

class RelationshipMapping(BaseModel):
    type: str = Field(..., description="The type of relationship to create")
    target: RelationshipMappingTarget = Field(..., description="The target of the relationship")

class ObservableMapping(BaseModel):
    fields: list[str] = Field(..., default_factory=list, description="One or more fields to map to an observable")
    field_lookup_type: Optional[str] = Field(default=FIELD_LOOKUP_TYPE_KEY, description="The type of lookup to perform for the fields.")
    type: str = Field(..., description="The type of observable to map to")
    value: Optional[str] = Field(default=None, description="OPTIONAL value to use for the observable")
    file_name: Optional[str] = Field(default=None, description="OPTIONAL if the type is F_FILE, the name of the file to use for the observable")
    file_decoder: Optional[DecoderType] = Field(default=None, description="OPTIONAL if the type is F_FILE, the decoder to use for the observable")
    time: bool = Field(default=False, description="Whether to use the time of the event as the time of the observable")
    directives: list[str] = Field(default_factory=list, description="The directives to add to the observable")
    tags: list[str] = Field(default_factory=list, description="The tags to add to the observable")
    volatile: bool = Field(default=False, description="Whether to add the observable as volatile. Volatile observables are added for the purposes of detection.")
    ignored_values: list[str] = Field(default_factory=list, description="A list of regex patterns to ignore when mapping the observable. Patterns are matched with re.fullmatch().")
    display_type: Optional[str] = Field(default=None, description="The display type to use for the observable.")
    display_value: Optional[str] = Field(default=None, description="The display value to use for the observable.")
    relationships: list[RelationshipMapping] = Field(default_factory=list, description="The relationships to add to the observable")
    _ignored_value_patterns: list[re.Pattern] = []

    @model_validator(mode='after')
    def validate_display_value_for_file_type(self):
        """validate that display_value is not set for file type observables"""
        if self.type == F_FILE and self.display_value is not None:
            raise ValueError(f"display_value is not supported for file type observables (type={self.type})")
        return self

    @model_validator(mode='after')
    def compile_ignored_value_patterns(self):
        """Pre-compile ignored_values into regex patterns."""
        for p in self.ignored_values:
            try:
                self._ignored_value_patterns.append(re.compile(p))
            except re.error as e:
                logging.error(f"invalid ignored_values regex pattern {p!r}: {e}")
        return self

    def is_ignored_value(self, value: str) -> bool:
        """Check if a value matches any ignored_values regex pattern."""
        return any(p.fullmatch(value) for p in self._ignored_value_patterns)

class QueryHuntConfig(HuntConfig):
    time_range: str = Field(..., description="The time range to query over. This can be a timedelta string or a cron schedule string.")
    max_time_range: Optional[str] = Field(default=None, description="The maximum time range to query over.")
    full_coverage: bool = Field(..., description="Whether to run the query over the full coverage of the time range.")
    use_index_time: bool = Field(..., description="Whether to use the index time as the time of the query.")
    offset: Optional[str] = Field(default=None, description="An optional offset to run the query at.")
    group_by: Optional[str] = Field(default=None, description="The field to group the results by.")
    description_field: Optional[str] = Field(default=None, description="The event field to use for the alert description suffix. If not set, the group_by field value is used.")
    query_file_path: Optional[str] = Field(alias="search", default=None, description="The path to the search query file.")
    query: Optional[str] = Field(default=None, description="The search query to execute.")
    observable_mapping: list[ObservableMapping] = Field(default_factory=list, description="The mapping of fields to observables.")
    max_result_count: Optional[int] = Field(default_factory=lambda: get_config().query_hunter.max_result_count, description="The maximum number of results to return.")
    query_timeout: Optional[str] = Field(default_factory=lambda: get_config().query_hunter.query_timeout, description="The timeout for the query (in HH:MM:SS format).")
    auto_append: str = Field(default="", description="The string to append to the query after the time spec. By default this is an empty string.")
    ignored_values: list[str] = Field(default_factory=list, description="A global list of regex patterns to ignore that applies to all observable mappings. Patterns are matched with re.fullmatch().")
    _ignored_value_patterns: list[re.Pattern] = []

    @model_validator(mode='after')
    def compile_ignored_value_patterns(self):
        """Pre-compile ignored_values into regex patterns."""
        for p in self.ignored_values:
            try:
                self._ignored_value_patterns.append(re.compile(p))
            except re.error as e:
                logging.error(f"invalid ignored_values regex pattern {p!r}: {e}")
        return self

    def is_ignored_value(self, value: str) -> bool:
        """Check if a value matches any ignored_values regex pattern."""
        return any(p.fullmatch(value) for p in self._ignored_value_patterns)

class FileContent(BaseModel):
    file_name: str = Field(..., description="The name of the file as defined by the observable mapping.")
    content: bytes = Field(..., description="The content of the file.")
    directives: list[str] = Field(default_factory=list, description="The directives to add to the file observable.")
    tags: list[str] = Field(default_factory=list, description="The tags to add to the file observable.")
    volatile: bool = Field(default=False, description="Whether to add the observable as volatile.")
    display_type: Optional[str] = Field(default=None, description="The display type to use for the file observable.")
    display_value: Optional[str] = Field(default=None, description="The display value to use for the file observable.")

def interpret_event_value(observable_mapping: ObservableMapping, event: dict) -> list[str]:
    """Interprets the event value(s) for the given event and observable mapping.

    Returns a list of observed, interpolated values."""
    assert isinstance(observable_mapping, ObservableMapping)
    assert isinstance(event, dict)

    result: list[str] = []

    if not observable_mapping.fields:
        raise ValueError(f"no fields specified for observable mapping {observable_mapping}")

    # is the value for this mapping not computed?
    if observable_mapping.value is None:
        # then we just take the value
        observed_value = event[observable_mapping.fields[0]] # hard coded to first field
    else:
        # otherwise we interpolate the value from the event
        observed_value = interpolate_event_value(observable_mapping.value, event)

    # we always return a list of values, even if there is only one
    if not isinstance(observed_value, list):
        result = [observed_value]
    else:
        result = observed_value

    # if any of the results are bytes, convert them into strings using utf-8
    return [_.decode("utf-8", errors="ignore") if isinstance(_, bytes) else str(_) for _ in result]

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
        return create_timedelta(self.config.time_range)

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
        with open(abs_path(path), 'r') as fp:
            result = fp.read()

            #if self.strip_comments:
                #result = COMMENT_REGEX.sub('', result)

        return result
    
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

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        submissions: list[Submission] = [] # of Submission objects

        def _create_submission(event: dict):
            return Submission(self.create_root_analysis(event))

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # this is used to keep track of which observables need to have relationship mapped
        relationship_tracking: dict[Observable, list[RelationshipMapping]] = {}

        # map results to observables
        for event in query_results:
            event_time = self.extract_event_timestamp(event) or local_time()
            event = self.wrap_event(event)

            # pull the observables out of this event
            observables: list[Observable] = []

            # pull file contents out separately from observables
            file_contents: list[FileContent] = []

            for observable_mapping in self.observable_mapping:
                # first make sure all the fields that we need to map this observable are present in the event
                all_fields_present = True
                for field_name in observable_mapping.fields:
                    try:
                        success, _ = extract_event_value(event, observable_mapping.field_lookup_type, field_name)
                        if not success:
                            all_fields_present = False
                            break
                    except PathAccessError:
                        all_fields_present = False
                        break
                    
                if not all_fields_present:
                    continue

                # used for file content observables to store the decoded value
                decoded_observed_value: Optional[bytes] = None

                # iterate through the list of all interpolated values for this observable mapping
                for observed_value in interpret_event_value(observable_mapping, event):
                    # if the value is empty we ignore it
                    if not observed_value:
                        continue

                    # if the value is in the global ignored list, then we ignore it
                    if self.config.ignored_values and self.config.is_ignored_value(observed_value):
                        continue

                    # if the value is in the ignored values list (for this observable mapping), then we ignore it
                    if observable_mapping.ignored_values and observable_mapping.is_ignored_value(observed_value):
                        continue

                    # create the observable
                    if observable_mapping.type == F_FILE:
                        if observable_mapping.file_decoder is not None:
                            decoded_observed_value = decode_value(observed_value, observable_mapping.file_decoder)

                        # if we don't specify a decoder then we assume the value is a string and encode it as utf8 bytes
                        if decoded_observed_value is None:
                            decoded_observed_value = observed_value.encode('utf-8')

                        for target_file_name in interpolate_event_value(observable_mapping.file_name, event):
                            # interpolate directives and tags from event fields
                            interpolated_directives = []
                            for directive in observable_mapping.directives:
                                interpolated_directives.extend(interpolate_event_value(directive, event))

                            interpolated_tags = []
                            for tag in observable_mapping.tags:
                                interpolated_tags.extend(interpolate_event_value(tag, event))

                            file_contents.append(FileContent(
                                file_name=target_file_name,
                                content=decoded_observed_value,
                                directives=interpolated_directives,
                                tags=interpolated_tags,
                                volatile=observable_mapping.volatile,
                                display_type=observable_mapping.display_type,
                                display_value=observable_mapping.display_value
                            ))

                        continue
                    
                    # otherwise it's just a normal observable
                    observable = create_observable(observable_mapping.type, observed_value, volatile=observable_mapping.volatile)

                    if observable is None:
                        logging.warning(f"unable to create observable {observable_mapping.type} with value {observed_value} for event {event} in hunt {self}")
                        continue

                    # did we specify that the time be recorded?
                    if observable_mapping.time:
                        observable.time = event_time

                    # add any specified directives
                    for directive in observable_mapping.directives:
                        for directive_value in interpolate_event_value(directive, event):
                            observable.add_directive(directive_value)

                    # and any specified tags
                    for tag in observable_mapping.tags:
                        for tag_value in interpolate_event_value(tag, event):
                            observable.add_tag(tag_value)

                    if observable_mapping.display_type is not None:
                        observable.display_type = observable_mapping.display_type

                    if observable_mapping.display_value is not None:
                        observable.display_value = observable_mapping.display_value

                    # track any relationships that we'll need to map in later
                    if observable_mapping.relationships:
                        relationship_tracking[observable] = observable_mapping.relationships

                    # add it to our list if we haven't already added it
                    if observable not in observables:
                        observables.append(observable)

            signature_id_observable = create_observable(F_SIGNATURE_ID, self.uuid)

            if signature_id_observable is not None:
                signature_id_observable.display_value = self.name
                observables.append(signature_id_observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission(event)
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
                                target_observable = submission.root.get_observable_by_spec(relationship_mapping.target.type, potential_target_value)
                                if target_observable is not None:
                                    observable.add_relationship(relationship_mapping.type, target_observable)

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.root.description += f' ({len(submission.root.details.get(QUERY_DETAILS_EVENTS, []))} event{"" if len(submission.root.details.get(QUERY_DETAILS_EVENTS, [])) == 1 else "s"})'


        return submissions
