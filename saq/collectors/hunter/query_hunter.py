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
from pydantic import BaseModel, Field

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.decoder import DecoderType, decode_value
from saq.collectors.hunter.event_processing import FIELD_LOOKUP_TYPE_KEY, extract_event_value, interpolate_event_value
from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration import get_config_value, get_config_value_as_int
from saq.constants import CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_MAX_RESULT_COUNT, CONFIG_QUERY_HUNTER_QUERY_TIMEOUT, F_FILE, F_HUNT, F_SIGNATURE_ID, G_TEMP_DIR
from saq.environment import g
from saq.observables.generator import create_observable

import pytz

from saq.collectors.hunter import Hunt, write_persistence_data, read_persistence_data
from saq.util import local_time, create_timedelta, abs_path

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

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

class QueryHuntConfig(HuntConfig):
    time_range: str = Field(..., description="The time range to query over. This can be a timedelta string or a cron schedule string.")
    max_time_range: Optional[str] = Field(default=None, description="The maximum time range to query over.")
    full_coverage: bool = Field(..., description="Whether to run the query over the full coverage of the time range.")
    use_index_time: bool = Field(..., description="Whether to use the index time as the time of the query.")
    offset: Optional[str] = Field(default=None, description="An optional offset to run the query at.")
    group_by: Optional[str] = Field(default=None, description="The field to group the results by.")
    query_file_path: Optional[str] = Field(alias="search", default=None, description="The path to the search query file.")
    query: Optional[str] = Field(default=None, description="The search query to execute.")
    observable_mapping: list[ObservableMapping] = Field(default_factory=list, description="The mapping of fields to observables.")
    max_result_count: Optional[int] = Field(default_factory=lambda: get_config_value_as_int(CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_MAX_RESULT_COUNT), description="The maximum number of results to return.")
    query_timeout: Optional[str] = Field(default_factory=lambda: get_config_value(CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_QUERY_TIMEOUT), description="The timeout for the query (in HH:MM:SS format).")

class FileContent(BaseModel):
    file_name: str = Field(..., description="The name of the file as defined by the observable mapping.")
    content: bytes = Field(..., description="The content of the file.")

class QueryHunt(Hunt):
    """Abstract class that represents a hunt against a search system that queries data over a time range."""

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

    def execute_query(self, start_time, end_time, *args, **kwargs):
        """Called to execute the query over the time period given by the start_time and end_time parameters.
           Returns a list of zero or more Submission objects."""
        raise NotImplementedError()

    # XXX copy pasta from lib/saq/collectors/hunter.py
    @property
    def last_end_time(self):
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
    def last_end_time(self, value):
        if value.tzinfo is None:
            value = pytz.utc.localize(value)

        value = value.astimezone(pytz.utc)

        self._last_end_time = value
        write_persistence_data(self.type, self.name, 'last_end_time', value)

    @property
    def start_time(self):
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
    def end_time(self):
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
    def ready(self):
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

    def load_query_from_file(self, path: str):
        with open(abs_path(self.query_file_path), 'r') as fp:
            result = fp.read()

            #if self.strip_comments:
                #result = COMMENT_REGEX.sub('', result)

        return result
    
    def load_hunt_config(self, path: str) -> QueryHuntConfig:
        return load_from_yaml(path, QueryHuntConfig)

    def load_hunt(self, path: str) -> QueryHuntConfig:
        super().load_hunt(path)

        if self.config.query_file_path:
            self.loaded_query = self.load_query_from_file(self.config.query_file_path)

        return self.config    

    @property
    def is_modified(self):
        return self.yaml_is_modified or self.query_is_modified

    @property
    def query_is_modified(self):
        """Returns True if this query was loaded from file and that file has been modified since we loaded it."""
        if self.query_file_path is None:
            return False

        try:
            return self.query_last_mtime != os.path.getmtime(self.query_file_path)
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

    def extract_event_timestamp(self, query_result):
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
        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=os.path.join(g(G_TEMP_DIR), root_uuid),
            desc=interpolate_event_value(self.name, event),
            analysis_mode=self.analysis_mode,
            tool=f'hunter-{self.type}',
            tool_instance=self.tool_instance,
            alert_type=self.alert_type,
            details=[{'search_id': self.search_id if self.search_id else None,
                    'search_link': self.search_link if self.search_link else None,
                    'query': self.formatted_query()}],
            event_time=None,
            queue=self.queue,
            instructions=interpolate_event_value(self.description, event),
            extensions={ "playbook_url": interpolate_event_value(self.playbook_url, event) })

        root.initialize_storage()

        for tag in self.tags:
            root.add_tag(interpolate_event_value(tag, event))

        for pivot_link in self.pivot_links:
            root.add_pivot_link(interpolate_event_value(pivot_link["url"], event), interpolate_event_value(pivot_link.get("icon", None), event), interpolate_event_value(pivot_link["text"], event))

        return root

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        submissions = [] # of Submission objects

        def _create_submission(event: dict):
            return Submission(self.create_root_analysis(event))

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

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

                # compute the value
                # if the value is not specified, then we take the value from the event
                # and if there are more than one fields specified, then we just take the first one
                if observable_mapping.value is None:
                    observed_value = event[observable_mapping.fields[0]] # hard coded to first field
                else:
                    # otherwise we interpolate the value from the event
                    observed_value = interpolate_event_value(observable_mapping.value, event)

                if observable_mapping.file_decoder is not None:
                    observed_value = decode_value(observed_value, observable_mapping.file_decoder)

                # create the observable
                if observable_mapping.type == F_FILE:
                    # if we're treating the value of this field as file content but the value is a string,
                    # then we need to encode it as bytes
                    if isinstance(observed_value, str):
                        observed_value = observed_value.encode('utf-8')

                    if not isinstance(observed_value, bytes):
                        logging.error(f"expected bytes for file content, got {type(observed_value)} for event {event} in hunt {self}")
                        continue

                    target_file_name = interpolate_event_value(observable_mapping.file_name, event)
                    file_contents.append(FileContent(file_name=target_file_name, content=observed_value))
                else:
                    observable = create_observable(observable_mapping.type, observed_value)

                if observable is None:
                    logging.error(f"unable to create observable {observable_mapping.type} with value {observed_value} for event {event} in hunt {self}")
                    continue

                # did we specify that the time be recorded?
                if observable_mapping.time:
                    observable.time = event_time

                # add any specified directives
                for directive in observable_mapping.directives:
                    observable.add_directive(interpolate_event_value(directive, event))

                # and any specified tags
                for tag in observable_mapping.tags:
                    observable.add_tag(interpolate_event_value(tag, event))

                # add it to our list if we haven't already added it
                if observable not in observables:
                    observables.append(observable)

            observables.append(create_observable(F_HUNT, self.name))
            observables.append(create_observable(F_SIGNATURE_ID, self.uuid))

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission(event)
                submission.root.event_time = event_time
                for observable in observables:
                    submission.root.add_observable(observable)

                for file_content in file_contents:
                    fd, temp_file_path = mkstemp(dir=g(G_TEMP_DIR))
                    os.write(fd, file_content.content)
                    os.close(fd)

                    submission.root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True)

                submission.root.details.append(event)
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
                            event_grouping[grouping_target].root.description += f': {grouping_target}'
                        submissions.append(event_grouping[grouping_target])

                    for observable in observables:
                        if observable not in event_grouping[grouping_target].root.observables:
                            event_grouping[grouping_target].root.add_observable(observable)

                    for file_content in file_contents:
                        fd, temp_file_path = mkstemp(dir=g(G_TEMP_DIR))
                        os.write(fd, file_content.content)
                        os.close(fd)

                        event_grouping[grouping_target].root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True)

                    event_grouping[grouping_target].root.details.append(event)

                    # for grouped events, the overall event time is the earliest event time in the group
                    # this won't really matter if the observables are temporal
                    if event_grouping[grouping_target].root.event_time is None:
                        event_grouping[grouping_target].root.event_time = event_time
                    elif event_time < event_grouping[grouping_target].root.event_time:
                        event_grouping[grouping_target].root.event_time = event_time

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.root.description += f' ({len(submission.root.details) - 1} event{"" if len(submission.root.details) - 1 == 1 else "s"})'

        return submissions
