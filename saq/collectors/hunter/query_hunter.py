# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import datetime
import logging
import os
import os.path
import re
from typing import Optional

import pytz
from pydantic import Field

from saq.analysis.root import Submission
from saq.collectors.hunter import Hunt, read_persistence_data, write_persistence_data
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.collectors.hunter.result_processing import (
    QUERY_DETAILS_EVENTS,
    QUERY_DETAILS_QUERY,
    QUERY_DETAILS_SEARCH_ID,
    QUERY_DETAILS_SEARCH_LINK,
    ResultProcessingMixin,
)
from saq.configuration.config import get_config
from saq.observables.mapping import ObservableMapping
from saq.query.config import BaseQueryConfig, load_query_from_file
from saq.util import abs_path, create_timedelta, local_time

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

class QueryHuntConfig(HuntConfig, BaseQueryConfig):
    time_range: str = Field(..., description="The time range to query over. This can be a timedelta string or a cron schedule string.")
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

class QueryHunt(Hunt, ResultProcessingMixin):
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
