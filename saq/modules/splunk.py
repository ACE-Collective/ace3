# vim: sw=4:ts=4:et:cc=120

import re
from datetime import datetime
from typing import Type, Optional
from pydantic import Field
import pytz

from saq.configuration.config import get_splunk_config
from saq.modules.api_analysis import BaseAPIAnalysis, BaseAPIAnalyzer, BaseAPIAnalysisPresenter, AnalysisDelay, BaseAPIAnalyzerConfig
from saq.modules.config import AnalysisModuleConfig
from saq.splunk import extract_event_timestamp, SplunkClient
from saq.util import format_iso8601, parse_event_time


#
# Requirements for Splunk queries
#
# <O_VALUE> is replaced by the value of the observable
# <O_TYPE> is replaced by the type of the observable
# <O_TIMESPEC> is replaced by the formatted timerange (done all in one to allow searching by index time)
#

from saq.analysis.presenter.analysis_presenter import register_analysis_presenter


class SplunkAPIAnalyzerConfig(BaseAPIAnalyzerConfig):
    use_index_time: bool = Field(default=False, description="Whether to use the index time as the time of the query.")
    splunk_user_context: Optional[str] = Field(default=None, description="The namespace user to use for the query.")
    splunk_app_context: Optional[str] = Field(default=None, description="The namespace app to use for the query.")

class SplunkAPIAnalysis(BaseAPIAnalysis):
    @property
    def search_id(self):
        return self.details.get('search_id', None)

    @search_id.setter
    def search_id(self, value):
        # Convert Job objects to their string name for JSON serialization
        if value is not None and hasattr(value, 'name'):
            value = value.name
        self.details['search_id'] = value

    @property
    def dispatch_state(self):
        return self.details.get('dispatch_state', None)

    @dispatch_state.setter
    def dispatch_state(self, value):
        self.details['dispatch_state'] = value

    @property
    def start_time(self):
        result = self.details.get('start_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @start_time.setter
    def start_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['start_time'] = value

    @property
    def running_start_time(self):
        result = self.details.get('running_start_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @running_start_time.setter
    def running_start_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['running_start_time'] = value

    @property
    def end_time(self):
        result = self.details.get('end_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @end_time.setter
    def end_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['end_time'] = value


class SplunkAPIAnalyzer(BaseAPIAnalyzer):
    """Base Module to make AnalysisModule performing correlational Splunk queries.

          This class should be overridden for each individual Splunk query.

          Attributes (in addition to parent class attrs):
              timezone: str that contains configured timezone for Splunk API instance (ex. GMT)
              use_index_time: bool that contains whether a query should search based on index time
              namespace_app: str that contains namespace_app, if necessary
              namespace_user: str that contains namespace_user, if necessary
    """
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return SplunkAPIAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.timezone = get_splunk_config(self.config.api_name).timezone
        self.use_index_time = self.config.use_index_time

        self.splunk = SplunkClient(
            name = self.config.api_name,
            user_context = self.config.splunk_user_context,
            app = self.config.splunk_app_context,
        )

    @property
    def generated_analysis_type(self):
        return SplunkAPIAnalysis

    def search_url(self, query=None) -> str:
        """Returns the url encoded search link. If you do not specify the query parameter, it defaults to use the
        self.target_query. Being able to customize the query can help in cases where the query might have something like
        a "| stats count" in it, but you want to link the user to a query that will give them the actual results."""
        if query is None:
            query = self.target_query

        return self.splunk.encoded_query_link(query)

    def _escape_value(self, value: str) -> str:
        # Make sure any backslashes are escaped first
        value = value.replace('\\', '\\\\')
        return value.replace('"', '\\"').replace("'", "\\'")

    def fill_target_query_timespec(self, start_time, stop_time):
        tz = pytz.timezone(self.timezone)

        earliest = start_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
        latest = stop_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            time_spec = f'earliest = {earliest} latest = {latest}'

        # set the gui link
        self.analysis.details['gui_link'] = self.splunk.encoded_query_link(
            self.target_query.replace('<O_TIMESPEC>', ''),
            start_time.astimezone(tz),
            stop_time.astimezone(tz),
        )

        self.target_query = self.target_query.replace('<O_TIMESPEC>', time_spec)

    # Based on QRadarAPIAnalysis, but may not need this in the future
    def process_splunk_event(self, analysis, observable, event, event_time):
        """Called for each event processed by the module. Can be overridden by subclasses."""
        pass

    def process_query_results(self, query_results, analysis, observable):
        # Extract column order from "| table col1 col2 ..." if present
        if analysis.query:
            m = re.search(r'\|\s*table\s+(.+?)(?:\||$)', analysis.query, re.IGNORECASE)
            if m:
                analysis.details['table_columns'] = [c.strip().rstrip(',') for c in m.group(1).split()]

        for event in query_results:
            event_time = extract_event_timestamp(event)
            self.process_splunk_event(analysis, observable, event, event_time)
            self.extract_result_observables(analysis, event, observable, event_time)

    def execute_query(self):
        # execute the query
        self.splunk.reset_search_status(
            dispatch_state=self.analysis.dispatch_state,
            start_time=self.analysis.start_time,
            running_start_time=self.analysis.running_start_time,
            end_time=self.analysis.end_time)

        # If we have a stored search_id (job name string), retrieve the Job object
        job = None
        if self.analysis.search_id is not None:
            try:
                job = self.splunk.client.jobs[self.analysis.search_id]
            except KeyError:
                # Job no longer exists, will create a new one
                job = None

        job, results = self.splunk.query_async(self.target_query, job, limit=self.max_result_count)

        # Store the job name (search_id setter converts Job to string)
        self.analysis.search_id = job
        self.analysis.dispatch_state = self.splunk.dispatch_state
        self.analysis.start_time = self.splunk.start_time
        self.analysis.running_start_time = self.splunk.running_start_time
        self.analysis.end_time = self.splunk.end_time

        # delay if there are no results
        if results is None:
            raise AnalysisDelay()

        # return results
        return results

register_analysis_presenter(SplunkAPIAnalysis, BaseAPIAnalysisPresenter)
