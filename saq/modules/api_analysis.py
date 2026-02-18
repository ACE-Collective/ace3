# vim: sw=4:ts=4:et:cc=120

"""Base classes for API Analysis Modules that can be used to add correlational analysis by querying APIs.

These base classes can be used to create child Analysis modules on an API-by-API basis,
such as QRadarAPIAnalysis or SplunkAPIAnalysis. The built-in 'flow' expects a correlational query that
will be ran for individual, applicable observables. The query results can be used to provide analysis like any other
analysis module, such as adding observables or details to an alert.

See QRadarAPIAnalysis for examples of how these classes can be inherited on multiple levels to implement many
different correlational queries.

"""

import datetime
import json
import logging
import re
import time
from typing import Optional, Type, Union

from pydantic import Field

from saq.analysis import Analysis, Observable
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.configuration import get_config
from saq.constants import AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.mapping import BaseObservableMapping
from saq.util import abs_path, create_timedelta

KEY_QUERY = 'query'
KEY_QUERY_RESULTS = 'query_results'
KEY_QUERY_ERROR = 'query_error'
KEY_QUERY_SUMMARY = 'query_summary'
KEY_QUERY_START = 'query_start'
KEY_QUESTION = 'question'
KEY_GUI_LINK = 'gui_link'


class APIObservableMapping(BaseObservableMapping):
    """Observable mapping configuration for API analyzers.

    Supports mapping query result fields to observables with optional tags, directives,
    and display settings.

    Example configuration:
        observable_mapping:
          - field: src_ip
            type: ipv4
            tags:
              - external
              - suspicious
            directives:
              - analyze_ip
            time: true

          - fields: [user, username]
            type: user
            tags:
              - from_splunk
    """
    pass


class BaseAPIAnalyzerConfig(AnalysisModuleConfig):
    question: str = Field(..., description="The question to use for the analysis.")
    summary: str = Field(..., description="The summary to use for the analysis.")
    api_name: str = Field(..., description="The name of the API config to use for the analysis.")
    query: Optional[str] = Field(default=None, description="The query to use for the analysis.")
    query_path: Optional[str] = Field(default=None, description="The path to the query file to use for the analysis.")
    wide_duration_before: Optional[str] = Field(default=None, description="The wide duration before the analysis.")
    wide_duration_after: Optional[str] = Field(default=None, description="The wide duration after the analysis.")
    narrow_duration_before: Optional[str] = Field(default=None, description="The narrow duration before the analysis.")
    narrow_duration_after: Optional[str] = Field(default=None, description="The narrow duration after the analysis.")
    observable_mapping: list[APIObservableMapping] = Field(
        default_factory=list,
        description="Observable mapping configuration with support for tags, directives, and display settings."
    )
    correlation_delay: Optional[str] = Field(default=None, description="The correlation delay for the analysis.")
    max_result_count: Optional[int] = Field(default=None, description="The max result count for the analysis.")
    query_timeout: Optional[int] = Field(default=None, description="The query timeout for the analysis.")
    async_delay: Optional[int] = Field(default=None, description="The async delay for the analysis.")

class AnalysisDelay(Exception):
    pass

class BaseAPIAnalysis(Analysis):
    """Base APIAnalysis class with built-in details based on query success/failure.

       This class should be overridden for each child class, however it is unlikely
       that much, if anything should be changed.

       Attributes:
           details: A dict containing all class properties.
       Properties:
           query: A string containing the query that was executed.
           query_results: A string containing the result of the query if successful
           query_error: A string containing the error message returned, if there was one
           query_summary: A string containing the summary configuration item for this query.
           question: A string containing question configuration item for this query
       """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
                KEY_QUERY:         None,
                KEY_QUERY_RESULTS: None,
                KEY_QUERY_ERROR:   None,
                KEY_QUESTION:      None,
                KEY_QUERY_SUMMARY: None,
                KEY_QUERY_START:   None,
                KEY_GUI_LINK:      None,
        }

    @property
    def jinja_template_path(self):
        return 'analysis/api_analysis.html'

    @property
    def query(self):
        """Returns the query query that was executed."""
        return self.details[KEY_QUERY]

    @query.setter
    def query(self, value):
        self.details[KEY_QUERY] = value

    @property
    def query_start(self):
        """Returns the time in seconds when the query started."""
        return self.details[KEY_QUERY_START]

    @query_start.setter
    def query_start(self, value):
        self.details[KEY_QUERY_START] = value

    @property
    def query_elapsed(self):
        return time.time() - self.query_start

    @property
    def query_results(self):
        """Returns the result of the query if successful."""
        return self.details[KEY_QUERY_RESULTS]

    @query_results.setter
    def query_results(self, value):
        self.details[KEY_QUERY_RESULTS] = value

    @property
    def query_error(self):
        """Returns the error message returned, if there was one."""
        return self.details[KEY_QUERY_ERROR]

    @query_error.setter
    def query_error(self, value):
        self.details[KEY_QUERY_ERROR] = value

    @property
    def question(self):
        """Returns the question configuration item for this query."""
        return self.details[KEY_QUESTION]

    @question.setter
    def question(self, value):
        self.details[KEY_QUESTION] = value

    @property
    def query_summary(self):
        """Returns the summary configuration item for this query."""
        return self.details[KEY_QUERY_SUMMARY]

    @query_summary.setter
    def query_summary(self, value):
        self.details[KEY_QUERY_SUMMARY] = value

    def generate_summary(self):
        result = f'{self.query_summary}: '
        if self.query_error is not None:
            result += f'ERROR: {self.query_error}'
            return result
        elif self.query_results is not None:
            # 'events' is a common query key and used heavily for qradar, so we attempt to extract it here
            # (rather than in QradarAPIAnalyzer and only using length key)
            if 'events' in self.query_results:
                if len(self.query_results['events']) == 0:
                    return None

                result += f'({len(self.query_results["events"])} results)'
            else:
                if len(self.query_results) == 0:
                    return None
                else:
                    result += f'({len(self.query_results)} results)'
        else:
            result += f'{self.query_summary} (no results or error??)'

        return result



class BaseAPIAnalyzer(AnalysisModule):
    """Base APIAnalyzer class with built-in methods for building target query and result processing.

       This class should be overridden for each API module and requires a few methods to be implemented in
       order to use the built-in execute_analysis method.

       - __init__ ; need to set api_class var and any other class attributes; include super call
       - fill_target_query_timespec
       - execute_query
       - process_query_results

       Additional optional methods have been included for common use cases to promote "DRY-ness" across child classes.

       - process_field_mapping
       - process_finalize

       That said, there are many liberties that can be taken with these base classes, including adding many additional
       methods for result processing, which is encouraged as needed.

       Attributes (in addition to parent class attrs):
           api: str containing API instance to use, that will be used to lookup API configuration
           api_class: str containing the API class used to make queries (used in execute_query)
           target_query_base: str containing the base query that will be made
           target_query: str containing the built query that will be made
           multi_values_base: list of the multiple value placeholders in target_query_base that need to be replaced
           multi_values: list of the actual values to use when replacing the value placeholders in target_query_base
           wide_duration_before: timedelta of how long to query for before an alert occurred
           wide_duration_after: timedelta of how long to query for after an alert occurred
           narrow_duration_before: timedelta of how long to query for before an observable 'occurred'
           narrow_duration_after: timedelta of how long to query for after an observable 'occurred'
           observable_mapping: dict that maps query result fields to observable types based on configuration
           correlation_delay: (optional) timedelta that allows a delay on correlation for slower APIs (cough QRadar)
           max_result_count: (optional) int containing max number of query results to pull for
           query_timeout: (query_ int containing number of timeouts to allow before failing analysis

       """

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return BaseAPIAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # base tool / api config that this analyzer should use
        # will be used for setting timeframes/credentials/etc.
        # ex. QRadarAPIAnalyzer = 'qradar'
        # SplunkAPIAnalyzer = 'splunk' or 'splunkx'
        self.api_defaults = get_config().get_api_query_defaults_config(self.config.api_name)
        self.api = self.config.api_name  # Used in logging statements

        # load the query query for this instance
        if self.config.query is not None:
            self.target_query_base = self.config.query
        elif self.config.query_path is not None:
            with open(abs_path(self.config.query_path), 'r') as fp:
                self.target_query_base = fp.read()
        else:
            raise RuntimeError(f"module {self} missing query or query_path settings in configuration")

        self.target_query = self.target_query_base

        # Flag for if this query should be interpreted as JSON (such as with Elasticsearch)
        self.json_query = False

        # Check to see if the base query has multiple values that need to be substituted
        self.multi_values_base = sorted(set(re.findall(r'(<O_VALUE\d+>)', self.target_query_base)))

        # If the query needs to search for multiple unique values, the analysis module extending this class
        # needs to set the values in this list. They will be substituted in order, so the first item in this list
        # will be substituted for <O_VALUE1>, the second item will become <O_VALUE2>, and so on.
        self.multi_values = []

        # each query can specify it's own range
        # the wide range is used if the observable does not have a time
        if self.config.wide_duration_before is not None:
            self.wide_duration_before = create_timedelta(self.config.wide_duration_before)
        else:
            self.wide_duration_before = create_timedelta(self.api_defaults.wide_duration_before)

        if self.config.wide_duration_after is not None:
            self.wide_duration_after = create_timedelta(self.config.wide_duration_after)
        else:
            self.wide_duration_after = create_timedelta(self.api_defaults.wide_duration_after)

        # the narrow range is used if the observable has a time
        if self.config.narrow_duration_before is not None:
            self.narrow_duration_before = create_timedelta(self.config.narrow_duration_before)
        else:
            self.narrow_duration_before = create_timedelta(self.api_defaults.narrow_duration_before)

        if self.config.narrow_duration_after is not None:
            self.narrow_duration_after = create_timedelta(self.config.narrow_duration_after)
        else:
            self.narrow_duration_after = create_timedelta(self.api_defaults.narrow_duration_after)

        # observable mappings are now stored directly from config as list[APIObservableMapping]
        # the config type handles validation via Pydantic

        # are we delaying correlational queries?
        self.correlation_delay = None
        if self.config.correlation_delay is not None:
            self.correlation_delay = create_timedelta(self.config.correlation_delay)

        self.max_result_count = self.config.max_result_count
        if self.max_result_count is None:
            self.max_result_count = self.api_defaults.max_result_count

        if self.config.query_timeout is not None:
            self.query_timeout = self.config.query_timeout
        else:
            self.query_timeout = self.api_defaults.query_timeout

        if self.config.async_delay is not None:
            self.async_delay_seconds = self.config.async_delay
        else:
            self.async_delay_seconds = self.api_defaults.async_delay

    def verify_environment(self):
        if self.config.query is None and self.config.query_path is None:
            raise RuntimeError(f"module {self} missing query or query_path settings in configuration")
        if self.config.query_path is not None:
            self.verify_path_exists(abs_path(self.config.query_path))

    def generated_analysis_type(self):
        return BaseAPIAnalysis

    def _escape_value(self, value: str) -> str:
        """Escapes common problem characters."""
        return value

    def build_target_query(self, observable: Observable, **kwargs) -> None:
        """Fills in the target_query attribute with observable value and time specification for correlation, using the target_query_base
        attribute to build from.

        Analysis modules extending this class that need to search for multiple unique values in a single query should
        override this method to insert the values it needs to search for into the self.multi_values list. The method
        should finish by calling: super().build_target_query(observable, **kwargs)

            Args:
                observable: observable that is being analyzed.
                **kwargs: additional variables used for unit testing.
        """

        # support legacy attribute accessors
        self.target_query = self.target_query_base.replace('<O_TYPE>', observable.type)
        self.target_query = self.target_query.replace('<O_VALUE>', self._escape_value(observable.value))

        # new generic attribute accessor
        self.target_query = re.sub(r'<observable\.([^>]+)>', lambda x: self._escape_value(getattr(observable, x.group(1))), self.target_query)

        # Make sure the same number of values in the base query exist in the list of values given by the analysis module
        if len(self.multi_values_base) != len(self.multi_values):
            raise ValueError(f'{self.name} has mismatched number of values: {self.multi_values_base} {self.multi_values}')

        # Replace each base value placeholder with its corresponding value
        for i in range(len(self.multi_values_base)):
            self.target_query = self.target_query.replace(self.multi_values_base[i], self._escape_value(self.multi_values[i]))

        source_time = kwargs.get('source_event_time') or observable.time or self.get_root().event_time
        if source_time is None:
            source_time = datetime.datetime.now()
            logging.error("Analysis event_time is None! Using current time for analysis instead")

        # if we are going off of the event time, then we use the wide duration
        start_time = source_time - self.wide_duration_before
        stop_time = source_time + self.wide_duration_after

        # if observable time is available, we can narrow our time spec duration
        if observable.time is not None:
            start_time = source_time - self.narrow_duration_before
            stop_time = source_time + self.narrow_duration_after

        # Fill out the start/end times in the query
        self.fill_target_query_timespec(start_time, stop_time)

        # Convert the query to JSON if we're supposed to (such as for Elasticsearch)
        if self.json_query:
            try:
                self.target_query = json.loads(self.target_query)
            except:
                raise ValueError(f"{self.name} query is not valid JSON: {self.target_query}")

    def _apply_mapping_properties(self, new_observable, mapping: APIObservableMapping) -> None:
        """Apply tags, directives, and display settings from a mapping to an observable."""
        if new_observable is None:
            return

        for tag in mapping.tags:
            new_observable.add_tag(tag)

        for directive in mapping.directives:
            new_observable.add_directive(directive)

        if mapping.display_type is not None:
            new_observable.display_type = mapping.display_type
        if mapping.display_value is not None:
            new_observable.display_value = mapping.display_value

    def extract_result_observables(self, analysis, result: dict, observable: Observable = None, result_time: Union[str, datetime.datetime] =
                                        None) -> None:
        """ Cycle through observable mappings and extract observables from query results.

            Processes each configured observable mapping, checking the specified field(s) in the result.
            For mappings with multiple fields:
              - fields_mode='all' (default): all fields must be present; first field's value is used.
              - fields_mode='any': each present field creates a separate observable.
            Applies configured tags, directives, and display settings to created observables.

            Args:
                analysis: the respective Analysis object to which we are adding observables.
                observable: (optional) the Observable object contain the observable we're currently analyzing
                result: a dict that contains an individual query result, ex. one QRadar or Splunk event.
                result_time: (optional) str or datetime.datetime that contains the datetime of query result

        """
        for mapping in self.config.observable_mapping:
            obs_time = result_time if mapping.time else None

            for field_group in mapping.resolve_fields(lambda f: f in result and result[f] is not None):
                # Use the first field in the group for the observable value
                matched_field = field_group[0]
                field_value = result[matched_field]

                if mapping.ignored_values and mapping.is_ignored_value(str(field_value)):
                    continue

                value = self.filter_observable_value(matched_field, mapping.type, field_value)
                new_observable = analysis.add_observable_by_spec(mapping.type, value, o_time=obs_time)
                self._apply_mapping_properties(new_observable, mapping)
                self.process_field_mapping(analysis, new_observable, result, matched_field, result_time)

    def filter_observable_value(self, result_field, observable_type, observable_value):
        """Called for each observable value added to analysis.
           Returns the observable value to add to the analysis.
           By default, the observable_value is returned as-is."""
        return observable_value

    def fill_target_query_timespec(self, start_time: Union[str, datetime.datetime], stop_time: Union[str, datetime.datetime]) -> None:
        """ Fills in query time specification dummy strings, such as <O_START> and <O_STOP> or <O_TIME>

            Adjusts the timezone and formatting of start_time and stop_time variables initialized in build_target_query as needed
            and replaces the dummy variables in configured query.

            Args:
                start_time: A string or datetime object that contains the 'start_time' of the query,
                            or the time AFTER which we should be searching for results.
                stop_time: A string or datetime object that contains the 'stop_time' of the query,
                            or the time BEFORE which we should be searching for results.
        """
        pass

    def execute_query(self) -> Union[dict, list]:
        """Handles execution of constructed target_query and return of said query results (or error).

            Handles initializing API client with credentials, executing the query, and procuring and returning the results, which may
            be a list of results or JSON-style dict

            Returns:
                dict or list: query results returned from API query
            Raises:
                Exception: in the case that a query fails for some reason
        """
        pass

    def process_query_results(self, query_results: Union[dict, list], analysis, observable: Observable) -> None:
        """Process the query results returned from execute_query.

            Suggestions for use here would be iterating through query results in order to build analysis results,
            add observables (use extract_result_observables if you have a mapping, etc.

            Args:
                query_results: A dict or list of all results returned from API query
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analyzing
        """
        pass

    def process_field_mapping(self, analysis, observable: Observable, result, result_field, result_time=None) -> None:
        """(Optional) Called each time an observable is created from the observable-field mapping.

            The idea of this method is to perform any additional processing when an observable is extracted based off of a field
            mapping. Example use cases: Adding detection points/directives/tags/etc. to current observable, or adding additional
            observables based on extraction.

            See FireEyeQRadarAPIAnalyzer.process_field_mapping for another example.

            Args:
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analyzing
                result: The result object from which we created an observable from observable-field mapping
                result_field: The result field extracted from the observable-field mapping
                result_time: An optional field that contains the time of the result
        """
        pass

    def process_finalize(self, analysis, observable: Observable) -> None:
        """(Optional) Called after all individual query results have completed processing.

            The idea of this method is to perform any additional processing using the query results holistically.
            Example use cases: Adding additional observables based on general query results, rather than specific observable-field
            mappings, as in process_field_mapping. This might involve creating observables from query-specific analysis attributes.

            See FireEyePostfixQueueIDAnalyzer.process_finalize for another example.

            Args:
                analysis: The respective Analysis object to which we are adding analysis/observables
                observable: An Observable object containing the observable we are currently analyzing
        """
        pass

    def execute_analysis(self, observable, **kwargs) -> AnalysisExecutionResult:
        """Analysis module execution. See base class for more information.

            In order for this method to run as expected, all required methods must be implemented in child classes
            (see BaseAPIAnalyzer docstring).

            This method may be overridden if analysis 'flow' must be drastically different (ex. executing and correlating using multiple
            queries or even multiple APIs). However, most complex query processing can be handled without overriding this method by
            adding additional methods to be called from process_query_results.

            For an example, see QRadarAPIAnalyzer.process_qradar_event

            Args:
                observable: An Observable object containing the observable we are currently analyzing
                **kwargs: Arbitrary named arguments used for unit/integration testing.

            Returns:
                AnalysisExecutionResult: success/failure of Analysis
                Analysis: used for unit testing to check what analysis was created
        """
        analysis = self.create_analysis(observable)
        analysis.query_start = time.time()
        analysis.question = self.config.question
        analysis.query_summary = self.config.summary

        if self.correlation_delay is not None:
            return self.delay_analysis(observable, analysis, seconds=self.correlation_delay.total_seconds())

        return self.continue_analysis(observable, analysis, **kwargs)

    def continue_analysis(self, observable: Observable, analysis: Analysis, **kwargs) -> AnalysisExecutionResult:
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        # expose analysis to child class methods
        self.analysis = analysis

        # only build the query once
        if analysis.query is None:
            self.build_target_query(observable)
            analysis.query = self.target_query
        else:
            self.target_query = analysis.query

        logging.debug(f'Executing {self.api} query: {self.target_query}')
        try:
            analysis.query_results = self.execute_query()

        except AnalysisDelay:
            # delay if not timed out
            if analysis.query_elapsed < self.query_timeout: 
                return self.delay_analysis(observable, analysis, seconds=self.async_delay_seconds)

            # warn if timed out
            logging.warning(f'{self.api} query timed out: {self.target_query}')
            analysis.query_results = None
            analysis.query_error = 'timed out'

        except Exception as e:
            logging.error(f'Error when executing {self.api} query: {e}')
            analysis.query_results = None
            analysis.query_error = str(e)

        if analysis.query_results is None:
            return AnalysisExecutionResult.COMPLETED

        logging.debug('Processing query results')
        self.process_query_results(analysis.query_results, analysis, observable)
        self.process_finalize(analysis, observable)
        logging.info(f'{self.name} took {analysis.query_elapsed:.2f} seconds')

        if kwargs.get('return_analysis'):
            return analysis

        return AnalysisExecutionResult.COMPLETED

class BaseAPIAnalysisPresenter(AnalysisPresenter):
    """Presenter for BaseAPIAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/api_analysis.html"

register_analysis_presenter(BaseAPIAnalysis, BaseAPIAnalysisPresenter)
