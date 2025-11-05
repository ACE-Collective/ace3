# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - query based hunting
#

import json
import logging
import os
import os.path
import re

from typing import Optional

from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis, Submission
from saq.configuration import get_config_value, get_config_value_as_int
from saq.constants import CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_MAX_RESULT_COUNT, CONFIG_QUERY_HUNTER_QUERY_TIMEOUT, F_FILE, F_HUNT, G_TEMP_DIR
from saq.environment import g
from saq.observables.generator import create_observable

import pytz

from saq.collectors.hunter import Hunt, write_persistence_data, read_persistence_data
from saq.util import local_time, create_timedelta, abs_path

COMMENT_REGEX = re.compile(r'^\s*#.*?$', re.M)

def _compute_directive_value(field_name: str, directives: dict[str, list[str]], event: Optional[dict]=None) -> str:
    """Returns the value for the directive for this field.
    If an optional event dict is passed, that is used to format the field value.
    This also {}-based event field interpolation into the directive value."""
    if field_name not in directives:
        return []

    if event is None:
        return directives[field_name]
    else:
        result = []
        for directive in directives[field_name]:
            try:
                result.append(directive.format(**event))
            except KeyError:
                logging.warning(f"directive {directive} not added -- missing key in event")
                pass

        return result

class QueryHunt(Hunt):
    """Abstract class that represents a hunt against a search system that queries data over a time range."""

    def __init__(self, time_range=None,
                       max_time_range=None,
                       full_coverage=None,
                       offset=None,
                       group_by=None,
                       search_query_path=None,
                       query=None,
                       observable_mapping=None,
                       temporal_fields=None,
                       directives=None,
                       directive_options=None,
                       strip_comments=False,
                       max_result_count=None,
                       query_result_file=None,
                       search_id=None,
                       search_link=None,
                       tag_mapping=None,
                       *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the range of time we run this query over
        self.time_range = time_range # datetime.timedetala

        # for full coverage type of hunting
        # in the case where hunting falls behind and the time to cover is greater than the time range
        # this is the maximum time range that can be used for each execution as the hunting attempts to catch up
        self.max_time_range = max_time_range

        # if this is set to True then we ensure full coverage of time by starting each query
        # and the end of the last query
        self.full_coverage = full_coverage

        # an optional offset to run the query at
        # this is useful for log entries that come in late
        self.offset = offset

        self.group_by = group_by
        self.search_query_path = search_query_path
        self.query = query
        self.observable_mapping = observable_mapping # key = field, value = observable type
        self.tag_mapping = tag_mapping # key = field, value = [tags]
        self.temporal_fields = temporal_fields # of fields
        self.directives = directives # key = field, value = [ directive ]
        self.directive_options = directive_options # key = field, value = { key = option_name value = option_value }

        # if this is set to True then hash-style comments are stripped from the loaded query
        self.strip_comments = strip_comments

        # maximum number of results we want back from the query 
        self.max_result_count = max_result_count

        # debugging utility to save the results of the query to a file
        self.query_result_file = query_result_file

        # allows hyperlink to search results
        self.search_id = search_id
        # might need to url_encode the link instead, store that here
        self.search_link = search_link

        # when the query is loaded from a file this trackes the last time the file was modified
        self.query_last_mtime = None

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
                    if now - (self.last_end_time + self.time_range) >= self.time_range:
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

    def load_query_from_file(self, path):
        with open(abs_path(self.search_query_path), 'r') as fp:
            result = fp.read()

            if self.strip_comments:
                result = COMMENT_REGEX.sub('', result)

        return result
    
    def load_from_yaml(self, path: str, *args, **kwargs) -> dict:
        config = super().load_from_yaml(path, *args, **kwargs)

        rule_section = config['rule']
        
        # if we don't specify a time range then it defaults to whatever the frequency is
        self.time_range = rule_section.get('time_range')
        if self.time_range is None:
            self.time_range = self.frequency
        else:
            self.time_range = create_timedelta(self.time_range)

        self.max_time_range = rule_section.get('max_time_range')
        if self.max_time_range is not None:
            self.max_time_range = create_timedelta(self.max_time_range)

        self.full_coverage = rule_section.get('full_coverage', False)
        self.group_by = rule_section.get('group_by')
        self.use_index_time = rule_section.get('use_index_time', False)

        self.max_result_count =  rule_section.get('max_result_count',
                                                   get_config_value_as_int(CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_MAX_RESULT_COUNT))
        if self.max_result_count is not None and not isinstance(self.max_result_count, int):
            self.max_result_count = int(self.max_result_count)

        self.query_timeout = rule_section.get('query_timeout',
                                              get_config_value(CONFIG_QUERY_HUNTER, CONFIG_QUERY_HUNTER_QUERY_TIMEOUT))

        if 'offset' in rule_section:
            self.offset = create_timedelta(rule_section['offset'])

        observable_mapping_section = config['observable_mapping']
        
        self.observable_mapping = {}
        for key, value in observable_mapping_section.items():

            # TODO revisit this, we can support encoded file content
            if value == F_FILE:
                mapping = f'{rule_section["type"]}.{rule_section["name"]}.{key} = {value}'
                logging.error(f'Invalid observable mapping: {mapping} - did you mean to user file_name?')
                continue

            self.observable_mapping[key] = value

        self.tag_mapping = rule_section.get('tag_mapping', {})
        #if 'tag_mapping' in config:
            #tag_mapping_section = config['tag_mapping']
            #self.tag_mapping = {}
            #for key, value in tag_mapping_section.items():
                #self.tag_mapping[key] = [_.strip() for _ in value.split(",")]

        temporal_fields_section = config.get('temporal_fields', {})
        self.temporal_fields = temporal_fields_section if temporal_fields_section is not None else {}
        #for key in temporal_fields_section.keys():
            #self.temporal_fields[key] = temporal_fields_section.getboolean(key)

        directives_section = config['directives']
    
        self.directives = {}
        self.directive_options = {}

        for key, value in directives_section.items():
            self.directives[key] = []
            directives = [_.strip() for _ in value.split(',')]
            for directive in directives:
                # does this directive have any options? these are : delimited
                if ':' in directive:
                    options = directive.split(':')
                    directive = options.pop(0)
                    self.directive_options[directive] = {}
                    for option in options:
                        # option_name=option_value
                        option_name, option_value = option.split('=', 1)
                        self.directive_options[key][option_name] = option_value
                
                #if directive not in VALID_DIRECTIVES:
                    #raise ValueError(f"invalid directive {directive}")

                self.directives[key].append(directive)

        # search or search_query_path load the search from a file
        if 'search' not in rule_section and 'query' not in rule_section:
            raise KeyError(f"missing search or query in {path}")

        self.search_query_path = rule_section.get('search')
        self.query = rule_section.get('query')

        if self.search_query_path is not None and self.query is not None:
            raise ValueError(f"both search and query are specified for {path} (only need one)")

        if self.search_query_path:
            self.query = self.load_query_from_file(self.search_query_path)
            self.query_last_mtime = os.path.getmtime(self.search_query_path)

        return config

    @property
    def is_modified(self):
        return self.yaml_is_modified or self.query_is_modified

    @property
    def query_is_modified(self):
        """Returns True if this query was loaded from file and that file has been modified since we loaded it."""
        if self.search_query_path is None:
            return False

        try:
            return self.query_last_mtime != os.path.getmtime(self.search_query_path)
        except FileNotFoundError:
            return True
        except Exception as e:
            logging.error(f"unable to check last modified time of {self.search_query_path}: {e}")
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

            if self.query_result_file is not None:
                with open(self.query_result_file, 'w') as fp:
                    json.dump(query_result, fp)

                logging.info(f"saved results to {self.query_result_file}")

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

    def create_root_analysis(self) -> RootAnalysis:
        import uuid as uuidlib
        root_uuid = str(uuidlib.uuid4())
        root = RootAnalysis(
                            uuid=root_uuid,
                            storage_dir=os.path.join(g(G_TEMP_DIR), root_uuid),
                            desc=self.name,
                            analysis_mode=self.analysis_mode,
                            tool=f'hunter-{self.type}',
                            tool_instance=self.tool_instance,
                            alert_type=self.alert_type,
                            details=[{'search_id': self.search_id if self.search_id else None,
                                    'search_link': self.search_link if self.search_link else None,
                                    'query': self.formatted_query()}],
                            event_time=None,
                            queue=self.queue,
                            instructions=self.description,
                            extensions={ "playbook_url": self.playbook_url })

        root.initialize_storage()

        for tag in self.tags:
            root.add_tag(tag)

        return root

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        submissions = [] # of Submission objects

        def _create_submission():
            return Submission(self.create_root_analysis())

        event_grouping = {} # key = self.group_by field value, value = Submission

        # this is used when grouping is specified but some events don't have that field
        missing_group = None

        # map results to observables
        for event in query_results:
            observable_time = None
            event_time = self.extract_event_timestamp(event) or local_time()
            event = self.wrap_event(event)

            # pull the observables out of this event
            observables: list[Observable] = []
            if self.name:
                observables.append(create_observable(F_HUNT, self.name))

            for field_name, mapped_observable_type in self.observable_mapping.items():
                if field_name in event and event[field_name] is not None:
                    query_observable_value = event[field_name]

                    # Set an initial observable type, which might get overwritten below
                    observable_type = mapped_observable_type

                    # Some of the hunts (particularly the observable detection) might return a list of values in the given field
                    # instead of a string. If we get a string back, we can add it to a list so that we can process these two use cases
                    # the same regardless of which type the hunt returned.
                    if isinstance(query_observable_value, str):
                        query_observable_values = [query_observable_value]
                    elif isinstance(query_observable_value, list):
                        query_observable_values = query_observable_value
                    else:
                        query_observable_values = []
                        logging.error(f'got unknown observable_value from splunk: {query_observable_value}')

                    for query_observable_value in query_observable_values:
                        # Set an initial observable value, which might get overwritten below
                        observable_value = query_observable_value

                        # With Splunk KVStore, it's possible that a returned field maps to an observable already in the DB
                        # We need to pull out the value of the observable for that ID (can't use the splunk value bc the formatting is wrong)
                        #if mapped_observable_type == 'observable_id':
                            # Get observables from kwargs if testing... this should be a dictionary where the observable ID is the key,
                            # and the value is the test observable.
                            #if 'mock_db_observables' in kwargs:
                                #observable = kwargs.get('mock_db_observables').get(query_observable_value)

                            # Otherwise query for the observable ID in the database
                            #else:
                            #observable = get_db().query(db_Observable).get(query_observable_value)

                            # If one was found, override the type and value with what is in the database
                            #if observable:
                                #logging.debug(f'found observable {query_observable_value} in database matching the query hunter hit')
                                #observable_value = observable.value
                                #observable_type = observable.type

                        # if a hunter returns bytes-like data, convert it before submission
                        try:
                            if isinstance(observable_value, bytes):
                                observable_value = observable_value.decode()
                        except (UnicodeDecodeError, AttributeError):
                            pass

                        observable = create_observable(observable_type, observable_value)
                        #observable = {'type': observable_type,
                                      #'value': observable_value}

                        if field_name in self.directives:
                            for directive in _compute_directive_value(field_name, self.directives, event=event):
                                observable.add_directive(directive)
                            #observable['directives'] = _compute_directive_value(field_name, self.directives, event=event)

                        if field_name in self.temporal_fields:
                            #observable['time'] = event_time
                            observable.time = event_time

                        if self.tag_mapping:
                            if field_name in self.tag_mapping:
                                for tag in self.tag_mapping[field_name]:
                                    observable.add_tag(tag)
                                #observable['tags'] = self.tag_mapping[field_name]

                        if observable not in observables:
                            observables.append(observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission()
                submission.root.event_time = event_time
                for observable in observables:
                    submission.root.add_observable(observable)

                #submission.observables = observables
                submission.root.details.append(event)
                submissions.append(submission)

            # if we are grouping but the field we're grouping by is missing
            # XXX this branch would never execute
            elif self.group_by != "ALL" and self.group_by not in event:
                if missing_group is None:
                    missing_group = _create_submission()
                    submissions.append(missing_group)


                for observable in observables:
                    if observable not in missing_group.observables:
                        missing_group.root.add_observable(observable)

                #missing_group.observables.extend([_ for _ in observables if _ not in missing_group.observables])
                missing_group.root.details.append(event)

                # see below about grouped events and event_time
                if missing_group.root.event_time is None:
                    missing_group.root.event_time = event_time
                elif event_time < missing_group.event_time:
                    missing_group.root.event_time = event_time

            # if we are grouping then we start pulling all the data into groups
            else:
                # if we're grouping all results together then there's only a single group
                grouping_targets = ["ALL" if self.group_by == "ALL" else event[self.group_by]]
                if self.group_by != "ALL":
                    if isinstance(event[self.group_by], list):
                        grouping_targets = event[self.group_by]

                for grouping_target in grouping_targets:
                    if grouping_target not in event_grouping:
                        event_grouping[grouping_target] = _create_submission()
                        if grouping_target != "ALL":
                            event_grouping[grouping_target].root.description += f': {grouping_target}'
                        submissions.append(event_grouping[grouping_target])

                    for observable in observables:
                        if observable not in event_grouping[grouping_target].root.observables:
                            event_grouping[grouping_target].root.add_observable(observable)

                    #event_grouping[grouping_target].observables.extend([_ for _ in observables if _ not in
                                                                            #event_grouping[grouping_target].observables])
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
                submission.root.description += f' ({len(submission.root.details) - 1} events)'

        return submissions
