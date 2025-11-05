# vim: sw=4:ts=4:et:cc=120
#
# ACE Splunk Hunting System
#

import re
import logging
import os, os.path
import threading

import pytz

from saq.configuration import get_config_value
from saq.constants import CONFIG_SPLUNK_APP_CONTEXT, CONFIG_SPLUNK_TIMEZONE, CONFIG_SPLUNK_URI, CONFIG_SPLUNK_USER_CONTEXT
from saq.splunk import extract_event_timestamp, SplunkClient
from saq.collectors.query_hunter import QueryHunt

class SplunkHunt(QueryHunt):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_index_time = bool()

        self.cancel_event = threading.Event()

        # supports hash-style comments
        self.strip_comments = True

        # splunk queries can optionally have <include:> directives
        self._query = None
        self.search_id = None
        self.time_spec = None

        # since we have multiple splunk instances, allow config to point to a different one
        self.splunk_config = self.manager.config.get('splunk_config', 'splunk')
        
        self.tool_instance = get_config_value(self.splunk_config, CONFIG_SPLUNK_URI)
        self.timezone = get_config_value(self.splunk_config, CONFIG_SPLUNK_TIMEZONE)

        # splunk app/user context
        self.default_namespace_user = get_config_value(self.splunk_config, CONFIG_SPLUNK_USER_CONTEXT)
        self.default_namespace_app = get_config_value(self.splunk_config, CONFIG_SPLUNK_APP_CONTEXT)
        self.namespace_user = self.default_namespace_user
        self.namespace_app = self.default_namespace_app

    def extract_event_timestamp(self, event):
        return extract_event_timestamp(event)

    def formatted_query(self):
        return self.query.replace('{time_spec}', self.time_spec)

    def formatted_query_timeless(self):
        return self.query.replace('{time_spec}', '')

    @property
    def query(self):
        if self._query is None:
            return self._query

        result = self._query

        # run the includes you might have
        while True:
            m = re.search(r'<include:([^>]+)>', result)
            if not m:
                break
            
            include_path = m.group(1)
            if not os.path.exists(include_path):
                logging.error(f"rule {self.name} included file {include_path} does not exist")
                break
            else:
                with open(include_path, 'r') as fp:
                    included_text = re.sub(r'^\s*#.*$', '', fp.read().strip(), count=0, flags=re.MULTILINE)
                    result = result.replace(m.group(0), included_text)

        return result

    @query.setter
    def query(self, value):
        self._query = value
    
    def load_from_yaml(self, path: str, *args, **kwargs) -> dict:
        config = super().load_from_yaml(path, *args, **kwargs)

        section_rule = config['rule']

        # make sure the time spec formatter is available
        # this should really be done at load time...
        if '{time_spec}' not in self.query:
            # why I waited so long to do this, I don't know
            self.query = '{time_spec} ' + self.query

        # load user and app context
        self.namespace_user = section_rule.get('splunk_user_context')
        self.namespace_app = section_rule.get('splunk_app_context')

        if not self.namespace_user:
            self.namespace_user = self.default_namespace_user
        if not self.namespace_app:
            self.namespace_app = self.default_namespace_app

        return config

    def execute_query(self, start_time, end_time, unit_test_query_results=None, **kwargs):
        tz = pytz.timezone(self.timezone)

        earliest = start_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
        latest = end_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            self.time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            self.time_spec = f'earliest = {earliest} latest = {latest}'

        query = self.formatted_query()

        logging.info(f"executing hunt {self.name} with start time {earliest} end time {latest}")
        logging.debug(f"executing hunt {self.name} with query {query}")

        if unit_test_query_results is not None:
            return unit_test_query_results
        
        # init splunk
        searcher = SplunkClient(self.splunk_config, user_context=self.namespace_user, app=self.namespace_app)

        # set search link
        self.search_link = searcher.encoded_query_link(self.formatted_query_timeless(), start_time.astimezone(tz), end_time.astimezone(tz))

        # reset search_id before searching so we don't get previous run results
        self.search_id = None

        # calculate the time at which we should stop the query
        #timeout = time.time() + create_timedelta(self.query_timeout).total_seconds()

        while True:
            # continue the query
            self.search_id, search_result = searcher.query_async(query, sid=self.search_id, limit=self.max_result_count, start=start_time.astimezone(tz), end=end_time.astimezone(tz), use_index_time=self.use_index_time, timeout=self.query_timeout)

            # stop if we are done
            if search_result is not None:
                return search_result

            # stop if the search failed
            if searcher.search_failed():
                logging.warning("splunk search {self} failed")
                searcher.cancel(self.search_id)
                return None

            # wait a few seconds before checking again
            if self.cancel_event.wait(3):
                searcher.cancel(self.search_id)
                return None

    def cancel(self):
        self.cancel_event.set()
