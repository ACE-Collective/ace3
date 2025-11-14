# vim: sw=4:ts=4:et:cc=120
#
# ACE Splunk Hunting System
#

import re
import logging
import os
import os.path
import threading
from typing import Optional

from pydantic import Field
import pytz
import yaml

from saq.configuration import get_config_value
from saq.constants import CONFIG_SPLUNK, CONFIG_SPLUNK_APP_CONTEXT, CONFIG_SPLUNK_TIMEZONE, CONFIG_SPLUNK_URI, CONFIG_SPLUNK_USER_CONTEXT
from saq.splunk import extract_event_timestamp, SplunkClient
from saq.collectors.hunter.query_hunter import QueryHunt, QueryHuntConfig

class SplunkHuntConfig(QueryHuntConfig):
    namespace_user: Optional[str] = Field(alias="splunk_user_context", default_factory=lambda: get_config_value(CONFIG_SPLUNK, CONFIG_SPLUNK_USER_CONTEXT), description="The namespace user to use for the hunt")
    namespace_app: Optional[str] = Field(alias="splunk_app_context", default_factory=lambda: get_config_value(CONFIG_SPLUNK, CONFIG_SPLUNK_APP_CONTEXT), description="The namespace app to use for the hunt")


class SplunkHunt(QueryHunt):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.cancel_event = threading.Event()

        # the time spec we're using for the query
        self.time_spec: Optional[str] = None

        # since we have multiple splunk instances, allow config to point to a different one
        self.splunk_config = self.manager.config.get('splunk_config', 'splunk')
        
        self.tool_instance = get_config_value(self.splunk_config, CONFIG_SPLUNK_URI)
        self.timezone = get_config_value(self.splunk_config, CONFIG_SPLUNK_TIMEZONE)

    @property
    def namespace_user(self) -> Optional[str]:
        return self.config.namespace_user
    
    @property
    def namespace_app(self) -> Optional[str]:
        return self.config.namespace_app

    @property
    def query(self) -> str:
        # load the query normally first
        result = super().query

        # if the query doesn't have a time_spec, add it
        if '{time_spec}' not in result:
            result = '{time_spec} ' + result

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

    def formatted_query(self):
        return self.query.replace('{time_spec}', self.time_spec)

    def formatted_query_timeless(self):
        return self.query.replace('{time_spec}', '')

    def extract_event_timestamp(self, event):
        return extract_event_timestamp(event)

    def load_from_yaml(self, path: str) -> SplunkHuntConfig:
        with open(path, "r") as fp:
            config_dict = yaml.safe_load(fp)

        self.config = SplunkHuntConfig.model_validate(config_dict["rule"])
        return self.config

    def execute_query(self, start_time, end_time, unit_test_query_results=None, **kwargs):
        tz = pytz.timezone(self.timezone)

        earliest = start_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
        latest = end_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            self.time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            self.time_spec = f'earliest = {earliest} latest = {latest}'

        query = self.formatted_query()

        logging.info(f"executing hunt {self.name} with start time {start_time} end time {end_time} time spec {self.time_spec}")
        logging.debug(f"executing hunt {self.name} with query {query}")

        # nooooo
        if unit_test_query_results is not None:
            return unit_test_query_results
        
        # init splunk
        searcher = SplunkClient(self.splunk_config, user_context=self.namespace_user, app=self.namespace_app)

        # set search link
        self.search_link = searcher.encoded_query_link(self.formatted_query_timeless(), start_time.astimezone(tz), end_time.astimezone(tz))

        # reset search_id before searching so we don't get previous run results
        self.search_id = None

        while True:
            # continue the query (this call times out on its own if the query takes too long)
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
