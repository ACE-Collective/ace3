# vim: sw=4:ts=4:et:cc=120
#
# ACE Splunk Hunting System
#

import datetime
import re
import logging
import os
import os.path
import threading
from typing import Optional

from pydantic import Field
import pytz
from splunklib.results import Message

from saq.collectors.hunter.loader import load_from_yaml
from saq.configuration.config import get_config
from saq.error.remote import RemoteApiError
from saq.splunk import extract_event_timestamp, SplunkClient
from saq.collectors.hunter.query_hunter import QueryHunt, QueryHuntConfig
from saq.constants import TIMESPEC_TOKEN
from saq.util import create_timedelta

TIMESPEC_PATTERN = re.compile(r'<(TIMESPEC\w*)>')

class SplunkHuntConfig(QueryHuntConfig):
    splunk_config: str = Field(default="default", description="The name of the splunk config to use for the hunt")
    namespace_user: Optional[str] = Field(alias="splunk_user_context", default=None, description="The namespace user to use for the hunt")
    namespace_app: Optional[str] = Field(alias="splunk_app_context", default=None, description="The namespace app to use for the hunt")
    # splunk requires | fields * to actually return all of the fields in the results
    # so by default we append this to every splunk query
    # you can override this by setting the auto_append field in the hunt config
    auto_append: str = Field(default="| fields *", description="The string to append to the query after the time spec. By default this is | fields *")

class SplunkHunt(QueryHunt):

    config: SplunkHuntConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.cancel_event = threading.Event()

        self.splunk_config = get_config().get_splunk_config(self.config.splunk_config)
        self.tool_instance = self.splunk_config.host
        self.timezone = self.splunk_config.timezone

        self.job = None

    @property
    def namespace_user(self) -> Optional[str]:
        return self.config.namespace_user

    @property
    def namespace_app(self) -> Optional[str]:
        return self.config.namespace_app

    @property
    def query(self) -> str:
        result = super().query

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
        result = self.query
        if not result.endswith(self.config.auto_append):
            result += ' ' + self.config.auto_append

        return result

    def formatted_query_timeless(self):
        result = self.query
        if not result.endswith(self.config.auto_append):
            result += self.config.auto_append

        return result

    def extract_event_timestamp(self, event):
        return extract_event_timestamp(event)

    def load_hunt_config(self, path: str) -> tuple[SplunkHuntConfig, set[str]]:
        return load_from_yaml(path, SplunkHuntConfig)

    def execute_query(self, start_time: datetime.datetime, end_time: datetime.datetime, unit_test_query_results=None, **kwargs) -> Optional[list[dict]]:
        tz = pytz.timezone(self.timezone)

        query = self.formatted_query()

        logging.info(f"executing hunt {self.name} with start time {start_time} end time {end_time}")
        logging.debug(f"executing hunt {self.name} with query {query}")

        # nooooo
        if unit_test_query_results is not None:
            return unit_test_query_results

        # init splunk
        searcher = SplunkClient(self.splunk_config.name, user_context=self.namespace_user, app=self.namespace_app)

        # detect TIMESPEC tokens in the query
        timespec_tokens = set(TIMESPEC_PATTERN.findall(query))

        if timespec_tokens:
            # Build time range map from explicit time_ranges config
            time_range_map = {}
            if self.config.time_ranges:
                for token_name, tr_config in self.config.time_ranges.items():
                    duration = create_timedelta(tr_config.duration_before)
                    time_range_map[token_name] = (end_time - duration, end_time)

            # Backward compat: if TIMESPEC is in query but not in time_ranges, derive from hunt's start/end
            if TIMESPEC_TOKEN in timespec_tokens and TIMESPEC_TOKEN not in time_range_map:
                time_range_map[TIMESPEC_TOKEN] = (start_time, end_time)

            # Error if any token in query has no config
            for token in timespec_tokens:
                if token not in time_range_map:
                    raise ValueError(f"hunt {self.name}: query contains <{token}> but no time range configured for it")

            # Replace tokens
            prefix = "_index_" if self.use_index_time else ""
            for token_name, (ts_start, ts_end) in time_range_map.items():
                earliest = ts_start.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
                latest = ts_end.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
                time_spec = f'{prefix}earliest={earliest} {prefix}latest={latest}'
                query = query.replace(f'<{token_name}>', time_spec)

            # Widest range for search_kwargs
            search_start = min(tr[0] for tr in time_range_map.values())
            search_end = max(tr[1] for tr in time_range_map.values())
            embed_time_in_query = False
        else:
            search_start = start_time
            search_end = end_time
            embed_time_in_query = True

        self.search_link = searcher.encoded_query_link(
            self.formatted_query_timeless(),
            search_start.astimezone(tz), search_end.astimezone(tz),
            use_index_time=self.use_index_time)

        # reset search_id before searching so we don't get previous run results
        self.job = None

        while True:
            self.job, search_result = searcher.query_async(
                query, job=self.job, limit=self.max_result_count,
                start=search_start.astimezone(tz), end=search_end.astimezone(tz),
                use_index_time=self.use_index_time, timeout=self.query_timeout,
                embed_time_in_query=embed_time_in_query)

            if search_result is not None:
                return self._filter_messages(search_result)

            if searcher.search_failed():
                logging.warning(f"splunk search {self} failed")
                searcher.cancel(self.job)
                raise RemoteApiError(500, f"Splunk search for {self.name} reported as failed")

            if self.cancel_event.wait(3):
                searcher.cancel(self.job)
                return None

    @staticmethod
    def _filter_messages(search_result):
        """Filter out Splunk Message objects from search results."""
        final_result = []
        for result in search_result:
            if isinstance(result, Message):
                logging.info(f"Splunk returned a message for this search: {result}")
                continue
            final_result.append(result)
        return final_result

    def cancel(self):
        self.cancel_event.set()
