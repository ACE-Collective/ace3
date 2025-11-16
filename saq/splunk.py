"""Splunk API Library"""
import csv
import logging
import os
import os.path
import time
import urllib.parse

from datetime import UTC, datetime
from requests.exceptions import HTTPError, Timeout, ProxyError, ConnectionError
from typing import Optional, Tuple, List

from splunklib.client import Job
import splunklib.client as client
from splunklib.results import JSONResultsReader

from saq.configuration import get_config
from saq.environment import get_data_dir
from saq.util import local_time, create_timedelta
from saq.error import report_exception
from saq.proxy import proxy_config

#
# NOTE: proxy support is missing
#

def extract_event_timestamp(event:dict) -> datetime:
    """Extracts the event time from the event as a datetime
    
    Args:
        event (dict): the event to extract the event time from

    Returns:
        datetime: the datetime of the _time field in the event
    """

    try:
        if '_time' in event:
            # XXX assume UTC
            return datetime.strptime(event['_time'][:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=UTC)
    except Exception as e:
        logging.error(f"_time field does not match expected format: {event['_time']}: {e}")
        report_exception()

    return local_time()


class SplunkQueryObject:
    """This is a wrapper around whatever Splunk API library we are using.
    This will eventually be replaced with direct Splunk SDK usage.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        proxies: Optional[dict] = None,
        user_context: Optional[str] = None,
        app: Optional[str] = None,
        dispatch_state: Optional[str]=None,
        start_time: Optional[datetime]=None,
        running_start_time: Optional[datetime]=None,
        end_time: Optional[datetime]=None,
        performance_logging_directory: Optional[str]=None,

    ):
        """
        Initializes a splunk api session

        Args:
            host (str): the splunk api host to use
            port (int): the splunk api port to use
            username (str, optional): the username for authentication (required if token is not provided)
            password (str, optional): the password for authentication (required if token is not provided)
            token (str, optional): the token for authentication (required if username and password are not provided)
            proxies (dict, optional): the proxy info used to connect to splunk api (default None -> no proxy)
            user_context (str): the user context for operations (default '-' -> any user)
            app (str): the app conext for operations (default '-' -> any app)
        """

        self.host = host
        self.port = port

        self.user_context = user_context
        self.app = app

        connect_kwargs = {
            "host": self.host,
            "port": self.port,
            "app": self.app,
            "owner": self.user_context,
            "autologin": True,
            "retries": 5,
            "retryDelay": 10,
        }

        if username:
            connect_kwargs["username"] = username
            connect_kwargs["password"] = password
        elif token:
            connect_kwargs["token"] = token
        else:
            raise ValueError("username and password or token must be provided")

        self.client = client.connect(**connect_kwargs)

        # determine gui search path from namespace app
        self.gui_path = 'en-US/app/search/search' if app is None or app == '-' else f'en-US/app/{app}/search'

        self.performance_logging_directory = performance_logging_directory

        self.reset_search_status(
            dispatch_state=dispatch_state, 
            start_time=start_time, 
            running_start_time=running_start_time, 
            end_time=end_time)

    def reset_search_status(
        self, 
        dispatch_state: Optional[str]=None, 
        start_time: Optional[datetime]=None, 
        running_start_time: Optional[datetime]=None, 
        end_time: Optional[datetime]=None):

        assert dispatch_state is None or isinstance(dispatch_state, str)
        assert start_time is None or isinstance(start_time, datetime)
        assert running_start_time is None or isinstance(running_start_time, datetime)
        assert end_time is None or isinstance(end_time, datetime)

        self.search_id = None
        self.is_done = None
        self.done_progress = None
        self._dispatch_state = dispatch_state
        self.is_failed = None
        self.event_count = None
        self.run_duration = None

        self.start_time = local_time() if start_time is None else start_time
        self.running_start_time = running_start_time
        self.end_time = end_time

    @property
    def dispatch_state(self):
        return self._dispatch_state

    @dispatch_state.setter
    def dispatch_state(self, value):
        if value == "RUNNING":
            if self.running_start_time is None:
                self.running_start_time = local_time()

        self._dispatch_state = value

    @property
    def wait_time(self):
        """Returns how long the search waited until it actually started, in seconds."""
        if self.running_start_time is None:
            if self.end_time is None:
                return (local_time() - self.start_time).total_seconds()
            else:
                return (self.end_time - self.start_time).total_seconds()

        return (self.running_start_time - self.start_time).total_seconds()

    @property
    def total_time(self):
        """Returns how long the search took in total, in seconds."""
        if not self.end_time:
            return (local_time() - self.start_time).total_seconds()
        else:
            return (self.end_time - self.start_time).total_seconds()
    
    @property
    def run_time(self):
        """Returns how long the search was in RUNNING state, in seconds."""
        if self.running_start_time is None:
            return None

        if not self.end_time:
            return (local_time() - self.running_start_time).total_seconds()

        return (self.end_time - self.running_start_time).total_seconds()

    def is_running(self) -> bool:
        return self.running_start_time is not None

    def search_failed(self) -> bool:
        return self.is_failed is not None and self.is_failed != "0"

    def encoded_query_link(self, query:str, start_time:Optional[datetime]=None, end_time:Optional[datetime]=None) -> str:
        """Returns a gui link for the query over the given time range

        Args:
            query (str): the query to convert to a gui link
            start_time (datetime, optional): the start time of the query (default None -> no start time)
            end_time (datetime, optional): the end time of the query (default None -> no end time)

        Returns:
            str: the gui link to the query over the given time range
        """
        # add search to start of query if missing
        if not query.lstrip().lower().startswith('search'):
            query = 'search ' + query

        # build params
        params = {'q': query}
        if start_time:
            params['earliest'] = int(time.mktime(start_time.timetuple()))
        if end_time:
            params['latest'] = int(time.mktime(end_time.timetuple()))

        # build link
        uri = (
            "https",
            f"{self.host}:{self.port}",
            self.gui_path,
            '',
            urllib.parse.urlencode(params),
            '',
        )
        return urllib.parse.urlunparse(uri)

    def query(
        self,
        query: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        timeout: str = '30:00',
        limit: int = 1000,
        use_index_time: bool = False,
    ) -> list:
        """Executes a query

        Args:
            query (str): the query to execute
            start (datetime, optional): the start time for the search (default None)
            end (datetime, optional): the end time for the search (default None)
            timeout (str, optional): the max timedelta to run the query for. format: DD:HH:MM:SS (default '30:00' -> 30 minutes)
            limit (int, optional): the max results to return (default 1000)
            use_index_time (bool, optional): set to true to search over index time (default False)

        Returns:
            list: list of results where each item is a dictionary that maps the field to the value
        """
        # remove search from start of query if it is present, it will get added back on later
        if query.lstrip().lower().startswith('search'):
            query = query[len('search'):]

        # set time prefix
        prefix = '_index_' if use_index_time else ''

        # add end time
        if end is not None:
            query = f'{prefix}latest={end.strftime("%m/%d/%Y:%H:%M:%S")} {query}'

        # add start time
        if start is not None:
            query = f'{prefix}earliest={start.strftime("%m/%d/%Y:%H:%M:%S")} {query}'

        # run the query
        job = None
        while True:
            # submit/check query
            job, results = self.query_async(query, job=job, limit=limit, start=start, end=end, use_index_time=use_index_time, timeout=timeout)

            if results is not None:
                return results

            # wait a bit
            time.sleep(3)

    def query_async(
        self, 
        query:str, 
        job:Optional[Job]=None, 
        limit:int=1000, 
        start:Optional[datetime]=None, 
        end:Optional[datetime]=None, 
        use_index_time:bool=False, 
        timeout: Optional[str]="30:00") -> Tuple[Optional[Job], Optional[List[dict]]]:
        """Executes a query asynchronously.

        To properly use the method you must call it in a loop and pass the returned sid into the next call until results are returned

        Args:
            query (str): the query to execute
            start (datetime, optional): the start time for the search (default None)
            end (datetime, optional): the end time for the search (default None)
            use_index_time (bool, optional): set to true to search over index time (default False)
            sid (str, optional): the search id returned from a previous call to query_async (default None -> new query)
            limit (int, optional): max results to return (default 1000)

        Returns:
            tuple: First value is the sid of the query, second value is the json results of the query
        """
        try:
            # check if we've timed out 
            if self.is_running() and timeout is not None:
                if local_time() >= self.running_start_time + create_timedelta(timeout):
                    logging.warning(f"splunk query timed out: {query}")
                    self.cancel(job)
                    return None, []

            # queue the query if we have not already
            if job is None:
                job = self.queue(query, limit, start=start, end=end, use_index_time=use_index_time)
                return job, None

            # wait for the job to complete
            if not self.complete(job):
                return job, None

            # return the results
            results_reader = JSONResultsReader(job.results(count="0", output_mode="json"))
            results = [result for result in results_reader]
            logging.info(f"got results for {job.name}")
            self.end_time = local_time()
            self.record_splunk_query_performance(job)
            self.delete_search_job(job)
            return job, results

        except HTTPError as e:
            # requeue query if splunk lost the query
            if e.response.status_code in [204]:
                return None, None

            # report erorr and return empty results
            logging.warning(f'Search failed: {type(e)} {e}')
            #self.cancel(sid)
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            return None, []

        # report erorrs and return empty results
        except ( ConnectionError, Timeout, ProxyError ) as e:
            logging.warning(f'Search failed: {type(e)} {e}')
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            return None, []

        except Exception as e:
            logging.error(f'Search failed: {e}')
            report_exception()
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            return None, []

    def queue(self, query:str, limit:int, start:Optional[datetime]=None, end:Optional[datetime]=None, use_index_time:bool=False) -> Optional[Job]:
        """Queue the query and return the job object

        Args:
            query (str): the query to queue
            limit (int): max results to return
            start (datetime, optional): the start time for the search (default None)
            end (datetime, optional): the end time for the search (default None)
            use_index_time (bool, optional): set to true to search over index time (default False)

        Returns:
            Optional[Job]: the job object for the query
        """
        self.reset_search_status()

        # add search to start of query if missing
        if not query.lstrip().lower().startswith('search'):
            query = 'search ' + query


        search_kwargs = {'max_count': limit, "exec_mode": "normal"}

        # see https://docs.splunk.com/Documentation/Splunk/9.0.3/RESTREF/RESTsearch#search.2Fjobs
        # then see https://community.splunk.com/t5/Splunk-Search/subsearch-default-time-range/m-p/52515/highlight/true#M12767
        # we have to pass in the time range we're using as these parameters
        # otherwise subsearch won't use the same time range as the main search

        if start is not None and end is not None:
            if use_index_time:
                search_kwargs['index_earliest'] = start.isoformat(sep='T',timespec='auto')
                search_kwargs['index_latest'] = end.isoformat(sep='T',timespec='auto')
                logging.info(f"using index time earliest = {search_kwargs['index_earliest']} latest = {search_kwargs['index_latest']}")
            else:
                search_kwargs['earliest_time'] = start.isoformat(sep='T',timespec='auto')
                search_kwargs['latest_time'] = end.isoformat(sep='T',timespec='auto')
                logging.info(f"using time earliest = {search_kwargs['earliest_time']} latest = {search_kwargs['latest_time']}")


        #self.job = self.search_session.post('/search/jobs', data=search_kwargs)
        search_job = self.client.jobs.create(query, **search_kwargs)
        #search_id = etree.fromstring(response.content).xpath('//sid/text()')[0]
        self.record_splunk_sid(search_job.name, query)
        return search_job

    def complete(self, job:Job) -> bool:
        """Checks if the query is complete

        Args:
            sid (str): the search id of the query to check on

        Returns:
            bool: True if complete, False otherwise
        """
        if not job.is_ready():
            logging.debug(f"job {job.name} is not ready yet")
            return False

        # gather all the stats at once
        job.refresh()

        self.is_done = job["isDone"]
        self.done_progress = job["doneProgress"]
        self.dispatch_state = job["dispatchState"]
        self.is_failed = job["isFailed"]
        self.event_count = job["eventCount"]
        self.run_duration = job["runDuration"]

        logging.info(f"{job.name} dispatch state {self.dispatch_state} done progress: {self.done_progress} is failed {self.is_failed} event count {self.event_count} run duration {self.run_duration} wait time {int(self.wait_time if self.wait_time else 0)} run time {int(self.run_time if self.run_time else 0)} total time {int(self.total_time if self.total_time else 0)}")
        return self.is_done == "1"

    def cancel(self, job:Job) -> bool:
        """Cancels a query by search id

        Args:
            sid (str): the search id of the query to cancel

        Returns:
            bool: True if cancelled succesfully, False otherwise
        """
        # skip if sid is not set
        if job is None:
            logging.warning("called cancel with no job")
            return True

        # tell splunk to delete the job
        try:
            job.cancel()
            return True

        # ignore failures
        except Exception as e:
            logging.warning(f"unable to cancel search {job.name}: {e}")
            return False

    def delete_search_job(self, job:Job) -> bool:
        """Deletes a search job by sid.

        Args:
            sid (str): the search id of the job to delete

        Returns:
            bool: True if deleted
        """
        # skip if sid is not set
        assert job is not None

        # tell splunk to delete the job
        try:
            logging.info(f"deleting search job {job.name}")
            job.delete()
            return True

        # ignore failures
        except Exception as e:
            logging.warning(f"unable to delete search {job.name}: {e}")
            return False

    def record_splunk_sid(self, job: Job, query: str):
        if not self.performance_logging_directory:
            return

        try:
            target_dir = os.path.join(get_data_dir(), self.performance_logging_directory)
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, local_time().strftime("splunk_sid_lookup_%d%m%Y.csv"))
            with open(target_path, "a+") as fp:
                writer = csv.writer(fp)
                writer.writerow([job.name, query])

        except Exception as e:
            logging.error(f"unable to record splunk sid: {e}")
            report_exception()

    def get_search_log(self, sid: str, target_file: str) -> bool:
        """Download the Splunk log for the given search and store it in the specified file.
        Returns True if one or more bytes was written. Raises exception on HTTP error."""

        # removed for now...
        raise NotImplementedError("not implemented")

    def record_splunk_query_performance(self, job: Job, error=None):
        if not self.performance_logging_directory:
            return

        target_dir = os.path.join(get_data_dir(), self.performance_logging_directory)

        try:
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, local_time().strftime("splunk_performance_%d%m%Y.csv"))
            with open(target_path, "a+") as fp:
                writer = csv.writer(fp)
                writer.writerow([job.name, local_time(), self.start_time, self.running_start_time, self.end_time, self.dispatch_state, self.run_duration, error, self.wait_time, self.total_time, self.run_time])

        except Exception as e:
            logging.error(f"unable to record splunk query performance: {e}")
            report_exception()

def SplunkClient(config: str = "splunk", **kwargs) -> SplunkQueryObject:
    """Convenience function for creating a SplunkClient from a config section

    Attributes:
        config (str, optional): the name of the config section to load a splunk client with (default splunk)

    Returns:
        SplunkQueryObject: a splunk client configured with the options set in the specified config section
    """

    kwargs.update({
        "host": get_config()[config]["host"],
        "port": get_config()[config]["port"],
        "proxies": proxy_config(get_config()[config].get("proxy", fallback=None)),
    })

    if get_config()[config].get("username"):
        kwargs["username"] = get_config()[config]["username"]
        kwargs["password"] = get_config()[config]["password"]
    else:
        kwargs["token"] = get_config()[config]["token"]

    if get_config()[config].get("user_context"):
        kwargs["user_context"] = get_config()[config]["user_context"]

    if get_config()[config].get("app_context"):
        kwargs["app"] = get_config()[config]["app_context"]

    return SplunkQueryObject(**kwargs)
