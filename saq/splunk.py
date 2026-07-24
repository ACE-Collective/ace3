"""Splunk API Library"""
import csv
import logging
import os
import os.path
import re
import ssl
import time
import urllib.parse

from datetime import UTC, datetime, timedelta
from http import client as http_client
from io import BytesIO
from requests.exceptions import HTTPError, Timeout, ProxyError, ConnectionError
from typing import TYPE_CHECKING, Optional, Tuple, List

if TYPE_CHECKING:
    from saq.configuration.schema import ProxyConfig

from splunklib import __version__ as splunklib_version
from splunklib.binding import _spliturl, handler as splunk_http_handler
from splunklib.client import AuthenticationError, Job
import splunklib.client as client
from splunklib.results import JSONResultsReader, Message

from saq.configuration.config import get_proxy_config, get_splunk_config
from saq.environment import get_data_dir
from saq.util import local_time, create_timedelta
from saq.error import report_exception
from saq.error.remote import RemoteApiError

# socket timeout (seconds) applied to every splunk HTTP request. without this a stalled
# connection blocks the calling thread forever.
DEFAULT_REQUEST_TIMEOUT = 60

# How many consecutive 401s to ride out while polling an already-dispatched search.
#
# NOTE This was added as a work-around for Splunk occasionally failing auth when
# multiple search heads are used for a single query.
DEFAULT_MAX_CONSECUTIVE_AUTH_FAILURES = 20


def _proxy_handler(proxy_host, proxy_port, proxy_scheme="http", timeout=None):
    """Returns a splunklib-compatible HTTP request handler that tunnels through an HTTP CONNECT proxy."""

    def connect(scheme, host, port):
        conn_kwargs = {}
        if timeout is not None:
            conn_kwargs["timeout"] = timeout

        ssl_context = ssl._create_unverified_context()

        if scheme == "https":
            # HTTPSConnection applies TLS after the CONNECT tunnel is established,
            # targeting the tunnel host — even when the proxy itself is plain HTTP.
            proxy_conn = http_client.HTTPSConnection(
                proxy_host, proxy_port,
                context=ssl_context,
                **conn_kwargs,
            )
            proxy_conn.set_tunnel(host, port)
        elif proxy_scheme == "https":
            proxy_conn = http_client.HTTPSConnection(
                proxy_host, proxy_port,
                context=ssl_context,
                **conn_kwargs,
            )
        else:
            proxy_conn = http_client.HTTPConnection(proxy_host, proxy_port, **conn_kwargs)

        return proxy_conn

    def request(url, message, **kwargs):
        scheme, host, port, path = _spliturl(url)
        body = message.get("body", "")
        head = {
            "Content-Length": str(len(body)),
            "Host": host,
            "User-Agent": f"splunk-sdk-python/{splunklib_version}",
            "Accept": "*/*",
            "Connection": "Close",
        }
        for key, value in message["headers"]:
            head[key] = value

        connection = connect(scheme, host, port)
        try:
            connection.request(message.get("method", "GET"), path, body, head)
            if timeout is not None:
                connection.sock.settimeout(timeout)
            response = connection.getresponse()
            return {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.getheaders()),
                "body": BytesIO(response.read()),
            }
        finally:
            connection.close()

    return request

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


def splunk_gui_path(app: Optional[str] = None) -> str:
    """Returns the Splunk web search path for the given app context (None/'-' -> default search app)."""
    return 'en-US/app/search/search' if app is None or app == '-' else f'en-US/app/{app}/search'


def encode_splunk_query_link(host: str, gui_path: str, query: str, start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None, use_index_time: bool = False) -> str:
    """Builds a Splunk web search URL for the given query and time range without needing a live connection.

    Args:
        host (str): the Splunk web host
        gui_path (str): the search app path (see splunk_gui_path)
        query (str): the SPL query
        start_time (datetime, optional): the start time of the query (default None -> no start time)
        end_time (datetime, optional): the end time of the query (default None -> no end time)
        use_index_time (bool, optional): set true to search over index time (default False)

    Returns:
        str: the gui link to the query over the given time range
    """
    is_generating_command = query.lstrip().startswith("|")

    # add search to start of query if missing (skip for generating commands starting with |)
    if not is_generating_command and not query.lstrip().lower().startswith("search"):
        query = "search " + query

    # add index time filter if index time is being used (only for search commands)
    if use_index_time and not is_generating_command:
        index_end_time_str = ""
        if end_time is not None:
            index_end_time_str = end_time.strftime("%m/%d/%Y:%H:%M:%S")

        index_start_time_str = ""
        if start_time is not None:
            index_start_time_str = start_time.strftime("%m/%d/%Y:%H:%M:%S")

        replacement = f"search _index_earliest={index_start_time_str} _index_latest={index_end_time_str} "
        query = re.sub(r'^\s*search\s+', replacement, query, flags=re.IGNORECASE)

    # build params
    params = {'q': query}
    if start_time:
        # if we're using index time then the event time ranges needs to completely overlap with the index time range
        if use_index_time:
            params['earliest'] = int(time.mktime((start_time - timedelta(days=30)).timetuple())) # hardcoded to 30 days before the start time
        else:
            params['earliest'] = int(time.mktime(start_time.timetuple()))

    if end_time:
        if use_index_time:
            params['latest'] = int(time.mktime((end_time + timedelta(days=30)).timetuple())) # hardcoded to 30 days after the end time
        else:
            params['latest'] = int(time.mktime(end_time.timetuple()))

    # build link
    uri = (
        "https",
        # NOTE we don't specify the port here (API calls are on a different port than the UI)
        f"{host}",
        gui_path,
        '',
        urllib.parse.urlencode(params),
        '',
    )
    return urllib.parse.urlunparse(uri)


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
        proxies: Optional["ProxyConfig"] = None,
        user_context: Optional[str] = None,
        app: Optional[str] = None,
        dispatch_state: Optional[str]=None,
        start_time: Optional[datetime]=None,
        running_start_time: Optional[datetime]=None,
        end_time: Optional[datetime]=None,
        performance_logging_directory: Optional[str]=None,
        request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
        max_consecutive_auth_failures: int = DEFAULT_MAX_CONSECUTIVE_AUTH_FAILURES,

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
            request_timeout (int, optional): socket timeout in seconds for each HTTP request
            max_consecutive_auth_failures (int, optional): how many consecutive 401s to tolerate while
                polling a running search before giving up (see query_async)
        """

        self.host = host
        self.port = port

        self.user_context = user_context
        self.app = app
        self.max_consecutive_auth_failures = max_consecutive_auth_failures

        connect_kwargs = {
            "host": self.host,
            "port": self.port,
            "app": self.app,
            "owner": self.user_context,
            # splunklib's autologin only does anything useful when we hold a username/password:
            # Context.login() is an explicit no-op when authenticating with a token, so leaving
            # autologin on for token auth just re-issues every failing request a second time and
            # reports it as "session token expired" when the real cause is something else.
            "autologin": bool(username),
            # these retries only cover transport-level exceptions, not HTTP error statuses.
            # note splunklib decrements this counter permanently and never resets it.
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

        if proxies is not None:
            connect_kwargs["handler"] = _proxy_handler(
                proxy_host=proxies.host,
                proxy_port=proxies.port,
                proxy_scheme=proxies.transport,
                timeout=request_timeout,
            )
        else:
            # splunklib's default handler is only given a timeout if we build it ourselves.
            # verify=False matches splunklib's own default (it uses an unverified SSL context).
            connect_kwargs["handler"] = splunk_http_handler(timeout=request_timeout, verify=False)

        self.client = client.connect(**connect_kwargs)

        # determine gui search path from namespace app
        self.gui_path = splunk_gui_path(app)

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

        # consecutive 401s seen while polling the current search (see query_async)
        self.consecutive_auth_failures = 0

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

    def encoded_query_link(self, query:str, start_time:Optional[datetime] = None, end_time:Optional[datetime] = None, use_index_time: bool = False) -> str:
        """Returns a gui link for the query over the given time range

        Args:
            query (str): the query to convert to a gui link
            start_time (datetime, optional): the start time of the query (default None -> no start time)
            end_time (datetime, optional): the end time of the query (default None -> no end time)

        Returns:
            str: the gui link to the query over the given time range
        """
        return encode_splunk_query_link(self.host, self.gui_path, query, start_time, end_time, use_index_time)

    def query(
        self,
        query: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        timeout: Optional[timedelta] = None,
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
        if timeout is None:
            timeout = create_timedelta("30:00")

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
        timeout: Optional[timedelta]=None,
        embed_time_in_query:bool=True) -> Tuple[Optional[Job], Optional[List[dict]]]:
        """Executes a query asynchronously.

        To properly use this method you must call it in a loop and pass the returned job into the next call until results are returned.

        Args:
            query (str): the query to execute.
            job (Job, optional): the job object returned from a previous call to query_async (default None -> new query).
            limit (int, optional): max results to return (default 1000).
            start (datetime, optional): the start time for the search (default None).
            end (datetime, optional): the end time for the search (default None).
            use_index_time (bool, optional): set to true to search over index time (default False).
            timeout (timedelta, optional): max time to wait for the query to complete (default 30 minutes).
            embed_time_in_query (bool, optional): set to False to skip embedding time ranges in the query string (default True).

        Returns:
            tuple: (Job, list[dict] | None) — the job object and the results, or None if the query is still running.
        """
        if timeout is None:
            timeout = create_timedelta("30:00")

        try:
            # check if we've timed out. this is measured from when the search entered the RUNNING
            # state, not from submit, so time spent waiting in the dispatch queue behind other
            # searches does not count against the query's run budget.
            if self.is_running() and timeout is not None:
                if local_time() >= self.running_start_time + timeout:
                    self._abort_timed_out_search(job, query, timeout)

            # queue the query if we have not already
            # NOTE an auth failure here means the credentials really are bad, so it is not retried
            if job is None:
                job = self.queue(query, limit, start=start, end=end, use_index_time=use_index_time, embed_time_in_query=embed_time_in_query)
                return job, None

            try:
                # wait for the job to complete
                if not self.complete(job):
                    self.consecutive_auth_failures = 0
                    return job, None

                # return the results
                results_reader = JSONResultsReader(job.results(count="0", output_mode="json"))
                results = []
                for item in results_reader:
                    if isinstance(item, Message):
                        logging.info(f"splunk message ({item.type}): {item.message}")
                    else:
                        results.append(item)
            except AuthenticationError as e:
                # The search itself is still alive on the search head that owns it -- this is
                # almost always a transient search-head-cluster proxy failure rather than a
                # credential problem. Keep polling instead of discarding the job.
                self.consecutive_auth_failures += 1
                if self.consecutive_auth_failures > self.max_consecutive_auth_failures:
                    raise

                logging.info(
                    "splunk returned 401 polling search %s (%s/%s consecutive): %s",
                    job.name, self.consecutive_auth_failures,
                    self.max_consecutive_auth_failures, e)
                return job, None

            self.consecutive_auth_failures = 0
            logging.info(f"got results for {job.name}")
            self.end_time = local_time()
            self.record_splunk_query_performance(job)
            self.delete_search_job(job)
            return job, results

        except RemoteApiError:
            # already classified (e.g. by _abort_timed_out_search); do not re-wrap as a 500
            raise

        except HTTPError as e:
            # requeue query if splunk lost the query
            if e.response.status_code in [204]:
                return None, None

            logging.warning(f'Search failed: {type(e)} {e}')
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            raise RemoteApiError(e.response.status_code, f"Splunk search failed: {e}")

        except (ConnectionError, Timeout, ProxyError) as e:
            logging.warning(f'Search failed: {type(e)} {e}')
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            raise RemoteApiError(502, f"Splunk search failed: {e}")

        except AuthenticationError as e:
            # NOTE splunklib reports every 401 as "session token expired" regardless of the actual
            # cause, so do not take that wording at face value. A static token that never expires
            # can still produce this when the search head cluster fails to proxy the request.
            logging.warning(
                "splunk rejected the request with 401 (search %s): this is either invalid "
                "credentials or a search head cluster proxy failure: %s",
                job.name if job else "<not dispatched>", e)
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            raise RemoteApiError(401, f"Splunk authentication failed: {e}")

        except Exception as e:
            logging.error(f'Search failed: {e}')
            report_exception()
            if job:
                self.delete_search_job(job)
            self.record_splunk_query_performance(job, error=e)
            raise RemoteApiError(500, f"Splunk search failed: {e}")

    def _abort_timed_out_search(self, job: Job, query: str, timeout: timedelta):
        """Cancels a search that exceeded its time budget and raises RemoteApiError(504).

        We deliberately raise rather than returning empty results: callers treat a result list as
        a successful search, and a query hunt would then record the time range as covered and
        never look at it again, silently losing detection coverage for that window.
        """
        logging.warning(
            "splunk query timeout after %s (dispatch state %s) for search %s: %s",
            timeout, self.dispatch_state, job.name, query)
        self.cancel(job)
        self.end_time = local_time()
        self.record_splunk_query_performance(job, error=f"query timeout after {timeout}")
        raise RemoteApiError(504, f"Splunk search timed out after {timeout}")

    def queue(self, query:str, limit:int, start:Optional[datetime]=None, end:Optional[datetime]=None, use_index_time:bool=False, embed_time_in_query:bool=True) -> Optional[Job]:
        """Queue the query and return the job object.

        Args:
            query (str): the query to queue.
            limit (int): max results to return.
            start (datetime, optional): the start time for the search (default None).
            end (datetime, optional): the end time for the search (default None).
            use_index_time (bool, optional): set to true to search over index time (default False).
            embed_time_in_query (bool, optional): set to False to skip embedding time ranges in the query string (default True).

        Returns:
            Optional[Job]: the job object for the query.
        """
        self.reset_search_status()

        is_generating_command = query.lstrip().startswith("|")

        if not is_generating_command:
            if embed_time_in_query:
                # strip "search" prefix if present (will be added back after time ranges)
                if query.lstrip().lower().startswith("search"):
                    query = query.lstrip()[len("search"):]

                # embed time ranges in the query string
                prefix = "_index_" if use_index_time else ""
                if end is not None:
                    query = f'{prefix}latest={end.strftime("%m/%d/%Y:%H:%M:%S")} {query}'
                if start is not None:
                    query = f'{prefix}earliest={start.strftime("%m/%d/%Y:%H:%M:%S")} {query}'

            # strip "search" prefix if already present (e.g. from TIMESPEC-replaced query)
            elif query.lstrip().lower().startswith("search"):
                query = query.lstrip()[len("search"):].lstrip()

            # add search prefix
            query = "search " + query

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
            # log at INFO so a search sitting in QUEUED/PARSING is visibly waiting rather than
            # looking like a hang. the elapsed time is what tells an operator which one it is.
            logging.info(
                "splunk search %s is not ready yet (waiting %ds since submit)",
                job.name, int((local_time() - self.start_time).total_seconds()))
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

def SplunkClient(name: str = "default", **kwargs) -> SplunkQueryObject:
    """Convenience function for creating a SplunkClient from a config section

    Attributes:
        config (str, optional): the name of the config section to load a splunk client with (default splunk)

    Returns:
        SplunkQueryObject: a splunk client configured with the options set in the specified config section
    """

    splunk_config = get_splunk_config(name)

    kwargs.update({
        "host": splunk_config.host,
        "port": splunk_config.port,
    })

    kwargs.setdefault("request_timeout", splunk_config.request_timeout)
    kwargs.setdefault("max_consecutive_auth_failures", splunk_config.max_consecutive_auth_failures)

    if splunk_config.proxy is not None:
        kwargs["proxies"] = get_proxy_config(splunk_config.proxy)

    if splunk_config.username is not None:
        kwargs["username"] = splunk_config.username
        kwargs["password"] = splunk_config.password
    else:
        kwargs["token"] = splunk_config.token

    if splunk_config.user_context is not None:
        kwargs["user_context"] = splunk_config.user_context

    if splunk_config.app_context is not None:
        kwargs["app"] = splunk_config.app_context

    return SplunkQueryObject(**kwargs)
