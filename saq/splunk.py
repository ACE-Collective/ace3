"""Splunk API Library"""
import csv
import logging
import os
import os.path
import time
import urllib.parse

from dataclasses import dataclass
from datetime import UTC, datetime
from lxml import etree
from requests.exceptions import HTTPError, Timeout, ProxyError, ConnectionError
from typing import Optional, Tuple, List

from saq.configuration import get_config
from saq.environment import get_data_dir
from saq.util import local_time, create_timedelta
from saq.error import report_exception
from saq.requests_wrapper import Session
from saq.proxy import proxy_config

@dataclass
class SavedSearch:
    name: str
    description: Optional[str]=None
    search: Optional[str]=None
    type: Optional[str]=None
    ns_user: Optional[str]=None
    ns_app: Optional[str]=None

# all saved search names managed by ice start with this prefix
SAVED_SEARCH_PREFIX = "ICE1_"

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
    except:
        logging.error(f"_time field does not match expected format: {event['_time']}")
        report_exception()

    return local_time()


class SplunkQueryObject:
    """Splunk api client for performing queries and kvstore operations

    Attributes:
        search_results (dict): the raw search results from the last query performed
            format: {'fields': ['field1', 'field2'], 'rows': [['r1v1', 'r1v2'], ['r2v1', 'r2v2']]}
    """

    def __init__(
        self,
        uri: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        proxies: Optional[dict] = None,
        user_context: str = '-',
        app: str = '-',
        dispatch_state: Optional[str]=None,
        start_time: Optional[datetime]=None,
        running_start_time: Optional[datetime]=None,
        end_time: Optional[datetime]=None,
        performance_logging_directory: Optional[str]=None,

    ):
        """
        Initializes a splunk api session

        Args:
            uri (str): the splunk api base uri to use e.g. https://splunk.com:8089
            username (str, optional): the username for authentication (required if token is not provided)
            password (str, optional): the password for authentication (required if token is not provided)
            token (str, optional): the token for authentication (required if username and password are not provided)
            proxies (dict, optional): the proxy info used to connect to splunk api (default None -> no proxy)
            user_context (str): the user context for operations (default '-' -> any user)
            app (str): the app conext for operations (default '-' -> any app)
        """

        self.uri = uri
        self.user_context = user_context
        self.app = app

        if self.user_context is None:
            logging.warning("user_context is not set, using default '-'")
            self.user_context = '-'

        if self.app is None:
            logging.warning("app is not set, using default '-'")
            self.app = '-'

        self.base_session = Session(max_retries=0)
        self.base_session.base_url = uri
        if token:
            self.base_session.headers['Authorization'] = f'Bearer {token}'
        else:
            self.base_session.auth = (username, password)
        self.base_session.proxies = proxies if proxies else {}
        self.base_session.trust_env = False
        self.base_session.verify = False

        # create the session
        self.search_session = Session(max_retries=0)
        self.search_session.base_url = f'{uri}/servicesNS/{user_context}/{app}'
        if token:
            self.search_session.headers['Authorization'] = f'Bearer {token}'
        else:
            self.search_session.auth = (username, password)
        self.search_session.proxies = proxies if proxies else {}
        self.search_session.trust_env = False
        self.search_session.verify = False

        # determine gui search path from namespace app
        self.gui_path = 'en-US/app/search/search' if app is None or app == '-' else f'en-US/app/{app}/search'

        self.performance_logging_directory = performance_logging_directory
        if self.performance_logging_directory is None:
            try:
                self.performance_logging_directory = get_config()["splunk"].get("performance_logging_dir")
            except Exception as e:
                logging.warning(f"unable to load performance_logging_dir: {e}")

        self.reset_search_status(
            dispatch_state=dispatch_state, 
            start_time=start_time, 
            running_start_time=running_start_time, 
            end_time=end_time)

    def get_server_info(self) -> dict:
        response = self.base_session.get("/services/server/info?output_mode=json")
        response.raise_for_status()
        return response.json()

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

    def encoded_query_link(self, query:str, start_time:datetime=None, end_time:datetime=None) -> str:
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
        uri = urllib.parse.urlparse(self.search_session.base_url)
        uri = (
            uri.scheme,
            uri.hostname,
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
        sid = None
        while True:
            # submit/check query
            sid, results = self.query_async(query, sid=sid, limit=limit, start=start, end=end, use_index_time=use_index_time, timeout=timeout)

            if results is not None:
                return results

            # wait a bit
            time.sleep(3)

    def query_async(
        self, 
        query:str, 
        sid:Optional[str]=None, 
        limit:int=1000, 
        start:Optional[datetime]=None, 
        end:Optional[datetime]=None, 
        use_index_time:bool=False, 
        timeout: Optional[str]="30:00") -> Tuple[Optional[str], Optional[List[dict]]]:
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
                    self.cancel(sid)
                    return None, []

            # queue the query if we have not already
            if sid is None:
                sid = self.queue(query, limit, start=start, end=end, use_index_time=use_index_time)
                return sid, None

            # check if it is complete
            if not self.complete(sid):
                return sid, None

            # return the results
            results = self.results(sid)
            logging.info(f"got results for {sid}")
            self.end_time = local_time()
            self.record_splunk_query_performance(sid)
            self.delete_search_job(sid)
            return sid, results

        except HTTPError as e:
            # requeue query if splunk lost the query
            if e.response.status_code in [204]:
                return None, None

            # report erorr and return empty results
            logging.warning(f'Search failed: {type(e)} {e}')
            #self.cancel(sid)
            if sid:
                self.delete_search_job(sid)
            self.record_splunk_query_performance(sid, error=e)
            return None, []

        # report erorrs and return empty results
        except ( ConnectionError, Timeout, ProxyError ) as e:
            logging.warning(f'Search failed: {type(e)} {e}')
            if sid:
                self.delete_search_job(sid)
            self.record_splunk_query_performance(sid, error=e)
            return None, []

        except Exception as e:
            logging.error(f'Search failed: {e}')
            report_exception()
            if sid:
                self.delete_search_job(sid)
            self.record_splunk_query_performance(sid, error=e)
            return None, []

    def queue(self, query:str, limit:int, start:Optional[datetime]=None, end:Optional[datetime]=None, use_index_time:bool=False) -> str:
        """Queue the query and return the search id

        Args:
            query (str): the query to queue
            limit (int): max results to return
            start (datetime, optional): the start time for the search (default None)
            end (datetime, optional): the end time for the search (default None)
            use_index_time (bool, optional): set to true to search over index time (default False)

        Returns:
            str: the search id of the query
        """
        self.reset_search_status()

        # add search to start of query if missing
        if not query.lstrip().lower().startswith('search'):
            query = 'search ' + query


        data = {'search': query, 'max_count': limit}

        # see https://docs.splunk.com/Documentation/Splunk/9.0.3/RESTREF/RESTsearch#search.2Fjobs
        # then see https://community.splunk.com/t5/Splunk-Search/subsearch-default-time-range/m-p/52515/highlight/true#M12767
        # we have to pass in the time range we're using as these parameters
        # otherwise subsearch won't use the same time range as the main search

        if start is not None and end is not None:
            if use_index_time:
                data['index_earliest'] = start.isoformat(sep='T',timespec='auto')
                data['index_latest'] = end.isoformat(sep='T',timespec='auto')
                logging.info(f"using index time earliest = {data['index_earliest']} latest = {data['index_latest']}")
            else:
                data['earliest_time'] = start.isoformat(sep='T',timespec='auto')
                data['latest_time'] = end.isoformat(sep='T',timespec='auto')
                logging.info(f"using time earliest = {data['earliest_time']} latest = {data['latest_time']}")


        response = self.search_session.post('/search/jobs', data=data)
        search_id = etree.fromstring(response.content).xpath('//sid/text()')[0]
        self.record_splunk_sid(search_id, query)
        return search_id

    def complete(self, sid:str) -> bool:
        """Checks if the query is complete

        Args:
            sid (str): the search id of the query to check on

        Returns:
            bool: True if complete, False otherwise
        """
        response = self.search_session.get(f'/search/jobs/{sid}')
        # weird bug with splunk api that results in it returning a 204 with no content, requeue query when this happens
        if response.status_code == 204:
            raise HTTPError('No content', response=response)

        parsed_xml = etree.fromstring(response.content)

        node_search = parsed_xml.find('.//*[@name="isDone"]')
        if node_search is not None:
            self.is_done = node_search.text

        node_search = parsed_xml.find('.//*[@name="doneProgress"]')
        if node_search is not None:
            self.done_progress = node_search.text

        node_search = parsed_xml.find('.//*[@name="dispatchState"]')
        if node_search is not None:
            self.dispatch_state = node_search.text

        node_search = parsed_xml.find('.//*[@name="isFailed"]')
        if node_search is not None:
            self.is_failed = node_search.text

        node_search = parsed_xml.find('.//*[@name="eventCount"]')
        if node_search is not None:
            self.event_count = node_search.text

        node_search = parsed_xml.find('.//*[@name="runDuration"]')
        if node_search is not None:
            self.run_duration = node_search.text

        logging.info(f"{sid} dispatch state {self.dispatch_state} done progress: {self.done_progress} is failed {self.is_failed} event count {self.event_count} run duration {self.run_duration} wait time {int(self.wait_time if self.wait_time else 0)} run time {int(self.run_time if self.run_time else 0)} total time {int(self.total_time if self.total_time else 0)}")
        return self.is_done == '1'

    def results(self, sid:str) -> List[dict]:
        """Returns the results for a given search id

        Args:
            sid (str): the search id of the query to get results for

        Returns:
            list: the list of results for the query
        """
        params = {'count': "0", 'output_mode': 'json_rows'}
        r = self.search_session.get(f'/search/jobs/{sid}/results', params=params).json()

        # convert list of fields and rows to list of dictionaries
        return [ { r['fields'][i] : row[i] for i in range(0, len(r['fields'])) } for row in r['rows'] ]

    def cancel(self, sid:str) -> bool:
        """Cancels a query by search id

        Args:
            sid (str): the search id of the query to cancel

        Returns:
            bool: True if cancelled succesfully, False otherwise
        """
        # skip if sid is not set
        if sid is None:
            return True

        # tell splunk to delete the job
        try:
            r = self.search_session.delete(f'/search/jobs/{sid}')
            return True

        # ignore failures
        except Exception as e:
            logging.warning(f"unable to cancel search {sid}: {e}")
            return False

    def delete_search_job(self, sid:str) -> bool:
        """Deletes a search job by sid.

        Args:
            sid (str): the search id of the job to delete

        Returns:
            bool: True if deleted
        """
        # skip if sid is not set
        assert sid

        # tell splunk to delete the job
        try:
            logging.info(f"deleting search job {sid}")
            response = self.search_session.delete(f'/search/jobs/{sid}')
            response.raise_for_status()
            return True

        # ignore failures
        except Exception as e:
            logging.warning(f"unable to delete search {sid}: {e}")
            return False

    def get_all_from_kvstore(self, collection:str) -> List[dict]:
        """gets all items in a kv store collection

        Args:
            collection (str): the name of the collection to retrieve entries from

        Returns:
            list: a list containing a dict for each item in the collection
        """
        try:
            return self.search_session.get(f'/storage/collections/data/{collection}').json()

        except Exception as e:
            logging.error(f'unable to get data from {collection}: {e}')
            return []

    def save_to_kvstore(self, collection:str, items:List[dict]) -> bool:
        """batch save a list of items to the collection. duplicated are ignored

        Args:
            collection (str): the name of the collection to add items to
            items (str): a list containing a dict for each item to add to the collection

        Returns:
            bool: True if save was successful, False otherwise
        """
        try:
            self.search_session.post(f'/storage/collections/data/{collection}/batch_save', json=items)
            return True

        except Exception as e:
            logging.error(f'unable to save data to {collection}: {e}')
            return False

    def delete_from_kvstore_by_id(self, collection:str, item_id:str) -> bool:
        """Deletes an item from the collection

        Args:
            collection (str): the name of the collection to delete the item from
            item_id (str): the id of the item to remove from the collection

        Returns:
            bool: True if delete was successful, False otherwise
        """
        try:
            self.search_session.delete(f'/storage/collections/data/{collection}/{item_id}')
            return True

        except Exception as e:
            logging.error(f'unable to delete {item_id} from {collection}: {e}')
            return False

    def delete_all_from_kvstore(self, collection:str) -> bool:
        """Deletes all items from the collection

        Args:
            collection (str): the name of the collection to delete all items from

        Returns:
            bool: True if delete was successful, False otherwise
        """
        try:
            self.search_session.delete(f'/storage/collections/data/{collection}')
            return True

        except Exception as e:
            logging.error(f'unable to clear {collection}: {e}')
            return False

    def record_splunk_sid(self, sid: str, query: str):
        if not self.performance_logging_directory:
            return

        try:
            target_dir = os.path.join(get_data_dir(), self.performance_logging_directory)
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, local_time().strftime("splunk_sid_lookup_%d%m%Y.csv"))
            with open(target_path, "a+") as fp:
                writer = csv.writer(fp)
                writer.writerow([sid, query])

        except Exception as e:
            logging.error(f"unable to record splunk sid: {e}")
            report_exception()

    def get_search_log(self, sid: str, target_file: str) -> bool:
        """Download the Splunk log for the given search and store it in the specified file.
        Returns True if one or more bytes was written. Raises exception on HTTP error."""
        response = self.search_session.get(f'/search/jobs/{sid}/search.log', stream=True)
        response.raise_for_status()
        bytes = 0
        with open(target_file, "wb") as fp:
            for chunk in response.iter_content(chunk_size=None):
                fp.write(chunk)
                bytes += len(chunk)

        return bytes > 0

    def record_splunk_query_performance(self, sid, error=None):
        if not self.performance_logging_directory:
            return

        target_dir = os.path.join(get_data_dir(), self.performance_logging_directory)

        try:
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, local_time().strftime("splunk_performance_%d%m%Y.csv"))
            with open(target_path, "a+") as fp:
                writer = csv.writer(fp)
                writer.writerow([sid, local_time(), self.start_time, self.running_start_time, self.end_time, self.dispatch_state, self.run_duration, error, self.wait_time, self.total_time, self.run_time])

        except Exception as e:
            logging.error(f"unable to record splunk query performance: {e}")
            report_exception()

        #try:
            #log_dir = os.path.join(target_dir, "logs")
            #if not os.path.isdir(log_dir):
                #os.mkdir(log_dir)

            #log_path = os.path.join(log_dir, f"{sid}.log")
            #if os.path.exists(log_path):
                #logging.info(f"splunk log file {log_path} already exists")
            #else:
                #if self.get_search_log(sid, log_path):
                    #logging.info(f"saved search log for {sid} to {log_path}")

        #except Exception as e:
            #logging.warning(f"unable to acquire search.log for {sid}: {e}")

    def get_saved_searches(self) -> list[SavedSearch]:
        """Returns the list of all the saved searches available as a list of SavedSearch objects."""

        ns = {
            "": "http://www.w3.org/2005/Atom",
            "s": "http://dev.splunk.com/ns/rest",
            "opensearch": "http://a9.com/-/spec/opensearch/1.1/",
        }

        results = []
        offset = 0

        while True:
            params = {
                "count": 30,
                "offset": offset,
            }

            logging.debug(f"downloading saved searches @ offset {offset}")
            response = self.search_session.request("get", "/saved/searches", params=params)
            response.raise_for_status()

            parsed_xml = etree.fromstring(response.content)

            total_results = int(parsed_xml.find(".//opensearch:totalResults", ns).text)
            items_per_page = int(parsed_xml.find(".//opensearch:itemsPerPage", ns).text)
            start_index = int(parsed_xml.find(".//opensearch:startIndex", ns).text)

            for node in parsed_xml.findall(".//entry", ns):
                search = SavedSearch(
                    name = node.find(".//title", ns).text,
                    description = node.find('.//*[@name="description"]', ns).text,
                    search = node.find('.//*[@name="search"]', ns).text,
                )

                # we mark what we manage by prepending a prefix to the name
                if not search.name.startswith(SAVED_SEARCH_PREFIX):
                    continue

                # make this feature transparent by stripping the prefix
                search.name = search.name[len(SAVED_SEARCH_PREFIX):]

                results.append(search)

            # are we done yet?
            if start_index + items_per_page >= total_results:
                break

            # move on to the next page
            offset += items_per_page

        return results

    def publish_saved_search(self, saved_search: SavedSearch) -> bool:
        """Publishes the given search to Splunk. Creates or updates the saved search.
        Returns True if successful. Raises HTTPError on API error."""

        prefixed_name = SAVED_SEARCH_PREFIX + saved_search.name
        logging.info(f"publishing saved search {prefixed_name}")

        try:
            response = self.search_session.request("post", "/saved/searches", data={
                "name": prefixed_name,
                "description": saved_search.description,
                "search": saved_search.search,
            }, halt_statuses=[409])
            response.raise_for_status()
            logging.info(f"created saved search {prefixed_name}")
            return response.status_code in range(200, 300)
        except HTTPError as e:
            if e.response.status_code == 409:
                response = self.search_session.request("post", f"/saved/searches/{prefixed_name}", data={
                    "description": saved_search.description,
                    "search": saved_search.search,
                })
                response.raise_for_status()
                logging.info(f"updated saved search {prefixed_name}")
                return response.status_code in range(200, 300)

        return False

    def delete_saved_search(self, saved_search: SavedSearch) -> bool:
        """Deletes the given saved search.
        Returns True if successful. Raises HTTPError on API error."""

        prefixed_name = SAVED_SEARCH_PREFIX + saved_search.name
        logging.info(f"deleting saved search {prefixed_name}")
        response = self.search_session.request("delete", f"/saved/searches/{prefixed_name}")
        response.raise_for_status()
        return response.status_code in range(200, 300)

# XXX refactor this garbage function
def SplunkClient(config: str = "splunk", **kwargs) -> SplunkQueryObject:
    """Convenience function for creating a SplunkClient from a config section

    Attributes:
        config (str, optional): the name of the config section to load a splunk client with (default splunk)

    Returns:
        SplunkQueryObject: a splunk client configured with the options set in the specified config section
    """

    kwargs.update({
        "uri": get_config()[config]["uri"],
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
