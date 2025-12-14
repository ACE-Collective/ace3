import hashlib
import io
import logging
import os
import re
import shutil
from typing import Type
from urllib.parse import urlunparse
from pydantic import Field

import requests
import urllib
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.search import search_down
from saq.brocess import add_httplog
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_TYPE_MANUAL, DIRECTIVE_CRAWL, DIRECTIVE_EXTRACT_URLS, F_URL, R_DOWNLOADED_FROM, R_REDIRECTED_FROM, AnalysisExecutionResult
from saq.crawlphish_filter import CrawlphishURLFilter
from saq.environment import get_data_dir, get_global_runtime_settings
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.proxy import proxies
from saq.util.networking import is_ipv4
from werkzeug.utils import secure_filename


KEY_STATUS_CODE = 'status_code'
KEY_REASON = 'reason' # "status_code_reason"
KEY_FILE_NAME = 'file_name'
KEY_CRAWLABLE = 'crawlable' # "filtered_status"
KEY_FILTERED_STATUS_REASON = 'filtered_status_reason'
KEY_NETWORK_ERROR = 'network_error' # "error_reason"
KEY_HEADERS = 'headers'
KEY_HISTORY = 'history'
KEY_REQUESTED_URL = 'requested_url'
KEY_FINAL_URL = 'final_url'
KEY_DOWNLOADED = 'downloaded'
KEY_PROXY = 'proxy'
KEY_PROXY_NAME = 'proxy_name'

class CrawlphishAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STATUS_CODE: None,
            KEY_REASON: None,
            KEY_FILE_NAME: None,
            KEY_CRAWLABLE: None,
            KEY_FILTERED_STATUS_REASON: None,
        }
        
    @property
    def status_code(self):
        """The HTTP status code received from the host."""
        if self.details is None:
            return None

        if KEY_STATUS_CODE not in self.details:
            return None

        return self.details[KEY_STATUS_CODE]

    @status_code.setter
    def status_code(self, value):
        self.details[KEY_STATUS_CODE] = value

    @property
    def status_code_reason(self):
        """The reason given by the web server for the status code."""
        if self.details is None:
            return None

        if KEY_REASON not in self.details:
            return None

        return self.details[KEY_REASON]

    @status_code_reason.setter
    def status_code_reason(self, value):
        self.details[KEY_REASON] = value

    @property
    def file_name(self):
        if self.details is None:
            return None

        if KEY_FILE_NAME not in self.details:
            return None

        return self.details[KEY_FILE_NAME]

    @file_name.setter
    def file_name(self, value):
        self.details[KEY_FILE_NAME] = value

    @property
    def filtered_status(self):
        """Was this URL filtered?  Did we NOT attempt to crawl it?"""
        if self.details is None:
            return None

        if KEY_CRAWLABLE not in self.details:
            return None

        return self.details[KEY_CRAWLABLE]

    @filtered_status.setter
    def filtered_status(self, value):
        self.details[KEY_CRAWLABLE] = value

    @property
    def filtered_status_reason(self):
        """What is the reason for the filtered status?"""
        if self.details is None:
            return None

        if KEY_FILTERED_STATUS_REASON not in self.details:
            return None

        return self.details[KEY_FILTERED_STATUS_REASON]

    @filtered_status_reason.setter
    def filtered_status_reason(self, value):
        self.details[KEY_FILTERED_STATUS_REASON] = value

    @property
    def error_reason(self):
        """Returns the details of any error in processing of the URL."""
        if self.details is None:
            return None

        if KEY_NETWORK_ERROR not in self.details:
            return None

        return self.details[KEY_NETWORK_ERROR]

    @error_reason.setter
    def error_reason(self, value):
        self.details[KEY_NETWORK_ERROR] = value

    @property
    def headers(self):
        if self.details is None:
            return None

        if KEY_HEADERS not in self.details:
            return None

        return self.details[KEY_HEADERS]

    @headers.setter
    def headers(self, value):
        assert value is None or isinstance(value, dict)
        self.details[KEY_HEADERS] = value

    @property
    def history(self):
        if self.details is None:
            return None

        if KEY_HISTORY not in self.details:
            return None

        return self.details[KEY_HISTORY]

    @history.setter
    def history(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_HISTORY] = value

    @property
    def requested_url(self):
        if self.details is None:
            return None

        if KEY_REQUESTED_URL not in self.details:
            return None

        return self.details[KEY_REQUESTED_URL]

    @requested_url.setter
    def requested_url(self, value):
        assert isinstance(value, str)
        self.details[KEY_REQUESTED_URL] = value

    @property
    def final_url(self):
        if self.details is None:
            return None

        if KEY_FINAL_URL not in self.details:
            return None

        return self.details[KEY_FINAL_URL]

    @final_url.setter
    def final_url(self, value):
        assert isinstance(value, str)
        self.details[KEY_FINAL_URL] = value

    @property
    def downloaded(self):
        """Was the download of the URL successful?"""
        if self.details is None:
            return None

        if KEY_DOWNLOADED not in self.details:
            return self.file_name is not None

        return self.details[KEY_DOWNLOADED]

    @downloaded.setter
    def downloaded(self, value):
        self.details[KEY_DOWNLOADED] = value

    def generate_summary(self):
        if self.details is None:
            return None

        if self.filtered_status:
            return "Crawlphish PASS: {}".format(self.filtered_status_reason)

        if not self.downloaded:
            return "Crawlphish: Error: {}".format(self.error_reason)

        result = "Crawlphish Download ({} - {}) - {}".format(
                self.status_code,
                self.status_code_reason,
                self.file_name)

        return result

class CloudphishProxyResult(object):
    """Represents the result of the request for a URL against a given proxy."""

    def __init__(self, json=None):
        if json:
            self.details = json
        else:
            self.details = {
                KEY_PROXY_NAME: None,
                KEY_STATUS_CODE: None,
                KEY_REASON: None,
                KEY_NETWORK_ERROR: None,
                KEY_HEADERS: {},
                KEY_HISTORY: [],
            }

    @property
    def json(self):
        return self.details

    @property
    def proxy_name(self):
        """The name of the proxy that was used."""
        return self.details[KEY_PROXY_NAME]

    @proxy_name.setter
    def proxy_name(self, value):
        assert isinstance(value, str)
        self.details[KEY_PROXY_NAME] = value

    @property
    def status_code(self):
        """The HTTP status code received from the host."""
        return self.details[KEY_STATUS_CODE]

    @status_code.setter
    def status_code(self, value):
        self.details[KEY_STATUS_CODE] = value

    @property
    def status_code_reason(self):
        """The reason given by the web server for the status code."""
        return self.details[KEY_REASON]

    @status_code_reason.setter
    def status_code_reason(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_REASON] = value

    @property
    def error_reason(self):
        """Returns the details of any error in processing of the URL."""
        return self.details[KEY_NETWORK_ERROR]

    @error_reason.setter
    def error_reason(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_NETWORK_ERROR] = value

    @property
    def headers(self):
        return self.details[KEY_HEADERS]

    @headers.setter
    def headers(self, value):
        assert value is None or isinstance(value, dict)
        self.details[KEY_HEADERS] = value

    @property
    def history(self):
        return self.details[KEY_HISTORY]

    @history.setter
    def history(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_HISTORY] = value

KEY_PROXIES = 'proxies'
KEY_PROXY_RESULTS = 'proxy_results'
KEY_EXTENDED_INFORMATION = 'extended_information'

class CrawlphishAnalysisV2(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_CRAWLABLE: None,
            KEY_FILTERED_STATUS_REASON: None,
            KEY_FILE_NAME: None,
            KEY_FINAL_URL: None,
            KEY_REQUESTED_URL: None,
            KEY_DOWNLOADED: None,
            KEY_PROXIES: [],
            KEY_PROXY_RESULTS: {},
            KEY_EXTENDED_INFORMATION: {},
        }

    @property
    def filtered_status(self):
        """Was this URL filtered?  Did we NOT attempt to crawl it?"""
        return self.details[KEY_CRAWLABLE]

    @filtered_status.setter
    def filtered_status(self, value):
        self.details[KEY_CRAWLABLE] = value

    @property
    def filtered_status_reason(self):
        """What is the reason for the filtered status?"""
        return self.details[KEY_FILTERED_STATUS_REASON]

    @filtered_status_reason.setter
    def filtered_status_reason(self, value):
        self.details[KEY_FILTERED_STATUS_REASON] = value

    @property
    def file_name(self):
        return self.details[KEY_FILE_NAME]

    @file_name.setter
    def file_name(self, value):
        self.details[KEY_FILE_NAME] = value

    @property
    def final_url(self):
        return self.details[KEY_FINAL_URL]

    @final_url.setter
    def final_url(self, value):
        assert value is None or isinstance(value, str)
        self.details[KEY_FINAL_URL] = value

    @property
    def requested_url(self):
        return self.details[KEY_REQUESTED_URL]

    @requested_url.setter
    def requested_url(self, value):
        assert isinstance(value, str)
        self.details[KEY_REQUESTED_URL] = value

    @property
    def downloaded(self):
        """Was the download of the URL successful?"""
        return self.details[KEY_DOWNLOADED]

    @downloaded.setter
    def downloaded(self, value):
        self.details[KEY_DOWNLOADED] = value

    @property
    def proxies(self):
        """Returns a list of the names of the proxies used to try to download the url.
           These are the keys to the proxy_results property."""

        # NOTE we do NOT return the keys() property of the proxy_results
        # these are in the order that the proxy was attempted to be used
        return self.details[KEY_PROXIES]

    @proxies.setter
    def proxies(self, value):
        assert isinstance(value, list)
        self.details[KEY_PROXIES] = value

    @property
    def proxy_results(self):
        result = self.details[KEY_PROXY_RESULTS]
        for proxy_name, proxy_result in result.items():
            if isinstance(result[proxy_name], dict):
                result[proxy_name] = CloudphishProxyResult(json=result[proxy_name])

        return result

    @proxy_results.setter
    def proxy_results(self, value):
        assert isinstance(value, dict)
        self.details[KEY_PROXY_RESULTS] = value

    #
    # read only properties that return the values from the last proxy result in the list

    @property
    def proxy_name(self):
        """The name of the last proxy that was attempted."""
        if self.proxies:
            return self.proxies[-1]
        else:
            return None

    @property
    def status_code(self):
        """The status code obtained from the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].status_code
        else:
            return None

    @property
    def status_code_reason(self):
        """The status code reason obtained from the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].status_code_reason
        else:
            return None

    @property
    def error_reason(self):
        """The error reason set on the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].error_reason
        else:
            return None

    @property
    def headers(self):
        """The headers returned by the last proxy request."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].headers
        else:
            return None

    @property
    def history(self):
        """The history (chain) of requests at the last proxy used."""
        if self.proxy_name:
            return self.proxy_results[self.proxy_name].history
        else:
            return None

    @property
    def extended_info(self) -> dict:
        """Returns a dict that contains extended information."""
        if self.details is None:
            return {}

        if KEY_EXTENDED_INFORMATION not in self.details:
            return {}

        return self.details[KEY_EXTENDED_INFORMATION]

    def generate_summary(self):

        if self.filtered_status:
            return "Crawlphish PASS: {}".format(self.filtered_status_reason)

        # were we not able to download it?
        if not self.downloaded:
            # list the error for each proxy
            result = "Crawlphish: Error: "
        else:
            # we were able to download something
            result = "Crawlphish Download ({}): ".format(self.file_name)

        for proxy in self.proxies:
            proxy_result = self.proxy_results[proxy]
            result += "({}: {}) ".format(proxy, 
                                         proxy_result.error_reason if proxy_result.error_reason else '{} - {}'.format(
                                         proxy_result.status_code, proxy_result.status_code_reason))

        return result

class CrawlphishAnalyzerConfig(AnalysisModuleConfig):
    whitelist_path: str = Field(..., description="Path to whitelisted netloc.")
    regex_path: str = Field(..., description="Path to whitelisted path regexes.")
    blacklist_path: str = Field(..., description="Path to blacklisted netloc.")
    uncommon_network_threshold: int = Field(..., description="Threshold for uncommon networks (total connections threshold).")
    user_agent: str = Field(..., alias="user-agent", description="The user-agent to send with requests.")
    timeout: int = Field(..., description="How long to wait (in full seconds) until a request is timed out.")
    max_download_size: int = Field(..., description="Maximum file size (in MB).")
    max_file_name_length: int = Field(..., description="Maximum file name length of downloaded files (in bytes) file names are truncated past this value.")
    update_brocess: bool = Field(..., description="Update the brocess database with requests made with crawlphish.")
    proxies: list[str] = Field(default_factory=list, description="Comma separate list of proxies to use. The special value GLOBAL refers to the global proxy settings.")
    auto_crawl_all_alert_urls: bool = Field(default=False, description="Enable automatic crawlphish analysis for all url observables.")
    blacklist_filter_enabled: bool = Field(default=True, description="Enable blacklist filtering.")
    whitelist_filter_enabled: bool = Field(default=True, description="Enable whitelist filtering.")
    path_regex_filter_enabled: bool = Field(default=True, description="Enable path regex filtering.")
    common_filter_enabled: bool = Field(default=True, description="Enable common filter.")
    intel_filter_enabled: bool = Field(default=True, description="Enable intel filter.")
    direct_ipv4_filter_enabled: bool = Field(default=True, description="Enable direct IPv4 filter.")
    cache_downloaded_files: bool = Field(default=False, description="Set this to true to cache anything downloaded by crawlphish.")
    cache_directory: str = Field(default="crawlphish_cache", description="Directory to store cached downloaded files into (relative to DATA_DIR).")
    user_agent_list_path: str = Field(default="crawlphish_uas.txt", description="Path (relative to ANALYST_DATA_DIR) to file that contains all the user agents to use (one per line).")

class CrawlphishAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return CrawlphishAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.headers = {
            'User-Agent': self.config.user_agent
        }

        self._initialized = False

        self.auto_crawl_all_alert_urls = self.config.auto_crawl_all_alert_urls

        # list of user agent strings to attempt to use
        self.ua_list: list = None

    @property
    def whitelist_path(self):
        return self.url_filter.whitelist_path

    @property
    def regex_path(self):
        return self.url_filter.regex_path

    @property
    def blacklist_path(self):
        return self.url_filter.blacklist_path

    @property
    def uncommon_network_threshold(self):
        """How many connections decides that a given fqdn or ip address is an "uncommon network"? """
        return self.config.uncommon_network_threshold

    @property
    def user_agent(self):
        """User agent string to use if user_agent_list is empty."""
        return self.config.user_agent

    @property
    def user_agent_list_path(self) -> str:
        """Returns the path to the file that contains a list of UAs to use."""
        return os.path.join(get_global_runtime_settings().analyst_data_dir, self.config.user_agent_list_path)

    @property
    def user_agent_list(self):
        """Returns the list of UAs to use. Each UA will be used in the order given."""
        if self.ua_list:
            return self.ua_list

        # use the default if no uas are provided
        return [ self.user_agent ]

    def load_user_agent_list(self):
        """Loads the UAs from user_agent_list_path."""
        if not os.path.exists(self.user_agent_list_path):
            return

        try:
            logging.info(f"loading user agent strings from {self.user_agent_list_path}")
            self.ua_list = []
            with open(self.user_agent_list_path, 'r') as fp:
                for ua in fp:
                    ua = ua.strip()
                    if ua:
                        # allow comments
                        if ua.startswith('#'):
                            continue

                        self.ua_list.append(ua)
                        logging.info(f"loaded user agent {ua}")

        except Exception as e:
            logging.info(f"unable to load user agent strings: {e}")

    @property
    def timeout(self):
        """How long to wait for an HTTP request to time out (in seconds)."""
        return self.config.timeout

    @property
    def max_download_size(self):
        """Maximum download size (in MB)."""
        return self.config.max_download_size * 1024 * 1024

    @property
    def max_file_name_length(self):
        """Maximum file name length (in bytes) to use for download file path."""
        return self.config.max_file_name_length

    @property
    def update_brocess(self):
        """Are we updating brocess when we make a request?"""
        return self.config.update_brocess

    @property
    def proxies(self):
        """The list of proxies we'll use to download URLs, attepted in order."""
        return self.config.proxies

    @property
    def blacklist_filter_enabled(self):
        return self.config.blacklist_filter_enabled

    @property
    def whitelist_filter_enabled(self):
        return self.config.whitelist_filter_enabled

    @property
    def path_regex_filter_enabled(self):
        return self.config.path_regex_filter_enabled

    @property
    def common_filter_enabled(self):
        return self.config.common_filter_enabled

    @property
    def intel_filter_enabled(self):
        return self.config.intel_filter_enabled

    @property
    def direct_ipv4_filter_enabled(self):
        return self.config.direct_ipv4_filter_enabled

    @property
    def generated_analysis_type(self):
        return CrawlphishAnalysisV2

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def cache_downloaded_files(self):
        return self.config.cache_downloaded_files

    @property
    def cache_directory(self):
        return os.path.join(get_data_dir(), self.config.cache_directory)

    def custom_requirement(self, url):
        # should we be crawling this url?
        if url.has_directive(DIRECTIVE_CRAWL):
            return True
        # if this is a manual analysis we always want to try to crawl any urls
        elif self.get_root().alert_type == ANALYSIS_TYPE_MANUAL:
            return True
        # are we crawling all urls in the alerts (this is noisy)
        elif self.auto_crawl_all_alert_urls and self.get_root().analysis_mode == ANALYSIS_MODE_CORRELATION:
            return True
        else:
            return False

    def execute_analysis(self, url) -> AnalysisExecutionResult:
        if not self._initialized:
            # used to decide what URLs to actually crawl
            self.url_filter = CrawlphishURLFilter(
                    blacklist_filter_enabled=self.blacklist_filter_enabled,
                    whitelist_filter_enabled=self.whitelist_filter_enabled,
                    path_regex_filter_enabled=self.path_regex_filter_enabled,
                    common_filter_enabled=self.common_filter_enabled,
                    intel_filter_enabled=self.intel_filter_enabled,
                    direct_ipv4_filter_enabled=self.direct_ipv4_filter_enabled)

            # a whitelist of sites we'll always crawl
            self.watch_file(self.url_filter.whitelist_path, self.url_filter.load_whitelist)
            self.watch_file(self.url_filter.blacklist_path, self.url_filter.load_blacklist)
            self.watch_file(self.url_filter.regex_path, self.url_filter.load_path_regexes)

            # load user agents
            self.watch_file(self.user_agent_list_path, self.load_user_agent_list)

            self._initialized = True

        analysis = self.create_analysis(url)
        # are we able to download it?
        analysis.downloaded = False
        # if not, why?
        #analysis.error_reason = None

        # is this URL crawlable?
        filter_result = self.url_filter.filter(url.value)
        analysis.filtered_status = filter_result.filtered
        analysis.filtered_status_reason = filter_result.reason

        if analysis.filtered_status:
            logging.debug("{} is not crawlable: {}".format(url.value, analysis.filtered_status_reason))
            return AnalysisExecutionResult.COMPLETED

        parsed_url = filter_result.parsed_url
        if parsed_url is None:
            logging.debug("unable to parse url {}".format(url.value))
            return AnalysisExecutionResult.COMPLETED

        formatted_url = urlunparse(parsed_url)

        # update brocess if we're configured to do so
        if self.update_brocess and parsed_url.hostname and not is_ipv4(parsed_url.hostname):
            logging.debug("updating brocess with crawlphish request for {}".format(parsed_url.hostname))
            add_httplog(parsed_url.hostname)

        # what proxies are we going to use to attempt to download the url?
        # these are attempted in the order specified in the configuration setting
        proxy_configs = [proxies(_) for _ in self.proxies]
        proxy_result = None

        # get referer if there is one
        referer_url = search_down(url, lambda x: isinstance(x, Observable) and x.type == F_URL)
        if referer_url:
            self.headers.update({'referer': referer_url.value})
        else:
            self.headers.pop('referer', None)

        # set of sha256 hashes of stuff we've already downloaded
        downloaded_files = set()

        # if we're not using a proxy then we go direct
        if not proxy_configs:
            proxy_configs = [("direct", {})]

        for index, proxy_config in enumerate(proxy_configs):
            proxy_name, proxy_config = proxy_config

            proxy_result = CloudphishProxyResult()
            proxy_result.proxy_name = proxy_name
            analysis.proxies.append(proxy_name)
            analysis.proxy_results[proxy_name] = proxy_result
            session = requests.Session()
            session.proxies = proxy_config

            analysis.extended_info[proxy_name] = {}

            for user_agent in self.user_agent_list:
                try:
                    logging.info(f"requesting url {formatted_url} via {proxy_name} with user agent {user_agent}")
                    response = session.request('GET', formatted_url,
                                               headers=self.headers,
                                               timeout=self.timeout,
                                               allow_redirects=True,
                                               verify=False,
                                               stream=True)

                    proxy_result.status_code = response.status_code
                    proxy_result.status_code_reason = response.reason
                    logging.info("url request result {} ({}) for {}".format(response.status_code,
                                                                            response.reason,
                                                                            formatted_url))

                    for header in response.headers.keys():
                        proxy_result.headers[header] = response.headers[header]

                    for part in response.history:
                        proxy_result.history.append(part.url)

                except requests.Timeout:
                    proxy_result.error_reason = "request timed out"
                    continue
                except Exception as e:
                    proxy_result.error_reason = str(e)
                    logging.debug(f"error requesting '{formatted_url}' : {e}")
                    continue

                path_components = [x for x in parsed_url.path.split('/') if x.strip()]

                # need to figure out what to call it
                file_name = None
                # content-disposition header is the official way
                if 'content-disposition' in response.headers:
                    file_name = response.headers['content-disposition']
                    # we could potentially see there here: attachment; filename="blah..."
                    content_file_match = re.search('attachment; filename*?="?(?P<real_filename>[^"]+)"?',
                                                    response.headers['content-disposition'] )
                    if content_file_match:
                        file_name = content_file_match.group('real_filename')

                        # handle rfc5987 which allows utf-8 encoding and url-encoding
                        if file_name.lower().startswith("utf-8''"):
                            file_name = file_name[7:]
                            file_name = urllib.unquote(file_name).decode('utf8')

                # otherwise we use the last element of the path
                if not file_name and parsed_url.path and not parsed_url.path.endswith('/'):
                    file_name = path_components[-1]

                # truncate if too long
                if file_name and len(file_name) > self.max_file_name_length:
                    file_name = file_name[len(file_name) - self.max_file_name_length:]

                # replace invalid filesystem characters
                if file_name:
                    file_name = secure_filename(file_name).strip()

                # default if we can't figure it out
                if not file_name:
                    file_name = 'unknown.crawlphish'

                # make the crawlphish dir
                dest_dir = os.path.join(self.get_root().file_dir, 'crawlphish')
                try:
                    if not os.path.isdir(dest_dir):
                        os.makedirs(dest_dir)
                except Exception as e:
                    logging.error("unable to create directory {}: {}".format(dest_dir, e))

                file_path = os.path.join(dest_dir, file_name)

                # prevent file path collision
                if os.path.isfile(file_path):
                    duplicate_count = 1
                    file_path = os.path.join(dest_dir, "{}_{}".format(duplicate_count, file_name))
                    while os.path.isfile(file_path):
                        duplicate_count = duplicate_count + 1
                        file_path = os.path.join(dest_dir, "{}_{}".format(duplicate_count, file_name))

                # download the results up to the limit
                try:
                    bytes_downloaded = 0
                    hasher = hashlib.sha256()
                    with open(file_path, 'wb') as fp:
                        for chunk in response.iter_content(io.DEFAULT_BUFFER_SIZE):
                            hasher.update(chunk)
                            bytes_downloaded += len(chunk)
                            fp.write(chunk)

                            if bytes_downloaded >= self.max_download_size:
                                logging.debug("exceeded max download size for {}".format(url))
                                response.close()

                    logging.info("downloaded {} bytes for {}".format(bytes_downloaded, file_path))

                except Exception as e:
                    analysis.downloaded = False
                    proxy_result.error_reason = "data transfer interrupted: {}".format(e)
                    logging.info("url {} transfer failed: {}".format(url, e))

                # have we already downloaded this?
                sha256 = hasher.hexdigest()
                if sha256 in downloaded_files:
                    logging.info(f"already downloaded {sha256}")

                    # it's a dupe
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logging.error(f"unable to delete {file_path}: {e}")

                    continue

                downloaded_files.add(sha256)
                logging.info(f"file {file_path} has sha256 {sha256}")

                # record all the details of the transaction
                analysis.downloaded = True
                analysis.file_name = file_name
                analysis.requested_url = formatted_url
                analysis.final_url = response.url

                # if the final url is different than the original url, record that url as an observable
                final_url = None
                if analysis.final_url and analysis.final_url != url.value:
                    final_url = analysis.add_observable_by_spec(F_URL, analysis.final_url, o_time=url.time)
                    if final_url:
                        final_url.add_tag('redirection_target')
                        final_url.add_relationship(R_REDIRECTED_FROM, url)
                        final_url.exclude_analysis(CrawlphishAnalyzer)

                #if len(response.history) > 1:
                    #url.add_tag('redirection')

                # and add the file for processing
                download = analysis.add_file_observable(file_path, move=True, volatile=True)
                if download: 
                    download.add_relationship(R_DOWNLOADED_FROM, final_url if final_url else url)

                    # 10/4/2021 - bad guys return legit HTML on 404 so we can't be doing this
                    # only extract if non-error http response
                    #if response.status_code >= 200 and response.status_code <= 299:
                    download.add_directive(DIRECTIVE_EXTRACT_URLS)

                # are we caching the files we download?
                if self.cache_downloaded_files:
                    # create a directory to store the file into
                    target_dir = os.path.join(self.cache_directory, self.get_root().uuid[0:3], self.get_root().uuid)

                    try:
                        if not os.path.isdir(target_dir):
                            os.makedirs(target_dir)
                    except Exception as e:
                        logging.error(f"unable to create cache directory {target_dir} for crawlphish files: {e}")

                    target_path = os.path.join(target_dir, os.path.basename(download.value))
                    while os.path.exists(target_path):
                        target_path = f"_{target_path}"

                    try:
                        shutil.copy2(download.full_path, target_path)
                    except Exception as e:
                        logging.error(f"unable to copy {file_path} to {target_path}: {e}")

                    logging.info(f"crawlphish cached file from {self.get_root().uuid} file {download.value} from url {url.value} to file path {target_path}")

                # collected extended information
                extended_info = {
                    'status_code': proxy_result.status_code,
                    'status_code_reason': proxy_result.status_code_reason,
                    'headers': proxy_result.headers,
                    'history': proxy_result.history,
                    'error_reason': proxy_result.error_reason,
                    'file_name': analysis.file_name,
                    'final_url': response.url
                }

                analysis.extended_info[proxy_name][user_agent] = extended_info

        return AnalysisExecutionResult.COMPLETED