# vim: sw=4:ts=4:et:cc=120

from datetime import datetime
import logging
import os.path
import re
from typing import Type
from pydantic import Field

from saq.constants import ANALYSIS_TYPE_BRO_HTTP, F_FILE, F_FQDN, F_IP, F_IP_CONVERSATION, F_URL, create_ip_conversation
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.whitelist import BrotexWhitelist

REGEX_CONNECTION_ID = re.compile(r'^(C[^\.]+\.\d+)\.ready$')
HTTP_DETAILS_REQUEST = 'request'
HTTP_DETAILS_REPLY = 'reply'
HTTP_DETAILS_READY = 'ready'

class BroHTTPStreamAnalyzerConfig(AnalysisModuleConfig):
    whitelist_path: str = Field(..., description="Path to the brotex custom whitelist file.")

class BroHTTPStreamAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return BroHTTPStreamAnalyzerConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # http whitelist
        self.whitelist = None

        # path to the whitelist file
        self.whitelist_path = os.path.join(get_base_dir(), self.config.whitelist_path)

    def execute_pre_analysis(self):
        if self.get_root().alert_type != ANALYSIS_TYPE_BRO_HTTP:
            return False

        # process the .ready file
        # file format is as follows
        #
        # C7kebl1wNwKQ1qOPck.1.ready
        # time = 1537467014.49546
        # interrupted = F
        # finish_msg = message ends normally
        # body_length = 433994
        # content_gap_length = 0
        # header_length = 494
        #

        self.get_root().details = {
            HTTP_DETAILS_REQUEST: [],
            HTTP_DETAILS_REPLY: [],
            HTTP_DETAILS_READY: [],
        }

        stream_prefix = None
        ready_path = None
        request_path = None
        request_entity_path = None
        reply_path = None
        reply_entity_path = None

        for file_observable in self.get_root().observables:
            if file_observable.type != F_FILE:
                continue

            m = REGEX_CONNECTION_ID.match(file_observable.file_name)
            if m:
                stream_prefix = m.group(1)
                # the ready file contains stream summary info
                ready_path = file_observable.full_path
            elif file_observable.file_name.endswith('.request'):
                # http request headers
                request_path = file_observable.full_path
            elif file_observable.file_name.endswith('request.entity'):
                # http request content (POST content for example)
                request_entity_path = file_observable.full_path
            elif file_observable.file_name.endswith('.reply'):
                # http response headers
                reply_path = file_observable.full_path
            elif file_observable.file_name.endswith('.reply.entity'):
                # http response content
                reply_entity_path = file_observable.full_path

        if stream_prefix is None:
            logging.error("unable to find .ready file for http submission in {}".format(self.get_root()))
            return False

        # make sure we have at least the files we expect (summary, and request headers)
        for path in [ ready_path, request_path ]:
            if path is None or not os.path.exists(path):
                logging.error("missing expected file {}".format(path))
                return False

        # parse the ready file
        stream_time = None
        interrupted = False
        content_gap_length = 0

        with open(ready_path, 'r') as fp:
            for line in fp:
                self.get_root().details[HTTP_DETAILS_READY].append(line.strip())
                key, value = [_.strip() for _ in line.split(' = ')]
                
                if key == 'time':
                    stream_time = datetime.fromtimestamp(float(value))
                elif key == 'interrupted':
                    interrupted = value == 'T'
                elif key == 'content_gap_length':
                    content_gap_length = int(value)

        # parse the request
        request_headers = [] # of tuples of key, value
        request_headers_lookup = {} # key = key.lower()

        with open(request_path, 'r') as fp:
            request_ipv4 = fp.readline().strip()
            request_method = fp.readline().strip()
            request_original_uri = fp.readline().strip()
            request_unescaped_uri = fp.readline().strip()
            request_version = fp.readline().strip()

            logging.info("processing {} ipv4 {} method {} uri {}".format(stream_prefix, request_ipv4,
                                                                         request_method, request_original_uri))

            self.get_root().details[HTTP_DETAILS_REQUEST].append(request_ipv4)
            self.get_root().details[HTTP_DETAILS_REQUEST].append(request_method)
            self.get_root().details[HTTP_DETAILS_REQUEST].append(request_original_uri)
            self.get_root().details[HTTP_DETAILS_REQUEST].append(request_unescaped_uri)
            self.get_root().details[HTTP_DETAILS_REQUEST].append(request_version)

            for line in fp:
                self.get_root().details[HTTP_DETAILS_REQUEST].append(line.strip())
                key, value = [_.strip() for _ in line.split('\t')]
                request_headers.append((key, value))
                request_headers_lookup[key.lower()] = value

        # parse the response if it exists
        reply_headers = [] # of tuples of key, value
        reply_headers_lookup = {} # key = key.lower()
        reply_version = None
        reply_code = None
        reply_reason = None
        reply_ipv4 = None
        reply_port = None

        if os.path.exists(reply_path):
            try:
                with open(reply_path, 'r') as fp:
                    first_line = fp.readline()
                    self.get_root().details[HTTP_DETAILS_REPLY].append(first_line)
                    reply_ipv4, reply_port = [_.strip() for _ in first_line.split('\t')]
                    reply_port = int(reply_port)
                    reply_version = fp.readline().strip()
                    reply_code = fp.readline().strip()
                    reply_reason = fp.readline().strip()

                    self.get_root().details[HTTP_DETAILS_REPLY].append(reply_version)
                    self.get_root().details[HTTP_DETAILS_REPLY].append(reply_code)
                    self.get_root().details[HTTP_DETAILS_REPLY].append(reply_reason)

                    for line in fp:
                        self.get_root().details[HTTP_DETAILS_REPLY].append(line.strip())
                        key, value = [_.strip() for _ in line.split('\t')]
                        reply_headers.append((key, value))
                        reply_headers_lookup[key.lower()] = value
            except UnicodeDecodeError:
                logging.info(f"{stream_prefix} contains binary content in headers - skipping")
                return False

        self.get_root().description = 'BRO HTTP Scanner Detection - {} {}'.format(request_method, request_original_uri)
        self.get_root().event_time = datetime.now() if stream_time is None else stream_time

        request_ip = self.get_root().add_observable_by_spec(F_IP, request_ipv4)
        if request_ip:
            request_ip.display_type = "HTTP Request IP"
        if reply_ipv4:
            reply_ip = self.get_root().add_observable_by_spec(F_IP, reply_ipv4)
            if reply_ip:
                reply_ip.display_type = "HTTP Reply IP"
            self.get_root().add_observable_by_spec(F_IP_CONVERSATION, create_ip_conversation(request_ipv4, reply_ipv4))

        if 'host' in request_headers_lookup:
            self.get_root().add_observable_by_spec(F_FQDN, request_headers_lookup['host'])

        uri = request_original_uri[:]
        if 'host' in request_headers_lookup:
            # I don't think we'll ever see https here as that gets parsed as a different protocol in bro
            # we should only be seeing HTTP traffic
            uri = '{}://{}{}{}'.format('https' if reply_port == 443 else 'http', 
                                       request_headers_lookup['host'], 
                                       # if the default port is used then leave it out, otherwise include it in the url
                                       '' if reply_port == 80 else ':{}'.format(reply_port), 
                                       uri)
            self.get_root().add_observable_by_spec(F_URL, uri)

        if request_original_uri != request_unescaped_uri:
            uri = request_unescaped_uri[:]
            if 'host' in request_headers_lookup:
                uri = '{}:{}'.format(request_headers_lookup['host'], uri)
                self.get_root().add_observable_by_spec(F_URL, uri)

        # has the destination host been whitelisted?
        if self.whitelist is None:
            self.whitelist = BrotexWhitelist(self.whitelist_path)
            self.whitelist.load_whitelist()
        else:
            self.whitelist.check_whitelist()

        if 'host' in request_headers_lookup and request_headers_lookup['host']:
            if self.whitelist.is_whitelisted_fqdn(request_headers_lookup['host']):
                logging.debug("stream {} whitelisted by fqdn {}".format(stream_prefix, request_headers_lookup['host']))
                self.get_root().whitelist()
                return
