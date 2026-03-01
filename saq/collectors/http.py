# vim: sw=4:ts=4:et:cc=120

import collections
import datetime
import os
import os.path
import re
import socket
import logging
from tkinter import BROWSE
from typing import Generator, Type, override

from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.analysis.root import Submission
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import ANALYSIS_MODE_HTTP, ANALYSIS_TYPE_BRO_HTTP, SERVICE_BRO_HTTP_COLLECTOR
from saq.environment import get_data_dir
from saq.service import ACEServiceInterface

REGEX_CONNECTION_ID = re.compile(r'^(C[^\.]+\.\d+)\.ready$')
HTTP_DETAILS_REQUEST = 'request'
HTTP_DETAILS_REPLY = 'reply'
HTTP_DETAILS_READY = 'ready'

class BroHTTPStreamCollector(Collector):
    """Collects BRO HTTP streams for analysis."""
    
    def __init__(self):
        super().__init__()
        
        # the location of the incoming http streams
        self.bro_http_dir = os.path.join(get_data_dir(), get_service_config(SERVICE_BRO_HTTP_COLLECTOR).http_dir)
        
        # for tool_instance
        self.hostname = socket.getfqdn()
    
    def collect(self) -> Generator[Submission, None, None]:
        """Collect HTTP streams and yield them as Submission objects."""
        # collect a list of streams to process
        stream_list = collections.deque()
        
        for file_name in os.listdir(self.bro_http_dir):
            m = REGEX_CONNECTION_ID.match(file_name)
            if m:
                # found a "ready" file indicating the stream is ready for processing
                stream_prefix = m.group(1)
                logging.info("found http stream {}".format(stream_prefix))

                # these are all the possible files that can exist for a single stream request/response
                source_files = [ os.path.join(self.bro_http_dir, '{}.request'.format(stream_prefix)),
                                 os.path.join(self.bro_http_dir, '{}.request.entity'.format(stream_prefix)),
                                 os.path.join(self.bro_http_dir, '{}.reply'.format(stream_prefix)),
                                 os.path.join(self.bro_http_dir, '{}.reply.entity'.format(stream_prefix)),
                                 os.path.join(self.bro_http_dir, '{}.ready'.format(stream_prefix)) ]

                # filter this list down to what is actually available for this one
                source_files = [f for f in source_files if os.path.exists(f)]

                # create a new submission request for this
                from saq.analysis.root import RootAnalysis
                
                root = RootAnalysis(
                    desc = 'BRO HTTP Scanner Detection - {}'.format(stream_prefix),
                    analysis_mode = ANALYSIS_MODE_HTTP,
                    tool = 'ACE - Bro HTTP Scanner',
                    tool_instance = self.hostname,
                    alert_type = ANALYSIS_TYPE_BRO_HTTP,
                    event_time = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(
                                                                                  self.bro_http_dir, file_name))),
                    details = {},
                )
                
                # Add files to the root analysis
                for source_file in source_files:
                    if os.path.exists(source_file):
                        http_observable = root.add_file_observable(source_file)
                        if http_observable:
                            http_observable.add_yara_meta("type", "network.http")
                
                submission = Submission(root)
                yield submission

class BroHTTPStreamCollectorService(ACEServiceInterface):
    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return ServiceConfig

    def __init__(self):
        self.collector = BroHTTPStreamCollector()
        self.collector_service = CollectorService(self.collector, config=get_service_config(SERVICE_BRO_HTTP_COLLECTOR))

    @override
    def start(self):
        self.collector_service.start()

    @override
    def wait_for_start(self, timeout: float = 5) -> bool:
        if not self.collector_service.wait_for_start(timeout):
            return False

        return True

    @override
    def start_single_threaded(self):
        self.collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    @override
    def stop(self):
        self.collector_service.stop()

    @override
    def wait(self):
        self.collector_service.wait()
