import logging
import os
from subprocess import PIPE, Popen
from typing import Type

from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import AnalysisExecutionResult, F_IPV4, F_IPV4_CONVERSATION, F_IPV4_FULL_CONVERSATION, parse_ipv4_conversation, parse_ipv4_full_conversation
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import ExternalProcessAnalysisModule
from saq.modules.config import AnalysisModuleConfig

def _compute_target_sensor(observable: Observable) -> str:
    """Computes the target sensor for a given Observable.
    Returns the name of the target sensor, or, None if the directive does not exist."""
    try:
        for directive in observable.directives:
            if directive.startswith("target_sensor_"):
                target_sensor = directive[len("target_sensor_"):].strip()
                if target_sensor:
                    logging.info(f"target sensor for {observable.value} is {target_sensor}")
                    return target_sensor
    except Exception as e:
        logging.error(f"unable to compute target sensor for {observable}: {e}")
        report_exception()

    return None


class PcapExtractionAnalysis(Analysis):
    """What was the network traffic for this IP address or conversation?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "stdout": None,
            "stderr": None,
            "output_file": None,
            "error": None,
        }

    def generate_summary(self):
        if self.details['output_file'] is None:
            return None

        return f"Sensor PCAP Extraction: {self.details['error'] if self.details['error'] else self.details['output_file']}"

class PcapConversationExtractionConfig(AnalysisModuleConfig):
    relative_duration: str = Field(..., description="The relative time capture (see -d option of the extract script).")
    executable_path: str = Field(..., description="The pcap executable path.")
    config_path: str = Field(..., description="The custom pcap extraction configuration path for ACE.")
    exclude_internal_network: str = Field(..., description="The exclude internal network.")
    max_pcap_count: int = Field(..., description="The maximum total number of pcap files we should get for a single alert.")
    max_size: int = Field(..., description="The maximum size (in MB) of pcap we collect from each sensor.")

class PcapConversationExtraction(ExternalProcessAnalysisModule):
    """Automatically pulls pcap for any FIPV4_CONVERSATION that comes in with an Alert."""

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return PcapConversationExtractionConfig

    def verify_environment(self):
        self.verify_path_exists(self.config['executable_path'])
        self.verify_path_exists(self.config['config_path'])
    
    @property
    def relative_duration(self):
        return self.config['relative_duration']

    @property
    def executable_path(self):
        path = self.config['executable_path']
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def config_path(self):
        path = self.config['config_path']
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def max_pcap_count(self):
        return self.config.getint('max_pcap_count')

    @property
    def max_size(self):
        return self.config.getint('max_size')

    @property
    def generated_analysis_type(self):
        return PcapExtractionAnalysis

    @property
    def valid_observable_types(self):
        return [ F_IPV4_CONVERSATION, F_IPV4_FULL_CONVERSATION ]

    def execute_analysis(self, conversation) -> AnalysisExecutionResult:

        # we only pull pcap for IP addresseses that 
        # 1) came with the alert
        # 2) is suspect (see https://wiki.local/w/index.php/ACE_Development_Guide#Detection_Points)
        if not conversation in self.get_root().observables and not conversation.has_detection_points():
            logging.debug("{} does not meet criteria for extraction".format(conversation))
            return AnalysisExecutionResult.COMPLETED

        # are we at our limit?
        if self.get_root().get_action_counter('pcap_conversation') >= self.max_pcap_count:
            logging.debug("exceeded pcap_conversation count skipping pcap extract for {}".format(conversation))
            return AnalysisExecutionResult.COMPLETED

        # if BOTH addresses are excluded then we do not collect PCAP
        # XXX do we still need this?  we have built-in exclusions support now
        if conversation.type == F_IPV4_CONVERSATION:
            src_ipv4, dst_ipv4 = parse_ipv4_conversation(conversation.value)
        else:
            src_ipv4, _, dst_ipv4, _ = parse_ipv4_full_conversation(conversation.value)

        #if self.is_excluded(IPv4Observable(src_ipv4)) and self.is_excluded(IPv4Observable(dst_ipv4)):
            #logging.debug("excluding conversation {}".format(conversation.value))
            #return False

        pcap_dir = os.path.join(self.get_root().storage_dir, 'pcap', '{0}_pcap'.format(conversation))
        extraction_time = conversation.time if conversation.time is not None else self.get_root().event_time

        file_name = "sensor_"
        if conversation.type == F_IPV4:
            file_name += conversation.value
        elif conversation.type == F_IPV4_CONVERSATION:
            file_name += conversation.value
        elif conversation.type == F_IPV4_FULL_CONVERSATION:
            file_name += conversation.value.replace(':', '_')

        file_name += ".pcap"

        pcap_file_path = self.get_root().create_file_path(file_name)

        # if the observable has the directive target_sensor_HOST then we know what host to target
        target_sensor = _compute_target_sensor(conversation)

        logging.debug("collecting pcap from {} into {} target {} at time {}".format(conversation, pcap_dir, pcap_file_path, extraction_time))

        result_OK, _stdout, _stderr = self.extract_pcap(
            conversation=conversation,
            target_sensor=target_sensor,
            event_time=extraction_time,
            output_dir=pcap_dir,
            output_path=pcap_file_path)

        if result_OK:
            analysis = self.create_analysis(conversation)
            analysis.details['stdout'] = _stdout
            analysis.details['stderr'] = _stderr
            analysis.details['output_file'] = file_name
            self.get_root().increment_action_counter('pcap_conversation')
            # a pcap file with only 92 bytes is an empty pcap files -- don't add it
            if os.path.getsize(pcap_file_path) > 92:
                pcap_observable = analysis.add_file_observable(pcap_file_path)
                if pcap_observable:
                    pcap_observable.add_yara_meta("type", "network.pcap")
            else:
                analysis.details['error'] = "empty pcap file"
            return AnalysisExecutionResult.COMPLETED

        else:
            logging.warning("unable to get pcap for conversation {0}".format(conversation))
            return AnalysisExecutionResult.COMPLETED

    def extract_pcap(self, *args, **kwargs):
        try:
            # XXX this functionality moves to the engine
            #if not self.acquire_semaphore():
                #logging.warning("unable to acquire semaphore")
                #return False, None, None

            return self.extract_pcap_exec(*args, **kwargs)
        finally:
            self.release_semaphore()

    def extract_pcap_exec(self, conversation, target_sensor, event_time, output_dir, output_path):
        assert conversation is not None
        assert target_sensor is None or isinstance(target_sensor, str)
        assert output_dir is not None
        assert output_path is not None

        event_time = event_time.strftime('%Y-%m-%d %H:%M:%S %z')

        if conversation.type == F_IPV4_CONVERSATION:
            src, dst = parse_ipv4_conversation(conversation.value)
            bpf = '(host {} and host {})'.format(src, dst)
        elif conversation.type == F_IPV4_FULL_CONVERSATION:
            src, src_port, dst, dst_port = parse_ipv4_full_conversation(conversation.value)
            bpf = '((src {} and src port {} and dst {} and dst port {}) or (src {} and src port {} and dst {} and dst port {}))'.format(src, src_port, dst, dst_port, dst, dst_port, src, src_port)

        params = [ self.executable_path,
            '-c', self.config_path,
            '-m', str(self.max_size),
            '-o', output_path,
            '-D', output_dir,
            '-t', event_time,
            '-d', self.relative_duration,
            '-r' ]

        if target_sensor is not None:
            params.append('--sensor')
            params.append(target_sensor)

        params.append(bpf)

        logging.info("extracting pcap using BPF {} @ {} duration {} to {}".format(bpf, event_time, self.relative_duration, output_dir))

        # also collect stdout and stderr for troubleshooting
        # collect the pcap
        self.external_process = Popen(params, stdout = PIPE, stderr = PIPE)
        _stdout, _stderr = self.external_process.communicate()
    
        logging.debug("got return code {} for pcap_extract".format(self.external_process.returncode))

        if self.external_process.returncode != 0:
            logging.warning("pcap extraction returned {}".format(str(self.external_process.returncode)))
            return False, _stdout, _stderr

        return True, _stdout, _stderr