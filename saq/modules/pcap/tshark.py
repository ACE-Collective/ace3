import logging
import os
import re
from subprocess import Popen
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_EXCLUDE_ALL, F_FILE, F_IPV4, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable


class TsharkAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "extracted_ipv4s": [],
        }

    def generate_summary(self):
        return f"Tshark PCAP Analysis: extracted {len(self.details['extracted_ipv4s'])} ipv4s"

class TsharkPcapAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return TsharkAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, pcap: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis import FileTypeAnalysis

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(pcap, FileTypeAnalysis)
        if file_type_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        # make sure the file exists
        if not pcap.exists:
            logging.error("pcap path {0} does not exist".format(pcap.value))
            return AnalysisExecutionResult.COMPLETED
    
        # make sure this is a pcap file
        if file_type_analysis.mime_type != 'application/vnd.tcpdump.pcap':
            if isinstance(pcap.value, str) and not pcap.file_name.lower().endswith(".pcap"):
                logging.info("invalid mime type: {0}".format(file_type_analysis.mime_type))
                return AnalysisExecutionResult.COMPLETED

        tshark_output_path = self.get_root().create_file_path('{0}.tshark'.format(pcap.value))
        tshark_stderr_path = self.get_root().create_file_path('{0}.tshark.stderr'.format(pcap.value))

        with open(tshark_output_path, 'wb') as stdout_fp:
            with open(tshark_stderr_path, 'wb') as stderr_fp:
                p = Popen(['tshark', '-t', 'a', '-V', '-r', os.path.join(self.get_root().storage_dir, pcap.value)], 
                    stdout=stdout_fp, stderr=stderr_fp)
                p.wait()

        if os.path.getsize(tshark_stderr_path) > 0:
            logging.error("tshark reported messages on stderr: {0}".format(tshark_stderr_path))
        else:
            try:
                os.remove(tshark_stderr_path)
            except Exception as e:
                logging.error("unable to delete {0}: {1}".format(tshark_stderr_path, str(e)))

        analysis = self.create_analysis(pcap)
        pcap.add_analysis(analysis)

        if os.path.getsize(tshark_output_path) > 0:
            file_observable = analysis.add_file_observable(tshark_output_path)
            if file_observable:
                file_observable.add_directive(DIRECTIVE_EXCLUDE_ALL)

            RE_TRUE_CLIENT_IP = re.compile(r"True-Client-IP: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
            RE_FORWARDED = re.compile(r"forwarded: for=")
            RE_FORWARDED_FOR = re.compile(r"for=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
            try:
                logging.info(f"parsing {tshark_output_path} for actual source IPs")
                with open(tshark_output_path, "r") as fp:
                    extracted_ipv4s = set()
                    for line in fp:
                        m = RE_TRUE_CLIENT_IP.search(line)
                        if m:
                            ipv4 = m.group(1)
                            ipv4_observable = analysis.add_observable_by_spec(F_IPV4, ipv4)
                            if ipv4_observable:
                                ipv4_observable.display_type = "True Client IP"
                                extracted_ipv4s.add(ipv4_observable.value)

                        m = RE_FORWARDED.search(line)
                        if m:
                            for m in RE_FORWARDED_FOR.finditer(line):
                                ipv4 = m.group(1)
                                ipv4_observable = analysis.add_observable_by_spec(F_IPV4, ipv4)
                                if ipv4_observable:
                                    ipv4_observable.display_type = "Forwarded For IP"
                                    extracted_ipv4s.add(ipv4_observable.value)

                    analysis.details["extracted_ipv4s"] = list(extracted_ipv4s)

            except Exception as e:
                logging.info(f"unable to parse {tshark_output_path}: {e}")

        return AnalysisExecutionResult.COMPLETED