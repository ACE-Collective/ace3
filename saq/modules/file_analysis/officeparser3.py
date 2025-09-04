import logging
import os
import shutil
from subprocess import PIPE, Popen, TimeoutExpired
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_EXTRACT_URLS, DIRECTIVE_SANDBOX, F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_empty_macro, is_macro_ext
from saq.observables.file import FileObservable


class OfficeParserAnalysis3(Analysis):
    """Does this OLE file have macros or olenative streams?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "extracted_files": []
        }

    @property
    def extracted_files(self):
        return self.details["extracted_files"]

    @extracted_files.setter
    def extracted_files(self, value):
        self.details["extracted_files"] = value

    def generate_summary(self):
        if not self.details:
            return None

        if not self.extracted_files:
            return None

        return "OfficeParser3 Analysis: extracted {} files".format(len(self.extracted_files))

class OfficeParserAnalyzer3(AnalysisModule):
    def verify_environment(self):
        self.verify_config_exists('officeparser_path')
        self.verify_path_exists(self.config['officeparser_path'])
        self.verify_config_exists('timeout')

    @property
    def officeparser_path(self):
        return self.config['officeparser_path']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    @property
    def merge_macros(self):
        return self.config.getboolean('merge_macros')

    @property
    def generated_analysis_type(self):
        return OfficeParserAnalysis3

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        # is this an OLE document?
        with open(local_file_path, 'rb') as fp:
            header = fp.read(8)
            
            if header != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                logging.debug("{} is not an OLE Compound Document".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

        # make sure this is not an MSI file
        if local_file_path.lower().endswith('.msi'):
            logging.debug("not extracting MSI file {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        if file_type_analysis.file_type and 'windows installer' in file_type_analysis.file_type.lower():
            logging.debug("not extracting windows installer file {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        officeparser_output_dir = '{}.officeparser'.format(local_file_path)
        if not os.path.isdir(officeparser_output_dir):
            try:
                os.makedirs(officeparser_output_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(
                    officeparser_output_dir, str(e)))
                return AnalysisExecutionResult.COMPLETED

        # lol look at all these options
        p = Popen([
            self.officeparser_path,
            '-l', 'DEBUG',
            '--print-header',
            '--print-directory',
            '--print-fat',
            '--print-mini-fat',
            '--print-streams',
            '--print-expected-file-size',
            '--print-invalid-fat-count',
            '--check-stream-continuity',
            '--check-fat',
            '--check-orphaned-chains',
            '-o', officeparser_output_dir,
            '--extract-streams',
            '--extract-ole-streams',
            '--extract-macros',
            '--extract-unknown-sectors',
            '--create-manifest',
            local_file_path],
            stdout=PIPE,
            stderr=PIPE)

        try:
            stdout, stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired:
            logging.warning("timeout expired for officeparser on {}".format(local_file_path))
            _file.add_tag('officeparser_failed')
            _file.add_directive(DIRECTIVE_SANDBOX)

            #try:
                #p.kill()
            #except:
                #pass

            stdout, stderr = p.communicate()

        manifest_path = os.path.join(officeparser_output_dir, 'manifest')
        if not os.path.exists(manifest_path):
            #logging.warning("manifest {0} is missing".format(manifest_path))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, OfficeParserAnalysis3)

        with open(manifest_path, 'rb') as fp:
            while True:
                try:
                    output_file = fp.readline().decode()
                except Exception as e:
                    logging.info("trouble reading {}: {}".format(manifest_path, e))
                    continue

                if output_file == '':
                    break
            
                output_file = output_file.strip()
                logging.debug("got extracted file {} from {}".format(output_file, local_file_path))

                # we don't want to add the stream_N_N.dat files
                # after running this thing for a year we have never seen this be useful
                # 5/10/2017 - due to CVE 2017-0199 this is no longer the case

                full_path = os.path.join(officeparser_output_dir, output_file)
                # only add normal files
                try:
                    if not os.path.isfile(full_path):
                        logging.info("skipping non-file {}".format(full_path))
                        continue
                except Exception:
                    logging.error("unable to check status of {}".format(full_path))
                    continue

                # and do not add if the file is empty
                try:
                    if not os.path.getsize(full_path):
                        logging.debug("skipping empty file {}".format(full_path))
                        continue
                except Exception as e:
                    logging.error("unable to check size of {}: {}".format(full_path, e))
                    report_exception()

                # if this is a macro file we want to see if it is an "empty macro file"
                if is_macro_ext(output_file):
                    if is_empty_macro(full_path):
                        logging.debug("macro file {} appears to be empty".format(full_path))
                        continue

                    if self.merge_macros:
                        # we also want to merge them into a single file for yara scanning
                        macro_path = os.path.join(officeparser_output_dir, 'macros.bas')
                        with open(macro_path, 'ab') as fp_out:
                            with open(full_path, 'rb') as fp_in:
                                shutil.copyfileobj(fp_in, fp_out)

                        # switch the file we're looking at to this macros.bas we appended to
                        full_path = macro_path

                # and then FILE type indicators are relative to the alert storage directory
                file_observable = analysis.add_file_observable(full_path, volatile=True)

                if not file_observable:
                    continue

                analysis.extracted_files.append(output_file)

                # add a relationship back to the original file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)

                # extract URLs from these files
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

                # point actions back at the source ole file
                file_observable.redirection = _file

                if is_macro_ext(output_file):
                    file_observable.add_tag('macro')
                    # always sandbox office documents tagged with macros
                    file_observable.add_directive(DIRECTIVE_SANDBOX)

            return AnalysisExecutionResult.COMPLETED