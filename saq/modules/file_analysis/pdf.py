import logging
import os
from subprocess import PIPE, Popen, TimeoutExpired
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, DIRECTIVE_EXTRACT_URLS, F_FILE, R_EXTRACTED_FROM
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_pdf_file
from saq.observables.file import FileObservable
from saq.util.filesystem import get_local_file_path


class PDFAnalysis(Analysis):
    pass # nothing generated

class PDFAnalyzer(AnalysisModule):
    """What is the raw PDF data after removing stream filters?"""

    def verify_environment(self):
        self.verify_config_exists('pdfparser_path')
        self.verify_path_exists(self.config['pdfparser_path'])

    @property
    def pdfparser_path(self):
        path = self.config['pdfparser_path']
        if os.path.isabs(path):
            return path
        return os.path.join(get_base_dir(), path)

    @property
    def generated_analysis_type(self):
        return PDFAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # do not analyze our own output
        if local_file_path.endswith('.pdfparser'):
            return AnalysisExecutionResult.COMPLETED

        # do not analyze OCR output
        if local_file_path.endswith('.ocr'):
            return AnalysisExecutionResult.COMPLETED

        # this file must actually be a PDF
        with open(local_file_path, 'rb') as fp:
            # the header can be anywhere in the first 1024 bytes
            # they released a change to the spec
            header = fp.read(1024)
            if b'%PDF-' not in header:
                #logging.debug("{0} is not a PDF file".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))
        analysis = self.create_analysis(_file)

        # we'll create an output file for the output of the pdf analysis
        pdfparser_output_file = '{}.pdfparser'.format(local_file_path)

        # run pdf parser
        with open(pdfparser_output_file, 'wb') as fp:
            p = Popen(['python3', self.pdfparser_path,
            '-f', '-w', '-v', '-c', '--debug', local_file_path], stdout=fp, stderr=PIPE)
            try:
                _, stderr = p.communicate(timeout=10)
            except TimeoutExpired as e:
                logging.warning("pdfparser timed out on {}".format(local_file_path))
                p.kill()
                _, stderr = p.communicate()

        if len(stderr) > 0:
            logging.warning("pdfparser returned errors for {}".format(local_file_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        file_observable = analysis.add_file_observable(pdfparser_output_file, volatile=True)

        if file_observable:
            # point actions back at the source ole file
            file_observable.redirection = _file
            file_observable.add_relationship(R_EXTRACTED_FROM, _file)
            # extract URLs from this file
            file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)

        # gs -sDEVICE=pdfwrite -dNOPAUSE -dBATCH -sOutputFile=output.pdf -c ".setpdfwrite <</NeverEmbed [ ]>> setdistillerparams" -f input.pdf
        # evaluate with ghostscript as well to try to get the URLs out of AES encrypted PDFs
        # changing command line to match our needs as the old commands were tailed for Qakbot PDFs we no longer observe
        gs_output_file = f"{local_file_path}.gs.pdf"
        p = Popen([
            "gs", 
            "-sDEVICE=pdfwrite", 
            "-o", gs_output_file,
            "-f", local_file_path], stdout=PIPE, stderr=PIPE)

        try:
            _, stderr = p.communicate(timeout=10)
        except TimeoutExpired as e:
            logging.warning("pdfparser timed out on {}".format(local_file_path))
            p.kill()
            _, stderr = p.communicate()

        if os.path.exists(gs_output_file) and os.path.getsize(gs_output_file) > 0:
            file_observable = analysis.add_file_observable(gs_output_file, volatile=True)

            if file_observable:
                # point actions back at the source ole file
                file_observable.redirection = _file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                # extract URLs from this file
                file_observable.add_directive(DIRECTIVE_EXTRACT_URLS)
                file_observable.exclude_analysis(self)

        return AnalysisExecutionResult.COMPLETED

KEY_STDOUT = 'stdout'
KEY_STDERR = 'stderr'
KEY_OUTPUT_PATH = 'output_path'

class PDFTextAnalysis(Analysis):
    """Converts a PDF to text for simple yara scanning."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_OUTPUT_PATH: None,
        }

    @property
    def stdout(self):
        return self.details[KEY_STDOUT]

    @stdout.setter
    def stdout(self, value):
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self):
        return self.details[KEY_STDERR]

    @stderr.setter
    def stderr(self, value):
        self.details[KEY_STDERR] = value

    @property
    def output_path(self):
        return self.details[KEY_OUTPUT_PATH]

    @output_path.setter
    def output_path(self, value):
        self.details[KEY_OUTPUT_PATH] = value

    def generate_summary(self):
        if not self.output_path:
            return None
        
        return "PDF Text Analysis"
    
class PDFTextAnalyzer(AnalysisModule):

    @property
    def pdftotext_path(self):
        return self.config['pdftotext_path']

    @property
    def timeout(self):
        return self.config.getint('timeout')

    def verify_environment(self):
        self.verify_config_exists('pdftotext_path')
        self.verify_path_exists(self.config['pdftotext_path'])

    @property
    def generated_analysis_type(self):
        return PDFTextAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.archive import ArchiveAnalyzer
        
        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # is this a PDF file?
        if not is_pdf_file(local_file_path):
            logging.debug("{} is not a pdf file".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        output_path = '{}.pdf_txt'.format(local_file_path)
        p = Popen([self.pdftotext_path, local_file_path, output_path], stdout=PIPE, stderr=PIPE)
        try:
            analysis.stdout, analysis.stderr = p.communicate(timeout=self.timeout)
        except TimeoutExpired:
            logging.warning(f"timeout executing {self.pdftotext_path} on {local_file_path}")
            return AnalysisExecutionResult.COMPLETED
        
        if len(analysis.stderr) > 0:
            logging.debug("pdftotext returned errors for {}".format(local_file_path))

        # add the output file as a new file to scan
        # the FILE type indicators are relative to the alert storage directory
        if os.path.exists(output_path):
            file_observable = analysis.add_file_observable(output_path, volatile=True)

            if file_observable:
                # point actions back at the source ole file
                file_observable.redirection = _file
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                analysis.output_path = file_observable.value
                # avoid analyzing these files with archive analyzer
                # 7z tends to choke
                file_observable.exclude_analysis(ArchiveAnalyzer)

        return AnalysisExecutionResult.COMPLETED