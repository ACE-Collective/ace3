import logging
import os
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_SANDBOX, F_FILE, AnalysisExecutionResult
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_office_ext, is_ole_file, is_rtf_file, is_zip_file
from saq.observables.file import FileObservable


KEY_TYPE = 'type'
KEY_MACROS = 'macros'
KEY_PATH = 'path'
#KEY_FILENAME = 'filename'
#KEY_STREAM_PATH = 'stream_path'
#KEY_VBA_FILENAME = 'vba_filename'
#KEY_ANALSIS = 'analysis'
#KEY_OLEVBA_SUMMARY = 'olevba_summary'
#KEY_ALL_MACRO_CODE = 'all_macro_code'
KEY_KEYWORD_SUMMARY = 'keyword_summary'

class OLEVBA_Analysis_v1_2(Analysis):
    """Does this office document have macros?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_TYPE: None,
            KEY_MACROS: [],
            #KEY_ALL_MACRO_CODE: None,
            KEY_KEYWORD_SUMMARY: {},
        } 

    @override
    @property
    def display_name(self) -> str:
        return "OLEVBA Analysis"

    @property
    def type(self):
        return self.details[KEY_TYPE]

    @type.setter
    def type(self, value):
        self.details[KEY_TYPE] = value

    @property
    def macros(self):
        return self.details[KEY_MACROS]

    @macros.setter
    def macros(self, value):
        self.details[KEY_MACROS] = value

    #@property
    #def all_macro_code(self):
        #return self.details_property(KEY_ALL_MACRO_CODE)

    #@all_macro_code.setter
    #def all_macro_code(self, value):
        #self.details[KEY_ALL_MACRO_CODE] = value

    @property
    def keyword_summary(self):
        return self.details[KEY_KEYWORD_SUMMARY]

    @keyword_summary.setter
    def keyword_summary(self, value):
        self.details[KEY_KEYWORD_SUMMARY] = value

    def generate_summary(self):
        if not self.type or not self.macros:
            return None

        result = '{}: ({} macro files) ({})'.format(self.display_name, len(self.macros), self.type)
        if self.macros:
            result += ' | '
            result += ', '.join(['{}={}'.format(x, self.keyword_summary[x]) for x in self.keyword_summary.keys()])

        return result

class OLEVBA_Analyzer_v1_2(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return OLEVBA_Analysis_v1_2

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def merge_macros(self):
        return self.config.getboolean('merge_macros')

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        # ignore rtf files
        if is_rtf_file(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        # ignore MSI files
        if local_file_path.lower().endswith('.msi'):
            return AnalysisExecutionResult.COMPLETED

        # ignore files we're not interested in
        if not ( is_office_ext(local_file_path) or is_ole_file(local_file_path) or is_zip_file(local_file_path) ):
            return AnalysisExecutionResult.COMPLETED

        # ignore large files
        if _file.size > 1024 * 1024 * 4: # 4MB
            return AnalysisExecutionResult.COMPLETED

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis:
            return AnalysisExecutionResult.COMPLETED

        # sometimes we end up with HTML files with office extensions (mostly from downloaded from the Internet)
        if 'html' in file_type_analysis.mime_type:
            return AnalysisExecutionResult.COMPLETED

        # ignore plain text files
        if file_type_analysis.mime_type == 'text/plain':
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        from oletools.olevba3 import VBA_Parser, filter_vba
        parser = None

        try:
            parser = VBA_Parser(local_file_path, relaxed=True)
            analysis.type = parser.type

            current_macro_index = None
            output_dir = None

            if parser.detect_vba_macros():
                analysis.scan_results = parser.analyze_macros(
                        show_decoded_strings=True, 
                        deobfuscate=False) # <-- NOTE setting that to True causes it to hang in 0.55.1

                for file_name, stream_path, vba_filename, vba_code in parser.extract_all_macros():
                    if current_macro_index is None:
                        current_macro_index = 0
                        output_dir = '{}.olevba'.format(local_file_path)
                        if not os.path.isdir(output_dir):
                            os.mkdir(output_dir)

                    if self.merge_macros:
                        output_path = os.path.join(output_dir, 'macros.bas')
                    else:
                        output_path = os.path.join(output_dir, 'macro_{}.bas'.format(current_macro_index))

                    if isinstance(vba_code, bytes):
                        vba_code = vba_code.decode('utf8', errors='ignore')

                    vba_code = filter_vba(vba_code)
                    if not vba_code.strip():
                        continue

                    with open(output_path, 'a') as fp:
                        fp.write(vba_code)

                    file_observable = analysis.add_file_observable(output_path, volatile=True)
                    if file_observable:
                        file_observable.redirection = _file
                        file_observable.add_tag('macro')
                        file_observable.add_directive(DIRECTIVE_SANDBOX)
                        analysis.macros.append({'file_name': file_name,
                                                'stream_path': stream_path,
                                                'vba_filename': vba_filename,
                                                'vba_code': vba_code,
                                                'local_path': file_observable.value})

                        # this analysis module will analyze it's own output so we need to not do that
                        file_observable.exclude_analysis(self)

                    current_macro_index += 1

                if analysis.scan_results:
                    analysis.keyword_summary = {}
                    for _type, keyword, description in analysis.scan_results:
                        if _type not in analysis.keyword_summary:
                            analysis.keyword_summary[_type.lower()] = 0

                        analysis.keyword_summary[_type.lower()] += 1

                    # do the counts exceed the thresholds?
                    threshold_exceeded = True
                    for option in self.config.keys():
                        if option.startswith("threshold_"):
                            _, kw_type = option.split('_', 1)

                            if kw_type not in analysis.keyword_summary:
                                logging.debug("threshold keyword {} not seen in {}".format(kw_type, local_file_path))
                                threshold_exceeded = False
                                break

                            if analysis.keyword_summary[kw_type] < self.config.getint(option):
                                logging.debug("count for {} ({}) does not meet threshold {} for {}".format(
                                              kw_type, analysis.keyword_summary[kw_type], self.config.getint(option), local_file_path))
                                threshold_exceeded = False
                                break

                            logging.debug("count for {} ({}) meets threshold {} for {}".format(
                                kw_type, analysis.keyword_summary[kw_type], self.config.getint(option), local_file_path))

                    # all thresholds passed (otherwise we would have returned by now)
                    if threshold_exceeded:
                        _file.add_tag('olevba') # tag it for alerting
                        _file.add_directive(DIRECTIVE_SANDBOX)
                
        except Exception as e:
            logging.warning("olevba execution error on {}: {}".format(local_file_path, e))
            #report_exception()

            # if the file ends with a microsoft office extension then we tag it
            if is_office_ext(local_file_path):
                _file.add_tag('olevba_failed')
                _file.add_directive(DIRECTIVE_SANDBOX)

            return AnalysisExecutionResult.COMPLETED

        finally:
            if parser:
                try:
                    parser.close()
                except Exception as e:
                    logging.error("unable to close olevba parser: {}".format(e))
                    report_exception()

        return AnalysisExecutionResult.COMPLETED