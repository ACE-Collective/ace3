import base64
import logging
import os
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.filesystem import safe_filename

from lxml import etree

from saq.util.strings import format_item_list_for_summary


class _XMLPlainTextDumper:
    def __init__(self, output_path):
        self.output_path = output_path
        self._data = []

    def start(self, tag, attrib):
        for attr in attrib:
            if 'instr' in attr:
                with open(self.output_path, 'a') as fp:
                    fp.write(attrib[attr])

    def end(self, tag):
        with open(self.output_path, 'a') as fp:
            fp.write(''.join(self._data))

        self._data.clear()

    def data(self, data):
        self._data.append(data)

    def close(self):
        pass

KEY_XML_PLAIN_TEXT = 'xml_plain_text'

class XMLPlainTextAnalysis(Analysis):
    """What does the XML document look like if you remove all the XML tags?"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_XML_PLAIN_TEXT: None,
        }

    @override
    @property
    def display_name(self):
        return "XML Plain Text Analysis"
 
    def generate_summary(self):
        return None

class XMLPlainTextAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return XMLPlainTextAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        if _file.file_name.endswith('.noxml'):
            return AnalysisExecutionResult.COMPLETED

        # is the file too big?
        if os.path.getsize(local_file_path) > self.config.getint('maximum_size'):
            logging.debug(f"{local_file_path} is too large for xml plain text analysis")
            return AnalysisExecutionResult.COMPLETED

        # make sure this is an XML document
        with open(local_file_path, 'rb') as fp:
            data = fp.read(1024)

        if b'<?xml' not in data:
            logging.debug("{} is not an XML document".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        # this file must have been extracted from a word document
        source_document = [r.target for r in _file.relationships if r.r_type == R_EXTRACTED_FROM]
        if not source_document:
            logging.debug("file {} was not extracted from anything".format(_file))
            return AnalysisExecutionResult.COMPLETED

        source_document = source_document[0]
        if not source_document.has_tag('microsoft_office'):
            logging.debug("file {} was not tagged as microsoft_office".format(_file))
            return AnalysisExecutionResult.COMPLETED

        output_path = '{}.noxml'.format(local_file_path)
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception as e:
                logging.error("unable to delete {}: {}".format(output_path, e))

        analysis = self.create_analysis(_file)

        parser = etree.XMLParser(target=_XMLPlainTextDumper(output_path))
        try:
            etree.parse(local_file_path, parser)
            if os.path.exists(output_path) and os.path.getsize(output_path):
                _file = analysis.add_file_observable(output_path, volatile=True)
                if _file:
                    analysis.details = { KEY_XML_PLAIN_TEXT : _file.file_path }
        except Exception as e:
            logging.info("unable to parse XML file {}: {}".format(_file, e))

        return AnalysisExecutionResult.COMPLETED

class _XMLParser(object):
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.output_path = None
        self._data = []
        self.extracted_files = []
        self.path = []

    def start(self, tag, attrib):
        if tag == PART_TAG:
            if PART_NAME in attrib:
                file_name = safe_filename(attrib[PART_NAME])
                self.output_path = os.path.join(self.output_dir, file_name[1:])

        if tag == DATA_TAG:
            self._data.clear()

    def end(self, tag):
        if tag == DATA_TAG and self.output_path and self._data:
            try:
                if not os.path.isdir(os.path.dirname(self.output_path)):
                    os.makedirs(os.path.dirname(self.output_path))

                logging.debug("extracting base64 encoded XML binary data into {}".format(self.output_path))
                with open(self.output_path, 'wb') as fp:
                    fp.write(base64.b64decode(''.join(self._data)))

                self.extracted_files.append(self.output_path)

            except Exception as e:
                logging.error("unable to extract base64 encoded data: {}".format(e))

            finally:
                self._data.clear()
                self.output_path = None

    def data(self, data):
        if self.output_path:
            self._data.append(data)

    def close(self):
        return self.extracted_files

PART_TAG = '{http://schemas.microsoft.com/office/2006/xmlPackage}part'
PART_NAME = '{http://schemas.microsoft.com/office/2006/xmlPackage}name'
DATA_TAG = '{http://schemas.microsoft.com/office/2006/xmlPackage}binaryData'

KEY_EXTRACTED_FILES = "extracted_files"

class XMLBinaryDataAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_EXTRACTED_FILES: []
        }

    @override
    @property
    def display_name(self):
        return "XML Binary Data Analysis"

    @property
    def extracted_files(self):
        return self.details[KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value):
        self.details[KEY_EXTRACTED_FILES] = value

    def generate_summary(self):
        if not self.extracted_files:
            return None

        return f"{self.display_name}: extracted {format_item_list_for_summary(self.extracted_files)}"

class XMLBinaryDataAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return XMLBinaryDataAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        # make sure this is an XML document
        with open(local_file_path, 'rb') as fp:
            data = fp.read(1024)
        
        if b'<?xml' not in data:
            logging.debug("{} is not an XML document".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        if b'Word.Document' not in data:
            logging.debug("{} is not a Word.Document".format(local_file_path))
            return AnalysisExecutionResult.COMPLETED

        try:

            analysis = self.create_analysis(_file)
            assert isinstance(analysis, XMLBinaryDataAnalysis)
            parser = etree.XMLParser(target=_XMLParser('{}.xml'.format(local_file_path)))
            extracted_files = etree.parse(local_file_path, parser)

            for extracted_file in extracted_files:
                rel_path = os.path.relpath(extracted_file, start=self.get_root().storage_dir)
                analysis.add_file_observable(extracted_file, volatile=True)
                analysis.extracted_files.append(rel_path)

        except Exception as e:
            logging.info("xml parsing failed for {}: {}".format(local_file_path, e))
            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED