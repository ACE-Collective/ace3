from datetime import datetime
import logging
import os
from lxml import etree
from urllib.parse import urlparse

from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_FORCE_DOWNLOAD, F_FILE, F_URL, AnalysisExecutionResult
from saq.crypto import encrypt
from saq.environment import get_data_dir
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_office_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


class _xml_parser:
    def __init__(self):
        self.urls = [] # the list of urls we find


    def start(self, tag, attrib):
        if not tag.endswith('Relationship'):
            return

        if 'Type' not in attrib:
            return

        if 'TargetMode' not in attrib:
            return

        if 'Target' not in attrib:
            return

        if not attrib['Type'].endswith('/oleObject'):
            return

        if attrib['TargetMode'] != 'External':
            return

        self.urls.append(attrib['Target'])

    def end(self, tag):
        pass

    def data(self, data):
        pass

    def close(self):
        pass

KEY_URLS = 'urls'

class OfficeXMLRelationshipExternalURLAnalysis(Analysis):
    """Extracts URLs from Office XML relationship files."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_URLS: [],
        }

    @property
    def display_name(self):
        return "Office XML URL Analysis"

    @property
    def urls(self):
        return self.details[KEY_URLS]

    @urls.setter
    def urls(self, value):
        self.details[KEY_URLS] = value

    def generate_summary(self):
        if not self.urls:
            return None

        domains = set()
        for url in self.urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            except Exception:
                pass

        domains = sorted(domains)

        return f"{self.display_name}: {format_item_list_for_summary(domains)}"

class OfficeXMLRelationshipExternalURLAnalyzer(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return OfficeXMLRelationshipExternalURLAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        if os.path.basename(local_file_path) != 'document.xml.rels':
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        parser_target = _xml_parser()
        parser = etree.XMLParser(target=parser_target)
        try:
            etree.parse(local_file_path, parser)
        except Exception as e:
            logging.warning("unable to parse XML file {}: {}".format(_file, e))

        for url in parser_target.urls:
            url = analysis.add_observable_by_spec(F_URL, url)
            url.add_directive(DIRECTIVE_FORCE_DOWNLOAD)
            _file.add_detection_point('{} contains a link to an external oleobject'.format(_file))

        analysis.urls = parser_target.urls

        return AnalysisExecutionResult.COMPLETED

class OfficeFileArchiveAction(Analysis):
    pass

class OfficeFileArchiver(AnalysisModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.existing_subdir = None

    @property
    def generated_analysis_type(self):
        return OfficeFileArchiveAction

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def office_archive_dir(self):
        """Relative path to the directory that contains archived office documents."""
        return os.path.join(get_data_dir(), self.config['office_archive_dir'])

    def verify_environment(self):
        self.verify_config_exists('office_archive_dir')
        self.create_required_directory(self.office_archive_dir)

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        self.wait_for_analysis(_file, FileTypeAnalysis)
        if not is_office_file(_file):
            return AnalysisExecutionResult.COMPLETED

        t = datetime.now()
        subdir = os.path.join(self.office_archive_dir, t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'))
        
        # is this different than the last time we checked?
        if subdir != self.existing_subdir:
            self.existing_subdir = subdir
            if not os.path.isdir(self.existing_subdir):
                os.makedirs(self.existing_subdir)

        i = 0
        target_path = os.path.join(self.existing_subdir, '{:06}_{}'.format(i, _file.file_name))
        while os.path.exists(target_path):
            i += 1
            target_path = os.path.join(self.existing_subdir, '{:06}_{}'.format(i, _file.file_name))

        target_path += '.e'
        encrypt(local_file_path, target_path)
        logging.debug("archived office file {}".format(target_path))

        analysis = self.create_analysis(_file)
        analysis.details = target_path
        return AnalysisExecutionResult.COMPLETED