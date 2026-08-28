import logging
import os
from subprocess import PIPE, Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import AnalysisExecutionResult, F_FILE
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_email_file, is_jar_file, is_javascript_file, is_lnk_file, is_office_ext, is_ole_file, is_pdf_file, is_pe_file, is_rtf_file, is_x509, is_zip_file
from saq.observables.file import FileObservable


# maps a boolean detection stored in FileTypeAnalysis.details to the YARA
# yara_meta:type=<value> directive stamped on the file observable so that
# type-scoped YARA rules (meta_tags = "type=...") only scan matching files
YARA_META_TYPE_BY_DETAIL = [
    ('is_pdf_file',   'document.pdf'),
    ('is_rtf_file',   'document.rtf'),
    ('is_pe_file',    'executable'),
    ('is_jar_file',   'archive.jar'),
    ('is_x509',       'certificate.x509'),
    ('is_email_file', 'email'),
]

# mime types / extensions that gate the (relatively expensive) is_javascript_file
# check so we never run "node --check" against binaries, images, etc.
JAVASCRIPT_MIME_TYPES = frozenset({
    'text/javascript', 'application/javascript',
    'application/x-javascript', 'application/ecmascript', 'text/ecmascript',
})
JAVASCRIPT_EXTENSIONS = frozenset({'.js', '.mjs', '.cjs', '.jse'})


class FileTypeAnalysis(Analysis):
    """What kind of file is this?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            'type': None, 
            'mime': None
        }

    @override
    @property
    def display_name(self) -> str:
        return "File Type Analysis"

    @property
    def file_type(self):
        if self.details is None:
            return None

        if 'type' not in self.details:
            return None

        return self.details['type']

    @property
    def mime_type(self):
        if self.details is None:
            return None

        if 'mime' not in self.details:
            return None

        return self.details['mime']

    @property
    def is_office_ext(self):
        if not self.details:
            return False

        if 'is_office_ext' not in self.details:
            return False

        return self.details['is_office_ext']

    @property
    def is_ole_file(self):
        if not self.details:
            return False

        if 'is_ole_file' not in self.details:
            return False

        return self.details['is_ole_file']

    @property
    def is_rtf_file(self):
        if not self.details:
            return False

        if 'is_rtf_file' not in self.details:
            return False

        return self.details['is_rtf_file']

    @property
    def is_pdf_file(self):
        if not self.details:
            return False

        if 'is_pdf_file' not in self.details:
            return False

        return self.details['is_pdf_file']

    @property
    def is_pe_file(self):
        if not self.details:
            return False

        if 'is_pe_file' not in self.details:
            return False

        return self.details['is_pe_file']

    @property
    def is_zip_file(self):
        if not self.details:
            return False

        if 'is_zip_file' not in self.details:
            return False

        return self.details['is_zip_file']

    @property
    def is_office_document(self):
        if not self.details:
            return False

        if 'is_office_document' not in self.details:
            return False

        return self.details['is_office_document']

    @property
    def is_lnk_file(self):
        if not self.details:
            return False

        if 'is_lnk_file' not in self.details:
            return False

        return self.details['is_lnk_file']

    @property
    def is_msi_file(self):
        if not self.details:
            return False

        if 'is_msi_file' not in self.details:
            return False

        return self.details['is_msi_file']

    @property
    def is_x509(self):
        if not self.details:
            return False

        if 'is_x509' not in self.details:
            return False

        return self.details['is_x509']

    @property
    def is_jar_file(self):
        if not self.details:
            return False

        if 'is_jar_file' not in self.details:
            return False

        return self.details['is_jar_file']

    @property
    def is_email_file(self) -> bool:
        if not self.details:
            return False

        if 'is_email_file' not in self.details:
            return False

        return self.details['is_email_file']

    def generate_summary(self):
        result = "File Type Analysis: {0} ({1})".format(
            self.details['type'] if self.details['type'] else '',
            self.details['mime'] if self.details['mime'] else '')

        if self.is_email_file:
            result += " (email)"

        if self.is_office_ext or self.is_office_document:
            result += " (ms office document)"

        if self.is_ole_file:
            result += " (ole compound file)"

        if self.is_rtf_file:
            result += " (rtf document)"

        if self.is_pdf_file:
            result += " (pdf document)"

        if self.is_pe_file:
            result += " (portable executable)"

        if self.is_zip_file:
            result += " (zip archive)"

        if self.is_lnk_file:
            result += " (windows shortcut)"

        if self.is_x509:
            result += " (x.509 certificate)"

        if self.is_jar_file:
            result += " (java archive)"

        return result

class FileTypeAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FileTypeAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("analyzing file {}".format(local_file_path))
        analysis = self.create_analysis(_file)

        # get the human readable
        p = Popen(['file', '-b', '-L', local_file_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        
        if len(stderr) > 0:
            logging.warning("file command returned error output for {0}".format(local_file_path))

        analysis.details['type'] = stdout.decode().strip()

        # get the mime type
        p = Popen(['file', '-b', '--mime-type', '-L', local_file_path], stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        
        if len(stderr) > 0:
            logging.warning("file command returned error output for {0}".format(local_file_path))

        analysis.details['mime'] = stdout.decode().strip()

        # stamp the mime type onto the observable so it is serialized with the alert.
        # The alert page reads FileObservable.mime_type (via is_image) for every file
        # observable it renders; without this it forks `file` again for each one, on
        # every page load.
        _file.mime_type = analysis.details['mime']

        # the page also scales image previews -- computing the dimensions here means PIL
        # opens each image once, at analysis time, instead of on every render
        if _file.is_image:
            _file.compute_scaled_dimensions()

        analysis.details['is_office_ext'] = is_office_ext(local_file_path)
        analysis.details['is_ole_file'] = is_ole_file(local_file_path)
        analysis.details['is_rtf_file'] = is_rtf_file(local_file_path)
        analysis.details['is_pdf_file'] = is_pdf_file(local_file_path)
        analysis.details['is_pe_file'] = is_pe_file(local_file_path)
        analysis.details['is_zip_file'] = is_zip_file(local_file_path)
        analysis.details['is_x509'] = is_x509(local_file_path)
        analysis.details['is_lnk_file'] = is_lnk_file(local_file_path)
        analysis.details['is_jar_file'] = analysis.is_zip_file and is_jar_file(local_file_path)

        analysis.details['is_email_file'] = is_email_file(local_file_path)
        analysis.details['is_email_file'] |= analysis.details['mime'] == 'message/rfc822'

        is_office_document = analysis.details['is_office_ext']
        is_office_document |= 'microsoft powerpoint' in analysis.file_type.lower()
        is_office_document |= 'microsoft excel' in analysis.file_type.lower()
        is_office_document |= 'microsoft word' in analysis.file_type.lower()
        is_office_document |= 'microsoft ooxml' in analysis.file_type.lower()
        is_office_document |= analysis.details['is_ole_file']
        is_office_document |= analysis.details['is_rtf_file']
        analysis.details['is_office_document'] = is_office_document

        # perform some additional analysis for some things we care about

        if is_office_document:
            _file.add_tag('microsoft_office')

        if analysis.is_ole_file:
            _file.add_tag('ole')

        if analysis.is_rtf_file:
            _file.add_tag('rtf')

        if analysis.is_pdf_file:
            _file.add_tag('pdf')

        if analysis.is_pe_file:
            _file.add_tag('executable')

        if analysis.is_zip_file:
            _file.add_tag('zip')

        if analysis.is_lnk_file:
            _file.add_tag('lnk')

        if analysis.is_x509:
            _file.add_tag('x509')

        if analysis.is_jar_file:
            _file.add_tag('jar')

        if analysis.is_email_file:
            _file.add_tag('email')

        if analysis.details['mime'].startswith('image/'):
            _file.add_yara_meta("type", "image")

        for detail_key, meta_value in YARA_META_TYPE_BY_DETAIL:
            if analysis.details.get(detail_key):
                _file.add_yara_meta("type", meta_value)

        if analysis.details['mime'] in ('text/html', 'application/xhtml+xml'):
            _file.add_yara_meta("type", "document.html")

        # only run the "node --check" based javascript detection when the mime
        # or extension already suggests javascript, to catch content that the
        # file command mislabels (e.g. as text/plain) without checking every file
        _, ext = os.path.splitext(_file.file_name.lower())
        if (analysis.details['mime'] in JAVASCRIPT_MIME_TYPES or ext in JAVASCRIPT_EXTENSIONS) \
                and is_javascript_file(local_file_path):
            _file.add_yara_meta("type", "script.javascript")

        return AnalysisExecutionResult.COMPLETED
