import base64
import email
import logging
from mmap import PROT_READ, mmap
import os
import re
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL, F_FILE, F_URL, R_DOWNLOADED_FROM, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.filesystem import map_mimetype_to_file_ext
from saq.util.strings import format_item_list_for_summary

KEY_URL = "url"


class MetaRefreshExtractionAnalysis(Analysis):
    """Does this HTML file downloaded from the Internet have a meta-redirect?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_URL: None
        }

    @override
    @property
    def display_name(self) -> str:
        return "Meta Refresh Analysis"

    @property
    def url(self):
        return self.details[KEY_URL]

    @url.setter
    def url(self, value):
        self.details[KEY_URL] = value

    def generate_summary(self):
        if self.url is None:
            return None

        return f"{self.display_name}: Detected meta-refresh to {self.url}"

class MetaRefreshExtractionAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MetaRefreshExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        # the file must have been downloaded from a URL
        # doesn't really matter what URL, just needs the downloaded_from relationship
        if not _file.has_relationship(R_DOWNLOADED_FROM):
            return AnalysisExecutionResult.COMPLETED

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        if os.path.getsize(local_file_path) == 0:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        try:
            import bs4

            with open(local_file_path, 'rb') as fp:
                # we're only going took at the first 8K of the file
                # that's where these things are usually at and we don't want to kill RAM loading binary files
                # since we're not going to try to guess if it's HTML or not here
                content = fp.read(1024 * 8)

            # based this on this post
            # https://stackoverflow.com/questions/2318446/how-to-follow-meta-refreshes-in-python
            soup  = bs4.BeautifulSoup(content.decode(errors='ignore'), 'lxml')

            for meta in soup.find_all(lambda x: x.name.lower() == 'meta'):
                if 'http-equiv' in meta.attrs and meta.attrs['http-equiv'].lower() == 'refresh':
                    wait, text = meta['content'].split(';')
                    if text.strip().lower().startswith("url="):
                        url = text[4:]
                        url_observable = analysis.add_observable_by_spec(F_URL, url)
                        if url_observable:
                            url_observable.add_directive(DIRECTIVE_CRAWL)
                        logging.info("found meta refresh url {} from {}".format(url, _file))

                        analysis.details = url
            
        except Exception as e:
            logging.info("meta refresh extraction failed (usually ok): {}".format(e))
            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED

KEY_EXTRACTED_FILES = "extracted_files"

class MHTMLAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_EXTRACTED_FILES: []
        }

    @override
    @property
    def display_name(self) -> str:
        return "MHTML Analysis"

    @property
    def extracted_files(self):
        return self.details[KEY_EXTRACTED_FILES]

    @extracted_files.setter
    def extracted_files(self, value):
        self.details[KEY_EXTRACTED_FILES] = value

    def generate_summary(self):
        if not self.extracted_files:
            return None

        return f"{self.display_name}: {format_item_list_for_summary(self.extracted_files)}"

class MHTMLAnalysisModule(AnalysisModule):

    # list of supported file extensions for this module
    MHTML_FILE_EXTENSIONS = [ '.mhtml', '.mht' ]

    # simple regex looking for start of a MIME header
    RE_HEADER = re.compile(b'^[a-zA-Z0-9-_]+:')

    @property
    def generated_analysis_type(self):
        return MHTMLAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def verify_environment(self):
        pass

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        matching_file_ext = False
        for file_ext in self.MHTML_FILE_EXTENSIONS:
            if _file.file_name.lower().endswith(file_ext):
                matching_file_ext = True
                break

        if not matching_file_ext:
            return AnalysisExecutionResult.COMPLETED

        try:
            parser = email.parser.BytesFeedParser()
            state_started_headers = False
            with open(local_file_path, 'rb') as fp:
                # skip any garbage at the start of the file
                for line in fp:
                    if not state_started_headers:
                        if not self.RE_HEADER.search(line):
                            continue
                        else:
                            state_started_headers = True

                    parser.feed(line)

            parsed_file = parser.close()

        except Exception as e:
            logging.warning(f"unable to parse {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        target_dir = f'{local_file_path}.extracted'
        if not os.path.exists(target_dir):
            try:
                os.mkdir(target_dir)
            except Exception as e:
                logging.error(f"unable to create {target_dir}: {e}")
                return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, MHTMLAnalysis)

        part_id = 0
        for part in parsed_file.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            part_name = f'file_{part_id}'
            part_id += 1

            # TODO try to determine what the file name should be
            #part_name = part.get_param('name')
            #if not part_name:

            try:
                target_path = os.path.join(target_dir, part_name)

                payload = part.get_payload(decode=True)
                if not payload:
                    logging.warning(f"unable to get payload from {target_path} for part {part_id}")
                    continue

                with open(target_path, 'wb') as fp:
                    fp.write(part.get_payload(decode=True))

                file_observable = analysis.add_file_observable(target_path, volatile=True)
                if file_observable:
                    _file.copy_directives_to(file_observable)
                    analysis.extracted_files.append(file_observable.value)

            except Exception as e:
                logging.error(f"unable to extract part #{part_id - 1} from {_file}: {e}")

        return AnalysisExecutionResult.COMPLETED

class HTMLDataURLAnalysis(Analysis):

    KEY_COUNT = "count"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            self.KEY_COUNT: 0,
        }

    @override
    @property
    def display_name(self) -> str:
        return "HTML Data URL Analysis"

    @property
    def count(self):
        return self.details[self.KEY_COUNT]

    @count.setter
    def count(self, value):
        self.details[self.KEY_COUNT] = value

    def generate_summary(self) -> str:
        if not self.count:
            return None

        return f"{self.display_name}: Extracted {self.count} Data URLs"

RE_HTML_EMBED = re.compile(b"data:([^/]+/[^;]+);base64,([-A-Za-z0-9+/=]+)")

class HTMLDataURLAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return HTMLDataURLAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def max_bytes(self):
        return int(self.config.get("max_bytes", 104857600))

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        analysis = None

        # map the file into memory so it can be scanned
        count = 0
        with open(local_file_path, "rb") as f:
            mm = mmap(f.fileno(), min([self.max_bytes, os.path.getsize(local_file_path)]), prot=PROT_READ) # XXX add limit
            for mime_type, b64data in RE_HTML_EMBED.findall(mm):
                # try to decoded the base64 data
                try:
                    decoded = base64.b64decode(b64data)
                except Exception as e:
                    logging.info(f"unable to decode base64 from html embed: {e}")
                    continue

                # TODO figure out a possible file extension based on mime type
                ext = map_mimetype_to_file_ext(mime_type.decode())

                # build local file path for this embedded document
                target_file_path = f"{local_file_path}_embed_{count}.{ext}"
                with open(target_file_path, "wb") as fp_out:
                    fp_out.write(decoded)
                    logging.info(f"extracted {len(decoded)} from {local_file_path} into {target_file_path}")

                if analysis is None:
                    analysis = self.create_analysis(_file)

                file_observable = analysis.add_file_observable(target_file_path, volatile=True)
                if file_observable:
                    file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                    # don't recurse on extracted document
                    file_observable.exclude_analysis(self)
                    analysis.count += 1

                count += 1

        return AnalysisExecutionResult.COMPLETED