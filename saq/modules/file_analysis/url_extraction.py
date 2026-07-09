import logging
import os
from typing import Type, override
from urllib.parse import urlparse
from pydantic import Field
from tld import get_tld
import validators
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL, F_FILE, F_URL, R_DOWNLOADED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.ocr import YARA_META_TYPE_OCR
from saq.observables.file import FileObservable
from saq.util.networking import is_subdomain

from urlfinderlib import find_urls, find_urls_in_text

from saq.util.strings import format_item_list_for_summary


KEY_URLS = "urls"


class URLExtractionConfig(AnalysisModuleConfig):
    max_file_size: int = Field(..., description="The maximum file size in bytes.")
    max_extracted_urls: int = Field(..., description="The maximum number of urls to extract from a single file.")
    excluded_domains: list[str] = Field(..., description="The list of FQDNs of urls to NOT extract (e.g., XML schema domains).")

class URLExtractionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_URLS: []
        }

    @override
    @property
    def display_name(self):
        return "URL Extraction Analysis"

    @property
    def urls(self) -> list[str]:
        return self.details[KEY_URLS]
    
    @urls.setter
    def urls(self, value: list[str]):
        self.details[KEY_URLS] = value

    def generate_summary(self):
        if not len(self.urls):
            return None

        # extract unique domain names from the URLs
        domains = set()
        for url in self.urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            except Exception as e:
                logging.debug(f"failed to parse url {url}: {e}")

        return f"{self.display_name} ({format_item_list_for_summary(sorted(list(domains)))})"

class URLExtractionAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return URLExtractionConfig

    @property
    def generated_analysis_type(self):
        return URLExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_EXTRACT_URLS ]

    @property
    def max_file_size(self):
        """The max file size to extract URLs from (in bytes.)"""
        return self.config.max_file_size * 1024 * 1024

    @property
    def max_extracted_urls(self):
        """The maximum number of urls to extract from a single file."""
        return self.config.max_extracted_urls

    @staticmethod
    def order_urls_by_interest(extracted_urls):
        """Sort the extracted urls into a list by their domain+TLD frequency and path extension.
        Baically, we want the urls that are more likely to be malicious to come first.
        """
        image_extensions = ('.png', '.gif', '.jpeg', '.jpg', '.tiff', '.bmp')
        image_urls = []
        # A dict of domain (key) & URL value groups
        # -- calling a domain the domain+tld
        _groupings = {}
        for url in extracted_urls:
            try:
                res = get_tld(url, as_object=True)
            except Exception as e:
                logging.info("Failed to get TLD on url:{} - {}".format(url, e))
                if 'no_tld' not in _groupings:
                    _groupings['no_tld'] = []
                _groupings['no_tld'].append(url)
                continue

            domain = str(res.domain) + '.' + str(res)
            if domain not in _groupings:
                _groupings[domain] = []
            _groupings[domain].append(url)

            if res.parsed_url.path.endswith(image_extensions):
                image_urls.append(url)
            # I'm not sure we want to do this with query extensions, always
            #if res.parsed_url.query.endswith(image_extensions):
                #image_urls.append(url)

        interesting_url_order = []
        _ordered_domains = sorted(_groupings, key=lambda k: len(_groupings[k]))
        for d in _ordered_domains:
            d_urls = _groupings[d]
            for url in d_urls:
                if url in image_urls:
                    continue
                interesting_url_order.append(url)

        interesting_url_order.extend(image_urls)
        if len(interesting_url_order) != len(extracted_urls):
            logging.error("URLs went missing during ordering. Resturning origional list.")
            return extracted_urls
        return interesting_url_order, _groupings

    def filter_excluded_domains(self, url):

        # filter out the stuff that is excluded via configuration
        fqdns = [_.strip() for _ in self.config.excluded_domains]

        if not fqdns:
            return True

        try:
            parsed_url = urlparse(url)
        except:
            return True

        # empty URL
        if parsed_url.hostname is None:
            return True

        # invalid URL; ex. http://center, http://blue
        if '.' not in parsed_url.hostname:
            return False

        for fqdn in fqdns:
            if is_subdomain(parsed_url.hostname, fqdn):
                return False

        return True

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        from saq.modules.url import CrawlphishAnalyzer
        from saq.modules.file_analysis.file_type import FileTypeAnalysis

        # we need file type analysis first
        file_type_analysis = _file.get_and_load_analysis(FileTypeAnalysis)
        if not file_type_analysis:
            return AnalysisExecutionResult.COMPLETED


        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return AnalysisExecutionResult.COMPLETED

        # skip files that are too large
        if file_size > self.max_file_size:
            logging.debug("file {} is too large to extract URLs from".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # if this file was downloaded from some url then we want all the relative urls to be aboslute to the reference url
        base_url = None
        if file_type_analysis.mime_type and 'html' in file_type_analysis.mime_type.lower():
            downloaded_from = _file.get_relationship_by_type(R_DOWNLOADED_FROM)
            if downloaded_from:
                base_url = downloaded_from.target.value

        # For JavaScript-tagged observables, force urlfinderlib to treat the
        # file as plain text. Without the override, urlfinderlib routes JS
        # source through its HTML finder (via might_be_html() body-sniffing),
        # which uses lxml and chokes on embedded string literals containing
        # escape sequences that parse as XML-incompatible attribute values.
        # For everything else we leave mimetype empty so urlfinderlib runs
        # its own libmagic detection — forwarding ACE's FileTypeAnalysis
        # mime string directly causes regressions because ACE reports mime
        # in one form (e.g. "message/rfc822") and urlfinderlib's internal
        # routing expects another (e.g. "rfc 822 mail").
        url_mimetype = ""
        if _file.has_yara_meta("type", "script.javascript"):
            url_mimetype = "text/plain"

        # extract all the URLs out of this file
        extracted_urls = []
        with open(local_file_path, 'rb') as fp:
            try:
                domain_as_url = False
                if _file.has_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL):
                    domain_as_url = True

                # XXX this can hang hard
                if _file.has_yara_meta("type", YARA_META_TYPE_OCR):
                    # OCR output is plain text. find_urls() would body-sniff it with might_be_html(),
                    # which is satisfied by any blob containing < > = : / anywhere in it, and route
                    # it through the HTML finder as well as the text finder.
                    extracted_urls = find_urls_in_text(fp.read(), domain_as_url=domain_as_url)
                else:
                    extracted_urls = find_urls(fp.read(), base_url=base_url, domain_as_url=domain_as_url, mimetype=url_mimetype)
                logging.debug("extracted {} urls from {}".format(len(extracted_urls), local_file_path))
            except Exception as e:
                logging.warning(f"failed to extract urls from {local_file_path}: {e}")
                return AnalysisExecutionResult.COMPLETED

        # OCR output is a lossy reconstruction, not a byte-for-byte transcription. urlfinderlib
        # accepts a URL when its *percent-encoded* form validates, but ACE stores the *raw* value --
        # so garbled text like  https://example.net/sh", *5{margin  gets laundered into a "valid"
        # URL observable. Where the source text is itself a guess, require the value we are about to
        # store to be valid as written. We don't apply this to other sources: in HTML or email the
        # bytes are ground truth, so a URL containing a raw space really is present in the source.
        if _file.has_yara_meta("type", YARA_META_TYPE_OCR):
            valid_urls = [url for url in extracted_urls if validators.url(url, simple_host=True)]
            if len(valid_urls) != len(extracted_urls):
                logging.debug(f"dropped {len(extracted_urls) - len(valid_urls)} malformed urls "
                              f"extracted from ocr text {local_file_path}")
            extracted_urls = valid_urls

        extracted_urls = list(filter(self.filter_excluded_domains, extracted_urls))
        analysis = self.create_analysis(_file)

        # since cloudphish_request_limit, order urls by our interest in them
        extracted_ordered_urls, analysis.details['urls_grouped_by_domain'] = self.order_urls_by_interest(extracted_urls)
        observable_count = 0
        for url in extracted_ordered_urls:
            analysis.details['urls'].append(url)
            logging.debug("extracted url {} from {}".format(url, _file))

            if observable_count < self.max_extracted_urls:
                url_observable = analysis.add_observable_by_spec(F_URL, url, volatile=True)
                if url_observable:
                    observable_count += 1

                    if _file.has_directive(DIRECTIVE_CRAWL_EXTRACTED_URLS):
                        url_observable.add_directive(DIRECTIVE_CRAWL)
                    else:
                        # don't download from links that came from files downloaded from the internet
                        if _file.has_relationship(R_DOWNLOADED_FROM):
                            url_observable.exclude_analysis(CrawlphishAnalyzer)
                            #url_observable.exclude_analysis(RenderAnalyzer)

        return AnalysisExecutionResult.COMPLETED