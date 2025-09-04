import logging
import os
from typing import override
from urllib.parse import urlparse
from tld import get_tld
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_CRAWL, DIRECTIVE_CRAWL_EXTRACTED_URLS, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL, F_FILE, F_URL, R_DOWNLOADED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.networking import is_subdomain

from urlfinderlib import find_urls

from saq.util.strings import format_item_list_for_summary


KEY_URLS = "urls"

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
                logging.debug("failed to parse url %s: %s", url, e)

        return f"{self.display_name} ({format_item_list_for_summary(sorted(list(domains)))})"

class URLExtractionAnalyzer(AnalysisModule):
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
        return self.config.getint("max_file_size") * 1024 * 1024

    @property
    def max_extracted_urls(self):
        """The maximum number of urls to extract from a single file."""
        return self.config.getint("max_extracted_urls")

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
        fqdns = [_.strip() for _ in self.config['excluded_domains']]

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
        from saq.modules.file_analysis.yara import YaraScanResults_v3_4

        # we need file type analysis first
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if file_type_analysis is None:
            return AnalysisExecutionResult.COMPLETED

        # IF we've got yara enabled THEN wait for it
        # otherrwise don't worry about it eh?
        if self._context.configuration_manager.is_module_enabled(YaraScanResults_v3_4):
            self.wait_for_analysis(_file, YaraScanResults_v3_4)

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

        # extract all the URLs out of this file
        extracted_urls = []
        with open(local_file_path, 'rb') as fp:
            try:
                domain_as_url = False
                if _file.has_directive(DIRECTIVE_EXTRACT_URLS_DOMAIN_AS_URL):
                    domain_as_url = True

                # XXX this can hang hard
                extracted_urls = find_urls(fp.read(), base_url=base_url, domain_as_url=domain_as_url)
                logging.debug("extracted {} urls from {}".format(len(extracted_urls), local_file_path))
            except:
                logging.warning(f"failed to extract urls from {local_file_path}")
                return AnalysisExecutionResult.COMPLETED

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