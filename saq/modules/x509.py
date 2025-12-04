"""Analysis Module for analyzing x509 certificates."""

import logging
import json
import os
from typing import override

from saq import x509
from saq.analysis import Analysis, RootAnalysis
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.constants import F_FILE, F_FQDN, F_SHA256, F_IPV4, F_URL, DIRECTIVE_CRAWL, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis import FileTypeAnalysis
from saq.util.filesystem import get_local_file_path
from saq.util.strings import format_item_list_for_summary

KEY_ISSUER = 'issuer'
KEY_SUBJECT = 'subject'
KEY_NOT_VALID_BEFORE = 'not_valid_before'
KEY_NOT_VALID_AFTER = 'not_valid_after'
KEY_SERIAL_NUMBER = 'serial_number'
KEY_COMMON_NAME = 'common_name'
KEY_SUBJECT_ALTERNATIVE_NAMES = 'subject_alternative_names'
KEY_SAN_IP_ADDRESSES = 'san_ip_addresses'
KEY_SAN_DNS_NAMES = 'san_dns_names'
KEY_SHA256_HASH = 'sha256_hash'
KEY_EXTENSIONS_TREE = 'extensions'


class X509Analysis(Analysis):
    """Is this document an x509 certificate?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ISSUER: None,
            KEY_SUBJECT: None,
            KEY_NOT_VALID_BEFORE: None,
            KEY_NOT_VALID_AFTER: None,
            KEY_SERIAL_NUMBER: None,
            KEY_COMMON_NAME: None,
            KEY_SHA256_HASH: None,
            KEY_EXTENSIONS_TREE: None,
            KEY_SUBJECT_ALTERNATIVE_NAMES: {
                KEY_SAN_IP_ADDRESSES: [],
                KEY_SAN_DNS_NAMES: [],
            }
        }

    @override
    @property
    def display_name(self) -> str:
        return "X509 Analysis"

    @property
    def issuer(self):
        return self.details[KEY_ISSUER]

    @issuer.setter
    def issuer(self, value):
        self.details[KEY_ISSUER] = value

    @property
    def subject(self):
        return self.details[KEY_SUBJECT]

    @subject.setter
    def subject(self, value):
        self.details[KEY_SUBJECT] = value

    @property
    def not_valid_before(self):
        return self.details[KEY_NOT_VALID_BEFORE]

    @not_valid_before.setter
    def not_valid_before(self, value):
        self.details[KEY_NOT_VALID_BEFORE] = value

    @property
    def not_valid_after(self):
        return self.details[KEY_NOT_VALID_AFTER]

    @not_valid_after.setter
    def not_valid_after(self, value):
        self.details[KEY_NOT_VALID_AFTER] = value

    @property
    def serial_number(self):
        return self.details[KEY_SERIAL_NUMBER]

    @serial_number.setter
    def serial_number(self, value):
        self.details[KEY_SERIAL_NUMBER] = value

    @property
    def common_name(self):
        return self.details[KEY_COMMON_NAME]

    @common_name.setter
    def common_name(self, value):
        self.details[KEY_COMMON_NAME] = value

    @property
    def sha256_hash(self):
        return self.details[KEY_SHA256_HASH]

    @sha256_hash.setter
    def sha256_hash(self, value):
        self.details[KEY_SHA256_HASH] = value

    @property
    def san_ip_addresses(self):
        return self.details[KEY_SUBJECT_ALTERNATIVE_NAMES][KEY_SAN_IP_ADDRESSES]

    def add_san_ip_address(self, value):
        self.details[KEY_SUBJECT_ALTERNATIVE_NAMES][KEY_SAN_IP_ADDRESSES].append(value)

    @property
    def san_dns_names(self):
        return self.details[KEY_SUBJECT_ALTERNATIVE_NAMES][KEY_SAN_DNS_NAMES]

    def add_san_dns_name(self, value):
        self.details[KEY_SUBJECT_ALTERNATIVE_NAMES][KEY_SAN_DNS_NAMES].append(value)

    @property
    def extension_tree(self):
        return self.details[KEY_EXTENSIONS_TREE]

    @extension_tree.setter
    def extension_tree(self, value):
        self.details[KEY_EXTENSIONS_TREE] = value

    @property
    def jinja_template_path(self):
        return "analysis/x509_file_analysis.html"

    def generate_summary(self):
        result = f"{self.display_name}: {self.common_name} | " \
                 f"Issuer={self.issuer} | " \
                 f"NotValidBefore={self.not_valid_before} | " \
                 f"Subject Alternative Names: {format_item_list_for_summary(self.san_dns_names)} DNS Names, " \
                 f"{format_item_list_for_summary(self.san_ip_addresses)} IP Addresses"

        return result


class X509Analyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return X509Analysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @staticmethod
    def parent_is_url(observable):
        """Determines whether current observable has URL Observable parent"""
        for parent in observable.parents:
            if isinstance(parent, RootAnalysis):
                return False

            if parent.observable.type == F_URL:
                return True

        return False

    def write_metadata_to_file(self, file, metadata: dict):
        """Write x509 metadata/details to file and add observable for analyst tuning"""
        logging.debug(f"Saving metadata for {file.value} to root storage")
        path = os.path.join(self.get_root().storage_dir, f"{file.value}.metadata")
        with open(path, "w") as fp:
            fp.write(json.dumps(metadata, default=str))

        target_path = os.path.relpath(path, start=self.get_root().storage_dir)
        return target_path

    def execute_analysis(self, _file) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = get_local_file_path(self.get_root(), _file)
        if not os.path.exists(local_file_path):
            logging.debug(f"file {local_file_path} could not be found")
            return AnalysisExecutionResult.COMPLETED

        logging.debug(f"analysis file {local_file_path}")

        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis:
            logging.debug("x509 analysis module requires FileTypeAnalysis")
            return AnalysisExecutionResult.COMPLETED

        if not file_type_analysis.is_x509:
            logging.debug(f"{local_file_path} is not a x509 certificate")
            return AnalysisExecutionResult.COMPLETED

        with open(local_file_path, 'rb') as f:
            file_bytes = f.read().strip()

        # custom_requirements function makes sure this is an x509 file before we load it here
        cert = x509.load_cert(file_bytes)

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, X509Analysis)

        # Get common certificate data
        analysis.issuer = x509.issuer(cert)
        analysis.subject = x509.subject(cert)
        analysis.serial_number = x509.serial_number(cert)
        analysis.not_valid_before = x509.not_valid_before(cert)
        analysis.not_valid_after = x509.not_valid_after(cert)
        analysis.common_name = x509.common_name(cert)
        analysis.sha256_hash = x509.sha256(cert)  # Created from DER-encoded format of the certificate

        # Note parent observable type; don't render/crawl extracted domains if parent is URL
        parent_is_url = self.parent_is_url(_file)
        if analysis.common_name is None:
            logging.info(f"unable to parse common name from {analysis.subject}")
        else:
            common_name = x509.remove_wildcard(analysis.common_name)
            cn_fqdn = analysis.add_observable_by_spec(F_FQDN, common_name)
            if cn_fqdn:
                cn_fqdn.display_type = "Certificate Common Name"

            if not parent_is_url:
                url = analysis.add_observable_by_spec(F_URL, f'http://{common_name}')
                if url:
                    url.display_type = "Certificate Common Name URL (http)"
                    url.add_directive(DIRECTIVE_CRAWL)
                url = analysis.add_observable_by_spec(F_URL, f'https://{common_name}')
                if url:
                    url.display_type = "Certificate Common Name URL (https)"
                    url.add_directive(DIRECTIVE_CRAWL)

        # Get Subject Alternative Name data
        for ip_address in x509.san_ip_addresses(cert):
            analysis.add_san_ip_address(ip_address)
            san_ip = analysis.add_observable_by_spec(F_IPV4, ip_address)
            if san_ip:
                san_ip.display_type = "Certificate SAN IP Address"

        for dns_name in x509.san_dns_names(cert):
            analysis.add_san_dns_name(dns_name)
            # Some certs have wildcards, make sure we submit the nearest FQDN (strip the wildcard)
            dns_name = x509.remove_wildcard(dns_name)
            san_fqdn = analysis.add_observable_by_spec(F_FQDN, dns_name)
            if san_fqdn:
                san_fqdn.display_type = "Certificate SAN DNS Name"

            if not parent_is_url:
                url = analysis.add_observable_by_spec(F_URL, f'http://{dns_name}')
                if url:
                    url.display_type = "Certificate SAN URL (http)"
                    url.add_directive(DIRECTIVE_CRAWL)
                url = analysis.add_observable_by_spec(F_URL, f'https://{dns_name}')
                if url:
                    url.display_type = "Certificate SAN URL (https)"
                    url.add_directive(DIRECTIVE_CRAWL)

        # A certificate's hash (used for tracking) is created from the DER-encoded format version of the
        # certificate.
        analysis.add_observable_by_spec(F_SHA256, analysis.sha256_hash)

        analysis.extension_tree = x509.get_readable_extensions(cert)

        # add file observable for x509 metadata
        target_path = self.write_metadata_to_file(_file, analysis.details)
        analysis.add_file_observable(target_path)

        return AnalysisExecutionResult.COMPLETED


class X509AnalysisPresenter(AnalysisPresenter):
    """Presenter for X509Analysis."""

    @property
    def template_path(self) -> str:
        return "analysis/x509_file_analysis.html"


register_analysis_presenter(X509Analysis, X509AnalysisPresenter)
