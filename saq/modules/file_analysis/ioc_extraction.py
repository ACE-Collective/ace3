import logging
import os
from typing import Type, override

from iocsearcher.document import open_document
from iocsearcher.searcher import Searcher
from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.constants import (
    DIRECTIVE_EXTRACT_IOCS,
    F_EMAIL_ADDRESS,
    F_FILE,
    F_FILE_NAME,
    F_FQDN,
    F_IP,
    F_MAC_ADDRESS,
    F_MD5,
    F_SHA1,
    F_SHA256,
    F_URL,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable


class ConfigurableSearcher(Searcher):
    """Custom Searcher with configurable IP validation behavior."""

    def __init__(self, include_private_ips: bool = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._include_private_ips = include_private_ips

    @classmethod
    def is_valid_ip4(
        cls,
        s,
        ignore_private=True,
        ignore_local=True,
        ignore_multicast=True,
        ignore_loopback=True,
        ignore_reserved=True,
        ignore_unspecified=True,
    ):
        """Override to use configured ignore_private setting."""
        if cls._include_private_ips:
            ignore_private = False
            ignore_local = False
            ignore_reserved = False
        return Searcher.is_valid_ip4(
            s,
            ignore_private=ignore_private,
            ignore_local=ignore_local,
            ignore_multicast=ignore_multicast,
            ignore_loopback=ignore_loopback,
            ignore_reserved=ignore_reserved,
            ignore_unspecified=ignore_unspecified,
        )

    def is_valid_ip6(
        self,
        s,
        ignore_private=True,
        ignore_local=True,
        ignore_multicast=True,
        ignore_loopback=True,
        ignore_reserved=True,
        ignore_unspecified=True,
    ):
        """Override to use configured ignore_private setting."""
        if self._include_private_ips:
            ignore_private = False
            ignore_local = False
            ignore_reserved = False

        return Searcher.is_valid_ip6(
            s,
            ignore_private=ignore_private,
            ignore_local=ignore_local,
            ignore_multicast=ignore_multicast,
            ignore_loopback=ignore_loopback,
            ignore_reserved=ignore_reserved,
            ignore_unspecified=ignore_unspecified,
        )


# Mapping from iocsearcher types to ACE observable types
# Note: iocsearcher uses 'ip4' and 'ip6' (not 'ipv4' and 'ipv6')
IOC_TYPE_MAPPING = {
    "url": F_URL,
    "fqdn": F_FQDN,
    "ip4": F_IP,
    "ip6": F_IP,
    "email": F_EMAIL_ADDRESS,
    "md5": F_MD5,
    "sha1": F_SHA1,
    "sha256": F_SHA256,
    "mac": F_MAC_ADDRESS,
    "filename": F_FILE_NAME,
}


class IOCExtractionConfig(AnalysisModuleConfig):
    max_file_size: int = Field(..., description="Maximum file size in megabytes")
    max_extracted_iocs: int = Field(..., description="Maximum IOCs to extract per file")
    include_private_ips: bool = Field(
        default=False,
        description="Include private/local/reserved IP addresses in extraction results",
    )


class IOCExtractionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "iocs": {},  # Dict of type -> list of values
            "total_count": 0,
            "skipped_types": [],  # IOC types found but not supported
        }

    @override
    @property
    def display_name(self) -> str:
        return "IOC Extraction Analysis"

    def generate_summary(self):
        if self.details["total_count"] == 0:
            return None

        type_counts = [f"{t}: {len(v)}" for t, v in self.details["iocs"].items() if v]
        return (
            f"Extracted {self.details['total_count']} IOCs ({', '.join(type_counts)})"
        )


class IOCExtractionAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return IOCExtractionConfig

    @property
    def generated_analysis_type(self):
        return IOCExtractionAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [DIRECTIVE_EXTRACT_IOCS]

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path for {_file}")
            return AnalysisExecutionResult.COMPLETED

        # Skip empty files
        file_size = os.path.getsize(local_file_path)
        if file_size == 0:
            return AnalysisExecutionResult.COMPLETED

        # Skip files that are too large
        max_size = self.config.max_file_size * 1024 * 1024
        if file_size > max_size:
            logging.debug(f"file {_file} is too large for IOC extraction")
            return AnalysisExecutionResult.COMPLETED

        # Try to extract text using iocsearcher's document handler
        try:
            doc = open_document(local_file_path)
            if doc:
                text, _ = doc.get_text()
            else:
                # Fall back to reading as text
                with open(local_file_path, "r", errors="ignore") as f:
                    text = f.read()
        except Exception as e:
            logging.warning(f"failed to read file {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # Search for IOCs
        searcher = ConfigurableSearcher(
            include_private_ips=self.config.include_private_ips
        )
        try:
            results = searcher.search_data(text)
        except Exception as e:
            logging.warning(f"iocsearcher failed on {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)
        observable_count = 0
        skipped_types = set()

        for ioc in results:
            # Ioc object has 'name' (type) and 'value' attributes
            ioc_type = ioc.name
            ioc_value = ioc.value

            ace_type = IOC_TYPE_MAPPING.get(ioc_type)

            if ace_type is None:
                skipped_types.add(ioc_type)
                continue

            # Track in details
            if ace_type not in analysis.details["iocs"]:
                analysis.details["iocs"][ace_type] = []

            if ioc_value not in analysis.details["iocs"][ace_type]:
                analysis.details["iocs"][ace_type].append(ioc_value)
                analysis.details["total_count"] += 1

            # Add as observable (up to limit)
            if observable_count < self.config.max_extracted_iocs:
                obs = analysis.add_observable_by_spec(ace_type, ioc_value)
                if obs:
                    obs.add_relationship(R_EXTRACTED_FROM, _file)
                    observable_count += 1

        analysis.details["skipped_types"] = list(skipped_types)
        return AnalysisExecutionResult.COMPLETED
