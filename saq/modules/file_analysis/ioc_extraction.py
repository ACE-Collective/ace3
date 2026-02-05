import logging
import os
import re
from typing import Optional, Type, Union, override

import yaml
from iocsearcher.document import open_document
from iocsearcher.searcher import Searcher
from pydantic import BaseModel, Field

from saq.analysis.analysis import Analysis
from saq.constants import (
    DIRECTIVE_EXTRACT_IOCS,
    F_FILE,
    R_EXTRACTED_FROM,
    AnalysisExecutionResult,
)
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable


class ConfigurableSearcher(Searcher):
    """Custom Searcher with configurable IP validation behavior."""

    def __init__(self, include_private_ips: bool = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._include_private_ips = include_private_ips

    def is_valid_ip4(
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


class IOCObservableMapping(BaseModel):
    """Mapping configuration for a single IOC type to ACE observable."""

    model_config = {"frozen": True}

    type: str = Field(..., description="The ACE observable type to map to")
    directives: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Directives to add to extracted observables"
    )
    tags: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Tags to add to extracted observables"
    )
    volatile: bool = Field(
        default=False,
        description="Whether to add observables as volatile (for detection only)"
    )
    ignored_values: tuple[str, ...] = Field(
        default_factory=tuple,
        description="List of values to ignore when extracting this IOC type"
    )
    display_type: Optional[str] = Field(
        default="IOC",
        description="Custom display type for the UI"
    )


class CustomPattern(BaseModel):
    """Custom regex pattern for IOC extraction."""

    model_config = {"frozen": True}

    pattern: str = Field(..., description="Python-compatible regular expression")
    type: str = Field(..., description="ACE observable type to create")
    directives: tuple[str, ...] = Field(default_factory=tuple)
    tags: tuple[str, ...] = Field(default_factory=tuple)
    volatile: bool = Field(default=False)
    display_type: Optional[str] = Field(default=None)




class IOCExtractionConfig(AnalysisModuleConfig):
    max_file_size: int = Field(..., description="Maximum file size in megabytes")
    include_private_ips: bool = Field(
        default=False,
        description="Include private/local/reserved IP addresses in extraction results",
    )
    extraction_config_path: str = Field(
        default="etc/default_ioc_extraction.yaml",
        description="Path to YAML config file, relative to SAQ_HOME",
    )


class IOCExtractionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "iocs": {},  # Dict of type -> list of values
            "total_count": 0,
            "skipped_types": [],  # IOC types found but not supported
            "excluded_count": 0,  # Number of IOCs filtered by exclude patterns
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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False
        # iocsearcher mapping loaded from YAML
        self._iocsearcher_mapping: dict[str, IOCObservableMapping] = {}
        # List of (CustomPattern, compiled_regex) tuples
        self._custom_patterns: list[tuple[CustomPattern, re.Pattern]] = []
        # List of compiled exclude regex patterns
        self._exclude_patterns: list[re.Pattern] = []

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

    def _load_patterns(self):
        """Load custom extraction and exclude patterns from YAML file."""
        yaml_path = os.path.join(
            get_base_dir(),
            self.config.extraction_config_path,
        )

        self._custom_patterns = []
        self._exclude_patterns = []
        self._iocsearcher_mapping = {}

        if not os.path.exists(yaml_path):
            logging.warning(f"IOC patterns file not found: {yaml_path}")
            return

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logging.warning(f"failed to load IOC patterns YAML {yaml_path}: {e}")
            return

        # Load iocsearcher type mappings
        iocsearcher_config = data.get("iocsearcher", {}) or {}
        if iocsearcher_config:
            for ioc_type, mapping_data in iocsearcher_config.items():
                try:
                    self._iocsearcher_mapping[ioc_type] = IOCObservableMapping(**mapping_data)
                except Exception as e:
                    logging.warning(f"invalid iocsearcher mapping for '{ioc_type}': {e}")

        # Load custom extraction patterns
        for entry in data.get("custom_patterns", []) or []:
            try:
                pattern_config = CustomPattern(**entry)
                compiled = re.compile(pattern_config.pattern)
                self._custom_patterns.append((pattern_config, compiled))
            except re.error as e:
                logging.warning(f"invalid regex in pattern '{entry.get('name', '<unnamed>')}': {e}")
            except Exception as e:
                logging.warning(f"invalid pattern config: {e}")

        # Load exclude patterns
        for pattern_str in data.get("exclude_patterns", []) or []:
            try:
                compiled = re.compile(pattern_str)
            except re.error as e:
                logging.warning(f"invalid exclude pattern regex '{pattern_str}': {e}")
                continue

            self._exclude_patterns.append(compiled)

        logging.debug(
            f"loaded {len(self._custom_patterns)} custom patterns and "
            f"{len(self._exclude_patterns)} exclude patterns"
        )

    def _is_excluded(self, value: str) -> bool:
        """Check if an IOC value matches any exclude pattern."""
        for pattern in self._exclude_patterns:
            if pattern.search(value):
                return True
        return False

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        if not self._initialized:
            yaml_path = os.path.join(
                get_base_dir(),
                self.config.extraction_config_path,
            )
            self.watch_file(yaml_path, self._load_patterns)
            self._initialized = True

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

        # Step 1: Search for IOCs with iocsearcher
        searcher = ConfigurableSearcher(
            include_private_ips=self.config.include_private_ips
        )
        try:
            results = searcher.search_data(text)
        except Exception as e:
            logging.warning(f"iocsearcher failed on {local_file_path}: {e}")
            return AnalysisExecutionResult.COMPLETED

        # Collect all IOCs as (mapping_or_config, value) using a set for deduplication
        # mapping_or_config is either IOCObservableMapping or CustomPattern
        seen: set[tuple[Union[IOCObservableMapping, CustomPattern], str]] = set()
        skipped_types = set()
        excluded_count = 0

        for ioc in results:
            ioc_type = ioc.name
            ioc_value = ioc.value

            mapping = self._iocsearcher_mapping.get(ioc_type)
            if mapping is None:
                skipped_types.add(ioc_type)
                continue

            # Check per-type ignored_values
            if ioc_value in mapping.ignored_values:
                excluded_count += 1
                continue

            seen.add((mapping, ioc_value))

        # Step 2: Run custom regex patterns against text
        for pattern_config, regex in self._custom_patterns:
            for match in regex.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                seen.add((pattern_config, value))

        # Step 3: Apply exclude patterns
        surviving: set[tuple[Union[IOCObservableMapping, CustomPattern], str]] = set()
        for mapping_or_config, value in seen:
            if self._is_excluded(value):
                excluded_count += 1
            else:
                surviving.add((mapping_or_config, value))

        # Step 4: Build analysis from surviving IOCs
        analysis = self.create_analysis(_file)

        for mapping_or_config, ioc_value in surviving:
            ace_type = mapping_or_config.type

            # Track in details
            if ace_type not in analysis.details["iocs"]:
                analysis.details["iocs"][ace_type] = []

            if ioc_value not in analysis.details["iocs"][ace_type]:
                analysis.details["iocs"][ace_type].append(ioc_value)
                analysis.details["total_count"] += 1

            # Add as observable
            obs = analysis.add_observable_by_spec(ace_type, ioc_value, volatile=mapping_or_config.volatile)
            if obs:
                obs.add_relationship(R_EXTRACTED_FROM, _file)

                # Apply directives
                for directive in mapping_or_config.directives:
                    obs.add_directive(directive)

                # Apply tags
                for tag in mapping_or_config.tags:
                    obs.add_tag(tag)

                # Apply display_type
                if mapping_or_config.display_type:
                    obs.display_type = mapping_or_config.display_type

        analysis.details["skipped_types"] = list(skipped_types)
        analysis.details["excluded_count"] = excluded_count
        return AnalysisExecutionResult.COMPLETED
