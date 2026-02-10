import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Type, override

import yaml
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field
from urlfinderlib import find_urls

from saq.analysis.analysis import Analysis
from saq.constants import (
    DIRECTIVE_EXTRACT_IOCS,
    F_FILE,
    R_EXTRACTED_FROM,
    F_URL,
    AnalysisExecutionResult,
)
from saq.environment import get_base_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.observables.file import FileObservable


class BaseConfig(BaseModel):
    directives: list[str] = Field(
        default_factory=list,
        description="Directives to add to extracted URL observables",
    )
    tags: list[str] = Field(
        default_factory=list, description="Tags to add to extracted URL observables"
    )
    volatile: bool = Field(
        default=False,
        description="Whether to add URL observables as volatile (for detection only)",
    )
    ignored_patterns: list[str] = Field(
        default_factory=list,
        description="List of regex patterns used to ignore extracted URLs",
    )
    display_type: Optional[str] = Field(
        default="IOC", description="Custom display type for the UI"
    )


class PatternConfig(BaseConfig):
    pattern: str = Field(..., description="Python-compatible regular expression")
    type: str = Field(..., description="ACE observable type to create")


class URLConfig(BaseConfig): ...


@dataclass
class CompiledPatternConfig:
    config: PatternConfig
    compiled_pattern: re.Pattern
    compiled_ignore_patterns: list[re.Pattern] = field(default_factory=list)


@dataclass
class CompiledURLConfig:
    config: URLConfig
    compiled_ignore_patterns: list[re.Pattern] = field(default_factory=list)


class IOCExtractionConfig(AnalysisModuleConfig):
    max_file_size: int = Field(..., description="Maximum file size in megabytes")
    extraction_config_path: str = Field(
        default="etc/default_ioc_extraction.yaml",
        description="Path to YAML config file, relative to SAQ_HOME",
    )


class IOCExtractionAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "iocs": defaultdict(list),  # Dict of type -> list of values
            "total_count": 0,
            "ignored": [],  # List of (type, value, matching ignore pattern) for IOCs that were ignored
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

        # Loading the config populates these variables with the config and the valid/compiled regex patterns
        self._compiled_refang_patterns: dict[str, list[re.Pattern]] = defaultdict(list)
        self._compiled_pattern_configs: list[CompiledPatternConfig] = []
        self._compiled_url_config: CompiledURLConfig | None = None

        # Track the unique observables to add, keyed by (type, value) with the config that found them
        self._observables_to_add: dict[tuple[str, str], CompiledPatternConfig | CompiledURLConfig] = {}

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

    def _load_config(self):
        """Load custom extraction and exclude patterns from YAML file."""
        self._compiled_refang_patterns = defaultdict(list)
        self._compiled_pattern_configs = []
        self._compiled_url_config = None

        yaml_path = os.path.join(
            get_base_dir(),
            self.config.extraction_config_path,
        )

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            logging.warning(f"failed to load IOC patterns YAML {yaml_path}: {e}")
            return

        # Load re-fang patterns
        num_refang_patterns = 0
        for replacement, patterns in data.get("refang_patterns", {}).items():
            for pattern in patterns:
                try:
                    self._compiled_refang_patterns[replacement].append(
                        re.compile(pattern)
                    )
                    num_refang_patterns += 1
                except re.error as e:
                    logging.error(f"invalid refang regex '{pattern}': {e}")

        # Load IOC extraction patterns
        for entry in data.get("patterns", []) or []:
            try:
                config = PatternConfig(**entry)
            except Exception as e:
                logging.error(f"invalid pattern config: {e}")
                continue

            try:
                compiled_pattern = re.compile(config.pattern)
            except re.error as e:
                logging.error(f"invalid regex '{config.pattern}' in pattern: {e}")
                continue

            compiled_ignore_patterns = []
            for ignore_pattern in config.ignored_patterns:
                try:
                    compiled_ignore_patterns.append(re.compile(ignore_pattern))
                except re.error as e:
                    logging.error(
                        f"invalid ignore regex '{ignore_pattern}' in pattern': {e}"
                    )

            self._compiled_pattern_configs.append(
                CompiledPatternConfig(
                    config=config,
                    compiled_pattern=compiled_pattern,
                    compiled_ignore_patterns=compiled_ignore_patterns,
                )
            )

        # Load the URL config
        url_config = data.get("urls", {})
        try:
            url_config = URLConfig(**url_config)
        except Exception as e:
            logging.warning(f"invalid URL config in IOC extraction config: {e}")

        if url_config:
            self._compiled_url_config = CompiledURLConfig(config=url_config)

            for ignore_pattern in url_config.ignored_patterns:
                try:
                    self._compiled_url_config.compiled_ignore_patterns.append(
                        re.compile(ignore_pattern)
                    )
                except re.error as e:
                    logging.warning(
                        f"invalid ignore regex '{ignore_pattern}' in URL config: {e}"
                    )

        logging.debug(
            f"loaded {num_refang_patterns} refang patterns and {len(self._compiled_pattern_configs)} custom patterns from IOC extraction config {yaml_path}"
        )

    def _is_excluded(self, value: str, compiled_ignore_patterns: list[re.Pattern]) -> str | None:
        """
        Check if a value matches any of the ignore patterns.
        
        Returns the pattern that caused the exclusion, or None if it should not be excluded.
        """
        for ignore_pattern in compiled_ignore_patterns:
            if ignore_pattern.search(value):
                return ignore_pattern.pattern
        return None

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        if not self._initialized:
            yaml_path = os.path.join(
                get_base_dir(),
                self.config.extraction_config_path,
            )
            self.watch_file(yaml_path, self._load_config)
            self._initialized = True

        self._observables_to_add = {}

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
            logging.info(f"file {_file} is too large for IOC extraction")
            return AnalysisExecutionResult.COMPLETED

        # Parse the text (visible text if HTML)
        with open(local_file_path, "r", errors="ignore") as f:
            raw_text = f.read()
            try:
                soup = BeautifulSoup(raw_text, "lxml")
                text = soup.get_text()
            except Exception as e:
                logging.debug(f"failed to parse file {local_file_path} as HTML: {e}")
                text = raw_text

        # Re-fang the text until no more changes occur
        changed = True
        while changed:
            changed = False
            for replacement, patterns in self._compiled_refang_patterns.items():
                for compiled_config in patterns:
                    new_text, num_subs = compiled_config.subn(replacement, text)
                    if num_subs > 0:
                        changed = True
                        text = new_text

        # Keep track of the IOCs that were ignored (to include in the analysis details)
        ignored: set[tuple[str, str, str]] = set()  # (type, value, matching ignore pattern)

        # Extract URLs
        if self._compiled_url_config:
            for url in find_urls(text):
                # Check if the URL should be ignored
                if matched_ignore_pattern := self._is_excluded(url, self._compiled_url_config.compiled_ignore_patterns):
                    ignored.add((F_URL, url, matched_ignore_pattern))
                    continue

                self._observables_to_add[(F_URL, url)] = self._compiled_url_config

        # Extract other IOC patterns
        for compiled_config in self._compiled_pattern_configs:
            for match in compiled_config.compiled_pattern.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)

                # Check if the matched value should be ignored
                if matching_ignore_pattern := self._is_excluded(value, compiled_config.compiled_ignore_patterns):
                    ignored.add(
                        (compiled_config.config.type, value, matching_ignore_pattern)
                    )
                    continue

                self._observables_to_add[(compiled_config.config.type, value)] = compiled_config

        # Build analysis from surviving IOCs
        analysis = self.create_analysis(_file)

        for (ioc_type, ioc_value), compiled_config in self._observables_to_add.items():
            # Track in details
            analysis.details["iocs"][ioc_type].append(ioc_value)
            analysis.details["total_count"] += 1

            # Add as observable
            obs = analysis.add_observable_by_spec(
                ioc_type, ioc_value, volatile=compiled_config.config.volatile
            )
            if obs:
                obs.add_relationship(R_EXTRACTED_FROM, _file)

                # Apply directives
                for directive in compiled_config.config.directives:
                    obs.add_directive(directive)

                # Apply tags
                for tag in compiled_config.config.tags:
                    obs.add_tag(tag)

                # Apply display_type
                if compiled_config.config.display_type:
                    obs.display_type = compiled_config.config.display_type

        analysis.details["ignored"] = sorted(ignored)
        return AnalysisExecutionResult.COMPLETED
