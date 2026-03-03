# vim: sw=4:ts=4:et:cc=120

import logging
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from saq.constants import (
    SUMMARY_DETAIL_FORMAT_MD,
    SUMMARY_DETAIL_FORMAT_PRE,
    SUMMARY_DETAIL_FORMAT_TXT,
)
from saq.observables.mapping import (
    ObservableMapping,
    compile_ignored_value_patterns,
    is_ignored_value,
)
from saq.util import abs_path

SUMMARY_DETAIL_LIMIT_DEFAULT = 100

VALID_SUMMARY_DETAIL_FORMATS = {SUMMARY_DETAIL_FORMAT_MD, SUMMARY_DETAIL_FORMAT_PRE, SUMMARY_DETAIL_FORMAT_TXT}


class SummaryDetailConfig(BaseModel):
    content: str
    header: Optional[str] = None
    format: str = SUMMARY_DETAIL_FORMAT_MD
    limit: int = SUMMARY_DETAIL_LIMIT_DEFAULT
    grouped: bool = False

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        if value not in VALID_SUMMARY_DETAIL_FORMATS:
            logging.error(
                "invalid summary_detail format %s - must be one of %s - defaulting to %s",
                value, VALID_SUMMARY_DETAIL_FORMATS, SUMMARY_DETAIL_FORMAT_MD,
            )
            return SUMMARY_DETAIL_FORMAT_MD
        return value


class BaseQueryConfig(BaseModel):
    """Shared query configuration mixin for hunts and API analysis modules."""
    query: Optional[str] = Field(default=None, description="The query to execute.")
    query_path: Optional[str] = Field(default=None, description="The path to the query file.")
    observable_mapping: list[ObservableMapping] = Field(
        default_factory=list,
        description="The mapping of fields to observables."
    )
    max_result_count: Optional[int] = Field(default=None, description="The maximum number of results to return.")
    ignored_values: list[str] = Field(
        default_factory=list,
        description="A global list of regex patterns to ignore that applies to all observable mappings. "
                    "Patterns are matched with re.fullmatch()."
    )
    summary_details: list[SummaryDetailConfig] = Field(
        default_factory=list,
        description="Summary details to add to submissions/analysis. Each definition generates one or more "
                    "SummaryDetail objects."
    )
    _ignored_value_patterns: list[re.Pattern] = []

    @model_validator(mode='after')
    def compile_ignored_value_patterns(self):
        """Pre-compile ignored_values into regex patterns."""
        self._ignored_value_patterns = compile_ignored_value_patterns(self.ignored_values)
        return self

    def is_ignored_value(self, value: str) -> bool:
        """Check if a value matches any ignored_values regex pattern."""
        return is_ignored_value(self._ignored_value_patterns, value)


def load_query_from_file(path: str) -> str:
    """Load a query string from a file path (resolved via abs_path)."""
    with open(abs_path(path), 'r') as fp:
        return fp.read()


def resolve_query(inline_query: Optional[str], query_file_path: Optional[str], context_name: str) -> str:
    """Resolve a query from inline string or file path. Raises ValueError if neither provided."""
    if inline_query is not None:
        return inline_query

    if query_file_path is not None:
        return load_query_from_file(query_file_path)

    raise ValueError(f"no query specified for {context_name}")
