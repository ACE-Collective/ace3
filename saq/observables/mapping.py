# vim: sw=4:ts=4:et:cc=120

import logging
import re

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class FieldsMode(str, Enum):
    ANY = "any"
    ALL = "all"


def compile_ignored_value_patterns(patterns: list[str]) -> list[re.Pattern]:
    """Compile a list of regex pattern strings into compiled re.Pattern objects."""
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            logging.error(f"invalid ignored_values regex pattern {p!r}: {e}")
    return compiled


def is_ignored_value(patterns: list[re.Pattern], value: str) -> bool:
    """Check if a value matches any of the compiled regex patterns using fullmatch."""
    return any(p.fullmatch(value) for p in patterns)


class BaseObservableMapping(BaseModel):
    """Base class for observable mapping configurations shared by query hunters and API analyzers."""
    field: Optional[str] = Field(default=None, description="Single field to map to an observable")
    fields: list[str] = Field(default_factory=list, description="One or more fields to map to an observable")
    type: str = Field(..., description="The type of observable to map to")
    tags: list[str] = Field(default_factory=list, description="Tags to add to the observable")
    directives: list[str] = Field(default_factory=list, description="Directives to add to the observable")
    time: bool = Field(default=False, description="Whether to use the time of the event as the time of the observable")
    ignored_values: list[str] = Field(
        default_factory=list,
        description="Regex patterns to skip when creating observables. Patterns are matched with re.fullmatch()."
    )
    display_type: Optional[str] = Field(default=None, description="The display type to use for the observable")
    display_value: Optional[str] = Field(default=None, description="The display value to use for the observable")
    fields_mode: FieldsMode = Field(
        default=FieldsMode.ALL,
        description="'all' requires all fields present to create one observable (default). "
                    "'any' creates a separate observable for each present field."
    )
    _ignored_value_patterns: list[re.Pattern] = []

    @model_validator(mode='after')
    def validate_field_or_fields(self):
        """Ensure either field or fields is specified, and normalize field into fields."""
        if not self.field and not self.fields:
            raise ValueError("Either 'field' or 'fields' must be specified in observable mapping")
        if self.field and not self.fields:
            self.fields = [self.field]
        return self

    @model_validator(mode='after')
    def compile_ignored_value_patterns(self):
        """Pre-compile ignored_values into regex patterns."""
        self._ignored_value_patterns = compile_ignored_value_patterns(self.ignored_values)
        return self

    def is_ignored_value(self, value: str) -> bool:
        """Check if a value matches any ignored_values regex pattern."""
        return is_ignored_value(self._ignored_value_patterns, value)

    def get_fields(self) -> list[str]:
        """Returns the list of fields to check, whether from field or fields."""
        if self.field:
            return [self.field]
        return self.fields
