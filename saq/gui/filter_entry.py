"""One entry of a filter list: the {name, inverted, values} shape the GUI's filter editor
produces, the database stores, and a share URL encodes."""

import re
from datetime import datetime
from typing import Union

import pytz
from pydantic import BaseModel, ConfigDict, Field, field_validator

from saq.analysis.module_path import IS_MODULE_PATH
from saq.detection_verdicts.constants import SOURCES, VERDICTS
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus
from saq.gui.detection_point_value import normalize_detection_point_value
from saq.gui.filter_names import (
    DATE_RANGE_FILTER_NAMES,
    DETECTION_POINT_FILTER_SLUGS,
    FILE_COLLECTION_FILTER_SLUGS,
    FILTER_NAMES,
    REMEDIATION_FILTER_SLUGS,
    SVS_RUN_FILTER_SLUGS,
    SVS_SAMPLE_FILTER_SLUGS,
    SVS_TEST_FILTER_SLUGS,
    SVS_VALIDATION_FILTER_SLUGS,
)
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus
from saq.signatures.model import SIGNATURE_UUID_PATTERN, SignatureType
from saq.svs.attack import normalize_platform
from saq.svs.constants import LABEL_FILTER_NONE, LABELS, RUN_STATES, VALIDATION_STATES
from saq.util.uuid import UUID_REGEX
from saq.util.relative_time import parse_date_range


# the values of the alert screen's Unconfirmed Detections filter
UNCONFIRMED_DETECTIONS_OPTIONS = ("True", "False")


class FilterEntryBase(BaseModel):
    """The shape of a filter entry, valid for any screen. Which names and values a screen
    accepts is that screen's entry model (saq/gui/filter_screens.py)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="a filter name of the screen the filter belongs to")
    inverted: bool = Field(default=False, description="negate this filter")
    # str for every filter except pair filters (alerts: Observable), whose values are
    # [type, value] pairs
    values: list[Union[str, list[str]]] = Field(min_length=1, description="the values to filter on")


class FilterEntry(FilterEntryBase):
    """A filter entry of the alert management screen.

    This is the single validation gate for all three doors: a modal save, an API call, and
    a hand-edited wiki link are all held to the same standard."""

    name: str = Field(description="a filter name supported by create_filter()")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in FILTER_NAMES:
            raise ValueError(f"unknown filter name {value!r} (expected one of {', '.join(sorted(FILTER_NAMES))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        """Reject an unparseable date token, detection point value or analysis module path at
        WRITE time.
        """
        if info.data.get("name") == "Analysis":
            for value in values:
                if not isinstance(value, str) or not IS_MODULE_PATH(value):
                    raise ValueError(f"analysis values must be module paths (module:Class[:instance]), got {value!r}")
            return values

        if info.data.get("name") == "Unconfirmed Detections":
            for value in values:
                if value not in UNCONFIRMED_DETECTIONS_OPTIONS:
                    raise ValueError(f"unconfirmed detections values must be True or False, got {value!r}")
            return values

        if info.data.get("name") == "Detection Point":
            if not all(isinstance(value, str) for value in values):
                raise ValueError(f"detection point values must be strings, got {values!r}")
            # normalize_detection_point_value raises ValueError, which pydantic reports
            return [normalize_detection_point_value(value) for value in values]

        if info.data.get("name") not in DATE_RANGE_FILTER_NAMES:
            return values

        now = datetime.now(pytz.utc)
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"date range value must be a string, got {value!r}")
            try:
                parse_date_range(value, now=now, tz=pytz.utc)
            except ValueError as e:
                raise ValueError(f"invalid date range {value!r}: {e}") from None

        return values


# the Verdict filter's value for a detection with no effective verdict (an unclassified alert)
VERDICT_FILTER_NONE = "none"


class DetectionPointFilterEntry(FilterEntryBase):
    """A filter entry of the detection points screen (GET /api/v2/detection-points)."""

    name: str = Field(description="a filter name of the detection points screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in DETECTION_POINT_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(DETECTION_POINT_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        if not all(isinstance(value, str) for value in values):
            raise ValueError(f"values must be strings, got {values!r}")

        name = info.data.get("name")
        if name == "Signature":
            # normalize_detection_point_value raises ValueError, which pydantic reports
            return [normalize_detection_point_value(value) for value in values]

        if name == "Alert Date":
            now = datetime.now(pytz.utc)
            for value in values:
                try:
                    parse_date_range(value, now=now, tz=pytz.utc)
                except ValueError as e:
                    raise ValueError(f"invalid date range {value!r}: {e}") from None
            return values

        allowed = {
            "Family": [signature_type.value for signature_type in SignatureType],
            "Verdict": [*VERDICTS, VERDICT_FILTER_NONE],
            "Source": list(SOURCES),
            "Has Override": ["true", "false"],
        }.get(name)
        if allowed is None:
            return values

        values = [value.lower() for value in values]
        for value in values:
            if value not in allowed:
                raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(allowed)})")

        return values


# the values of the SVS samples screen's boolean filters
SAMPLE_BOOL_OPTIONS = ("true", "false")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class SampleFilterEntry(FilterEntryBase):
    """A filter entry of the SVS samples screen (GET /api/v2/svs/samples)."""

    name: str = Field(description="a filter name of the SVS samples screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in SVS_SAMPLE_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(SVS_SAMPLE_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        if not all(isinstance(value, str) for value in values):
            raise ValueError(f"values must be strings, got {values!r}")

        name = info.data.get("name")
        if name == "Signature":
            for value in values:
                if not SIGNATURE_UUID_PATTERN.match(value):
                    raise ValueError(f"invalid signature uuid {value!r}")
            return values

        if name == "SHA256":
            values = [value.strip().lower() for value in values]
            for value in values:
                if not _SHA256_HEX.match(value):
                    raise ValueError(f"invalid sha256 {value!r} (expected 64 hex characters)")
            return values

        if name == "Alert":
            values = [value.strip().lower() for value in values]
            for value in values:
                if not UUID_REGEX.fullmatch(value):
                    raise ValueError(f"invalid alert uuid {value!r}")
            return values

        if name == "Last Captured":
            now = datetime.now(pytz.utc)
            for value in values:
                try:
                    parse_date_range(value, now=now, tz=pytz.utc)
                except ValueError as e:
                    raise ValueError(f"invalid date range {value!r}: {e}") from None
            return values

        allowed = {
            "Label": [*LABELS, LABEL_FILTER_NONE],
            "Label Source": list(SOURCES),
            "Stored": list(SAMPLE_BOOL_OPTIONS),
            "Missing Data": list(SAMPLE_BOOL_OPTIONS),
            "Unknown Version": list(SAMPLE_BOOL_OPTIONS),
            "Retired": list(SAMPLE_BOOL_OPTIONS),
        }.get(name)
        if allowed is None:
            return values

        values = [value.lower() for value in values]
        for value in values:
            if value not in allowed:
                raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(allowed)})")

        return values


_SHA_PREFIX = re.compile(r"^[0-9a-f]{4,64}$")


class ValidationFilterEntry(FilterEntryBase):
    """A filter entry of the SVS validations screen (GET /api/v2/svs/yara/validations)."""

    name: str = Field(description="a filter name of the SVS validations screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in SVS_VALIDATION_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(SVS_VALIDATION_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        if not all(isinstance(value, str) for value in values):
            raise ValueError(f"values must be strings, got {values!r}")

        name = info.data.get("name")
        if name == "Head":
            values = [value.strip().lower() for value in values]
            for value in values:
                if not _SHA_PREFIX.match(value):
                    raise ValueError(f"invalid commit {value!r} (expected at least 4 hex characters)")
            return values

        if name == "Created":
            now = datetime.now(pytz.utc)
            for value in values:
                try:
                    parse_date_range(value, now=now, tz=pytz.utc)
                except ValueError as e:
                    raise ValueError(f"invalid date range {value!r}: {e}") from None
            return values

        allowed = {
            "State": list(VALIDATION_STATES),
            "Has Regressions": list(SAMPLE_BOOL_OPTIONS),
            "Has New FP": list(SAMPLE_BOOL_OPTIONS),
            "Compile Errors": list(SAMPLE_BOOL_OPTIONS),
        }.get(name)
        if allowed is None:
            return values

        values = [value.lower() for value in values]
        for value in values:
            if value not in allowed:
                raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(allowed)})")

        return values


# an ATT&CK technique or sub-technique id, e.g. T1059 or T1059.001
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class CatalogTestFilterEntry(FilterEntryBase):
    """A filter entry of the SVS tests screen (GET /api/v2/svs/tests)."""

    name: str = Field(description="a filter name of the SVS tests screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in SVS_TEST_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(SVS_TEST_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        if not all(isinstance(value, str) for value in values):
            raise ValueError(f"values must be strings, got {values!r}")

        name = info.data.get("name")
        if name == "Technique":
            values = [value.strip().upper() for value in values]
            for value in values:
                if not _TECHNIQUE.match(value):
                    raise ValueError(f"invalid technique {value!r} (expected an ATT&CK id such as T1059 or T1059.001)")
            return values

        if name in ("Platform", "Executor"):
            return [value.strip().lower() for value in values]

        if name == "Removed":
            values = [value.lower() for value in values]
            for value in values:
                if value not in SAMPLE_BOOL_OPTIONS:
                    raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(SAMPLE_BOOL_OPTIONS)})")
            return values

        return values


# the date range filters of the SVS runs screen
RUN_DATE_RANGE_FILTER_NAMES = ("Created", "Started", "Ended", "Reviewed")


class RunFilterEntry(FilterEntryBase):
    """A filter entry of the SVS runs screen (GET /api/v2/svs/runs)."""

    name: str = Field(description="a filter name of the SVS runs screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in SVS_RUN_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(SVS_RUN_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        if not all(isinstance(value, str) for value in values):
            raise ValueError(f"values must be strings, got {values!r}")

        name = info.data.get("name")
        if name == "Technique":
            values = [value.strip().upper() for value in values]
            for value in values:
                if not _TECHNIQUE.match(value):
                    raise ValueError(f"invalid technique {value!r} (expected an ATT&CK id such as T1059 or T1059.001)")
            return values

        if name == "Test":
            values = [value.strip().lower() for value in values]
            for value in values:
                if not UUID_REGEX.fullmatch(value):
                    raise ValueError(f"invalid test guid {value!r}")
            return values

        if name == "Target":
            return [value.strip().lower() for value in values]

        if name == "Platform":
            # Atomic Red Team's names find the platform they count as: iaas:aws finds iaas
            return [normalize_platform(value) for value in values]

        if name in ("Owner", "Reviewer"):
            return [value.strip() for value in values]

        if name in RUN_DATE_RANGE_FILTER_NAMES:
            now = datetime.now(pytz.utc)
            for value in values:
                try:
                    parse_date_range(value, now=now, tz=pytz.utc)
                except ValueError as e:
                    raise ValueError(f"invalid date range {value!r}: {e}") from None
            return values

        allowed = {
            "State": list(RUN_STATES),
            "Changed Since Review": list(SAMPLE_BOOL_OPTIONS),
            "Has Open Alerts": list(SAMPLE_BOOL_OPTIONS),
            "Has Missing": list(SAMPLE_BOOL_OPTIONS),
            "Has Possibly Suppressed": list(SAMPLE_BOOL_OPTIONS),
            "Has Candidates": list(SAMPLE_BOOL_OPTIONS),
            "Has Late": list(SAMPLE_BOOL_OPTIONS),
            "Has Context Only": list(SAMPLE_BOOL_OPTIONS),
            "Needs Attention": list(SAMPLE_BOOL_OPTIONS),
        }.get(name)
        if allowed is None:
            return values

        values = [value.strip().lower() for value in values]
        for value in values:
            if value not in allowed:
                raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(allowed)})")

        return values


# the options of the Remediations screen's multiple-choice filters
REMEDIATION_FILTER_OPTIONS = {
    "Action": tuple(action.value for action in RemediationAction),
    "Status": tuple(status.value for status in RemediationStatus),
    "Result": tuple(result.value for result in RemediatorStatus),
}

# the options of the File Collections screen's multiple-choice filters
FILE_COLLECTION_FILTER_OPTIONS = {
    "Status": tuple(status.value for status in FileCollectionStatus),
    "Result": tuple(result.value for result in FileCollectorStatus),
}


def _request_filter_values(name: str, values: list, options: dict[str, tuple[str, ...]]) -> list:
    """The values of a filter of the Remediations or File Collections screen, which list the
    requests a service works through: an ID is a number, an Alert a uuid, Created a date range,
    and a multiple-choice value one of its options in any case. Text filters take any text."""
    if not all(isinstance(value, str) for value in values):
        raise ValueError(f"values must be strings, got {values!r}")

    if name == "ID":
        values = [value.strip() for value in values]
        for value in values:
            if not value.isdigit():
                raise ValueError(f"invalid id {value!r} (expected a number)")
        return values

    if name == "Alert":
        values = [value.strip().lower() for value in values]
        for value in values:
            if not UUID_REGEX.fullmatch(value):
                raise ValueError(f"invalid alert uuid {value!r}")
        return values

    if name == "Created":
        now = datetime.now(pytz.utc)
        for value in values:
            try:
                parse_date_range(value, now=now, tz=pytz.utc)
            except ValueError as e:
                raise ValueError(f"invalid date range {value!r}: {e}") from None
        return values

    allowed = options.get(name)
    if allowed is None:
        return values

    by_lower = {option.lower(): option for option in allowed}
    result = []
    for value in values:
        if value.lower() not in by_lower:
            raise ValueError(f"invalid {name} value {value!r} (expected one of {', '.join(allowed)})")
        result.append(by_lower[value.lower()])
    return result


class RemediationFilterEntry(FilterEntryBase):
    """A filter entry of the Remediations screen (GET /api/v2/remediation/remediations)."""

    name: str = Field(description="a filter name of the Remediations screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in REMEDIATION_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(REMEDIATION_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        return _request_filter_values(info.data.get("name"), values, REMEDIATION_FILTER_OPTIONS)


class FileCollectionFilterEntry(FilterEntryBase):
    """A filter entry of the File Collections screen (GET /api/v2/file-collections)."""

    name: str = Field(description="a filter name of the File Collections screen")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value not in FILE_COLLECTION_FILTER_SLUGS:
            raise ValueError(
                f"unknown filter name {value!r} (expected one of {', '.join(sorted(FILE_COLLECTION_FILTER_SLUGS))})")

        return value

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list, info) -> list:
        return _request_filter_values(info.data.get("name"), values, FILE_COLLECTION_FILTER_OPTIONS)
