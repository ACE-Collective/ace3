"""One entry of a filter list: the {name, inverted, values} shape the GUI's filter editor
produces, the database stores, and a share URL encodes."""

from datetime import datetime
from typing import Union

import pytz
from pydantic import BaseModel, ConfigDict, Field, field_validator

from saq.analysis.module_path import IS_MODULE_PATH
from saq.gui.detection_point_value import normalize_detection_point_value
from saq.gui.filter_names import DATE_RANGE_FILTER_NAMES, FILTER_NAMES
from saq.util.relative_time import parse_date_range


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
