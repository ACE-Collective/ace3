"""Alert dispositions: the configured list, how each is shown, and how each classifies.

The `dispositions:` config block is the only list of dispositions there is. Its order is the
order the disposition modals show them in. `disposition_classification:` says which of them
mean a detection found malicious activity (tp) and which mean it did not (fp); anything not
listed there is unclassified (OPEN, IGNORE, UNKNOWN, REVIEWED). See docs/SVS.md, Part 1.

`alert_type_dispositions:` keeps some dispositions to some alert types (feed watch alerts have only
OPEN, IGNORE, RELEVANT and NOT_RELEVANT): a type with a list has only its list, and a disposition
named in any list is hidden from every type without one, except OPEN and IGNORE, which ACE gives
every alert (the disposition it starts with, and the one the cleanup deletes).

Everything here reads the configuration on each call rather than caching it, so a test can
change the configuration and see the change.
"""

import logging
from typing import Optional

from saq.configuration.config import get_config, get_engine_config
from saq.constants import DISPOSITION_IGNORE, DISPOSITION_OPEN

DISPOSITION_CLASS_TP = "tp"
DISPOSITION_CLASS_FP = "fp"

# the badge style for a disposition value that is no longer configured, such as one stored on an
# alert before the disposition was removed
DEFAULT_DISPOSITION_CSS = "secondary"


def get_dispositions() -> dict[str, dict]:
    """Every configured disposition, in configured order:
    name -> {"rank", "css", "show_save_to_event", "analyst_selectable"}."""
    return {name: disposition.model_dump() for name, disposition in get_config().dispositions.items()}


def get_selectable_dispositions() -> dict[str, dict]:
    """The dispositions an analyst may choose, in configured order (the disposition modals)."""
    return {name: value for name, value in get_dispositions().items() if value["analyst_selectable"]}


# never hidden from an alert type without a list of its own
UNRESTRICTED_DISPOSITIONS = (DISPOSITION_OPEN, DISPOSITION_IGNORE)


class DispositionNotAllowed(ValueError):
    """The disposition is not one the alert's type may have (alert_type_dispositions)."""

    def __init__(self, disposition: str, alert_types: dict[str, Optional[str]]):
        types = ", ".join(sorted({str(alert_type) for alert_type in alert_types.values()}))
        super().__init__(f"{disposition} is not a disposition of {types} alerts")
        self.disposition = disposition
        # alert uuid -> its alert type
        self.alert_types = alert_types


def is_disposition_allowed(disposition: Optional[str], alert_type: Optional[str]) -> bool:
    """True if an alert of alert_type may have this disposition (see the module docstring)."""
    lists = get_config().alert_type_dispositions
    if alert_type in lists:
        return disposition in lists[alert_type]
    if disposition in UNRESTRICTED_DISPOSITIONS:
        return True
    return not any(disposition in names for names in lists.values())


def get_alert_type_dispositions(alert_type: Optional[str]) -> dict[str, dict]:
    """The dispositions an analyst may choose for an alert of alert_type, in configured order."""
    return {name: value for name, value in get_selectable_dispositions().items()
            if is_disposition_allowed(name, alert_type)}


def is_valid_disposition(disposition: Optional[str]) -> bool:
    return disposition in get_config().dispositions


def is_selectable_disposition(disposition: Optional[str]) -> bool:
    """True if an analyst may set this disposition. The server enforces this: a disposition that
    is not analyst_selectable is set only by ACE itself."""
    config = get_config().dispositions.get(disposition)
    return config is not None and config.analyst_selectable


def is_frozen_disposition(disposition: Optional[str]) -> bool:
    """True if an alert with this disposition is frozen: only ACE sets the disposition (it is not
    analyst_selectable), so no analyst changes it, and the alert is never reset or re-analyzed.
    SIMULATED is the one such disposition (docs/SVS_RUNS.md)."""
    config = get_config().dispositions.get(disposition)
    return config is not None and not config.analyst_selectable


def get_disposition_rank(disposition: Optional[str]) -> Optional[int]:
    """The rank used to roll an event's alerts up to one disposition, or None for a value that
    is not configured."""
    config = get_config().dispositions.get(disposition)
    return config.rank if config is not None else None


def get_disposition_css(disposition: Optional[str]) -> str:
    """The badge style for a disposition, with a neutral default for a value that is not
    configured (it can still be stored on an old alert)."""
    config = get_config().dispositions.get(disposition)
    return config.css if config is not None else DEFAULT_DISPOSITION_CSS


def get_disposition_class(disposition: Optional[str]) -> Optional[str]:
    """DISPOSITION_CLASS_TP, DISPOSITION_CLASS_FP, or None for an unclassified disposition."""
    return get_config().disposition_classification.get(disposition)


def validate_stop_analysis_on_dispositions():
    """Checks that every disposition the engine's stop_analysis_on_dispositions names is configured.

    The setting lives in the engine's service config, which the main config schema does not
    validate, so a typo there is caught when an Engine is created rather than silently never
    matching. Only the engine reads it, and resolving the engine's service config imports the
    engine, so no other process checks it.
    """
    unknown = [d for d in get_engine_config().stop_analysis_on_dispositions if not is_valid_disposition(d)]
    if unknown:
        raise ValueError(
            f"service_engine.stop_analysis_on_dispositions names dispositions that are not "
            f"configured in dispositions: {', '.join(unknown)}")
