"""Alert dispositions: the configured list, how each is shown, and how each classifies.

The `dispositions:` config block is the only list of dispositions there is. Its order is the
order the disposition modals show them in. `disposition_classification:` says which of them
mean a detection found malicious activity (tp) and which mean it did not (fp); anything not
listed there is unclassified (OPEN, IGNORE, UNKNOWN, REVIEWED). See docs/SVS.md, Part 1.

Everything here reads the configuration on each call rather than caching it, so a test can
change the configuration and see the change.
"""

import logging
from typing import Optional

from saq.configuration.config import get_config, get_engine_config

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


def is_valid_disposition(disposition: Optional[str]) -> bool:
    return disposition in get_config().dispositions


def is_selectable_disposition(disposition: Optional[str]) -> bool:
    """True if an analyst may set this disposition. The server enforces this: a disposition that
    is not analyst_selectable is set only by ACE itself."""
    config = get_config().dispositions.get(disposition)
    return config is not None and config.analyst_selectable


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


def initialize_dispositions():
    """Checks the disposition configuration once per process and records the classification.

    The engine's stop_analysis_on_dispositions lives in the engine's service config, which the
    main config schema does not validate, so a typo there is caught here rather than silently
    never matching.
    """
    unknown = [d for d in get_engine_config().stop_analysis_on_dispositions if not is_valid_disposition(d)]
    if unknown:
        raise ValueError(
            f"service_engine.stop_analysis_on_dispositions names dispositions that are not "
            f"configured in dispositions: {', '.join(unknown)}")

    # Logged at WARNING on every start on purpose: labels are derived from this map when they
    # are read, so a changed map relabels every detection at once (docs/SVS.md, Logging contract).
    classification = dict(get_config().disposition_classification)
    logging.warning("disposition classification in effect", extra={"disposition_classification": classification})
