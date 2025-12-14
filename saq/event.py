import datetime
import logging
import os.path

from typing import Optional

from saq.configuration.config import get_config
from saq.database import Event, EventStatus, get_db
from saq.environment import get_global_runtime_settings
from saq.error import report_exception

from yaml import load as yaml_load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def _get_threat_names(event: Event):
    return [ _.malware.name for _ in event.malware ]

class AutoCloseCriteria:
    def __init__(self, threat_name: str):
        self.threat_name = threat_name

    # this is added for testing purposes
    def __eq__(self, other):
        if not isinstance(other, AutoCloseCriteria):
            return False

        return self.threat_name == other.threat_name

    def matches(self, threat_names: list[str]) -> bool:
        """Returns True if the given event data matches the auto close criteria."""
        if not threat_names:
            logging.debug("threat name not set or empty")
            return False

        if self.threat_name not in threat_names:
            logging.debug(f"threat_names does not have threat {self.threat_name}")
            return False

        return True

def load_auto_close_criteria(file_path: Optional[str]=None) -> list[AutoCloseCriteria]:
    """Returns the list of configured auto close criteria.
    Returns an empty list if none can be loaded."""
    if file_path is None:
        file_path = os.path.join(get_global_runtime_settings().analyst_data_dir, get_config().events.autoclose_path)

    with open(file_path, "r") as fp:
        content = yaml_load(fp, Loader=Loader)
        if not content:
            return []

        if "criteria" not in content:
            return []

        return [AutoCloseCriteria(**_) for _ in content["criteria"]]

def get_auto_close_events(criteria: Optional[dict]=None) -> list[int]:
    """Returns a list of events that have been configured for auto-closing and have expired in time.
    Returns an empty list if none are found that match this criteria."""
    try:
        if criteria is None:
            criteria = load_auto_close_criteria()

        # get the status id associated to the "OPEN" status
        open_id = get_db().query(EventStatus.id).filter(EventStatus.value == "OPEN").scalar()

        # look for events with creation date 2 days or older
        cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=2)).replace(hour=0, minute=0, second=0)
        return [event.id for event in get_db().query(Event).filter(Event.status_id == open_id, Event.creation_date <= cutoff_date)
                if any([c.matches(_get_threat_names(event)) for c in load_auto_close_criteria()])]

    except Exception as e:
        logging.error(f"unable to load auto close criteria: {e}")
        report_exception()
