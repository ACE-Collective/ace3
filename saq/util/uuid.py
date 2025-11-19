import os
import re

from saq.configuration.config import get_config_value
from saq.constants import CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR, G_SAQ_NODE
from saq.environment import g, get_base_dir, get_data_dir


UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

def validate_uuid(uuid):
    if not UUID_REGEX.match(uuid):
        raise ValueError("invalid UUID {}".format(uuid))

    return True

def is_uuid(uuid):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)

def get_storage_dir(uuid):
    """Returns the path (relative to SAQ_HOME) to the storage directory for the given uuid."""
    result = workload_storage_dir(uuid)
    if os.path.exists(result):
        return result
    else:
        return storage_dir_from_uuid(uuid)

def storage_dir_from_uuid(uuid):
    """Returns the path (relative to SAQ_HOME) to the storage directory for the given uuid."""
    validate_uuid(uuid)
    return os.path.relpath(os.path.join(get_data_dir(), g(G_SAQ_NODE), uuid[0:3], uuid), start=get_base_dir())

def workload_storage_dir(uuid):
    """Returns the path (relative to SAQ_HOME) to the storage directory for the current engien for the given uuid."""
    validate_uuid(uuid)
    if get_config_value(CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR):
        return os.path.join(get_config_value(CONFIG_ENGINE, CONFIG_ENGINE_WORK_DIR), uuid)
    else:
        return storage_dir_from_uuid(uuid)