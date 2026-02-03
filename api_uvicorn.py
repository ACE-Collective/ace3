#!/usr/bin/env python
"""FastAPI application entry point for uvicorn.

This module expects the environment to be set up by the container startup
script (docker/startup/start.sh -> bin/initialize-environment.sh) which sets:
- SAQ_HOME environment variable
- SAQ_CONFIG_PATHS environment variable (if load_local_environment exists)
- Activates the Python virtual environment
"""
import os

import aceapi_v2
from saq.configuration import initialize_configuration
from saq.configuration.config import get_config, resolve_configuration
from saq.constants import ENV_ACE_LOG_CONFIG_PATH
from saq.crypto import initialize_encryption
from saq.logging import initialize_logging

# get SAQ_HOME from environment (set by container startup)
saq_home = os.environ.get("SAQ_HOME", os.path.dirname(os.path.realpath(__file__)))

# if no logging is specified then use the default console logging configuration
logging_config_path = os.environ.get(ENV_ACE_LOG_CONFIG_PATH)
if logging_config_path is None:
    logging_config_path = os.path.join(saq_home, "etc", "logging_configs", "console_logging.yaml")
elif not os.path.isabs(logging_config_path):
    logging_config_path = os.path.join(saq_home, logging_config_path)

# initialize configuration and logging (minimal init for FastAPI)
initialize_configuration(config_paths=None)
initialize_logging(logging_config_path)

# initialize encryption so that encrypted config values (e.g. gui.secret_key)
# get resolved — required for Flask session cookie verification
initialize_encryption()
resolve_configuration(get_config())

# create fastapi application
application = aceapi_v2.create_app()
