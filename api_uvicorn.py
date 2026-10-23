#!/usr/bin/env python
"""FastAPI application entry point for uvicorn.

This module expects the environment to be set up by the container startup
script (docker/startup/start.sh -> bin/initialize-environment.sh) which sets:
- SAQ_HOME environment variable
- SAQ_CONFIG_PATHS environment variable (if load_local_environment exists)
- Activates the Python virtual environment

** WARNING **
Served via "uvicorn api_uvicorn:application --workers N". uvicorn --workers uses the
"spawn" start method, so each worker is a fresh interpreter and the async db engine
(aceapi_v2/database.py) is created lazily per worker -- no pooled connection crosses a
fork. Switching to a fork-based worker model would require a pid-checkout listener on
the engine; see the fork-safety note in aceapi_v2/database.py:create_engine_for.
"""
import os

import aceapi_v2
from saq.constants import ENV_ACE_LOG_CONFIG_PATH
from saq.environment import initialize_environment

# get SAQ_HOME from environment (set by container startup)
saq_home = os.environ.get("SAQ_HOME", os.path.dirname(os.path.realpath(__file__)))

# if no logging is specified then use the default console logging configuration
logging_config_path = os.environ.get(ENV_ACE_LOG_CONFIG_PATH)
if logging_config_path is None:
    logging_config_path = os.path.join(saq_home, "etc", "logging_configs", "console_logging.yaml")
elif not os.path.isabs(logging_config_path):
    logging_config_path = os.path.join(saq_home, logging_config_path)

initialize_environment(saq_home=saq_home, config_paths=None, logging_config_path=logging_config_path)

# create fastapi application
application = aceapi_v2.create_app()
