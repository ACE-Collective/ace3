#!/usr/bin/env python
"""AI investigation API entry point for uvicorn.

Same environment contract as api_uvicorn.py (SAQ_HOME set by docker/startup/start.sh, spawn-based
uvicorn workers, per-worker async db engine), with one addition: the custody checks in
aceapi_ai.startup_checks run after environment initialization and abort the process unless this
container holds no encryption capability, no GUI/node credentials, and no plaintext secret its
query backends do not declare. See that module for the property being enforced.
"""
import os

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

initialize_environment(saq_home=saq_home, config_paths=None, logging_config_path=logging_config_path, relative_dir=saq_home)

# refuses to boot unless the container upholds the custody property; imported after environment
# initialization because the checks read the loaded configuration
from aceapi_ai.startup_checks import run_startup_checks

run_startup_checks()

import aceapi_ai

application = aceapi_ai.create_app()
