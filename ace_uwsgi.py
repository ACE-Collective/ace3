#!/usr/bin/env python
import os
import os.path
import sys

from saq.constants import ENV_ACE_LOG_CONFIG_PATH
from saq.environment import initialize_environment
import app

# apache env vars and wsgi are different
# so we use the location of this saq.wsgi file as the root of ACE
# which is what SAQ_HOME would be pointing to
os.environ['SAQ_HOME'] = os.path.dirname(os.path.realpath(__file__))
saq_home = os.environ['SAQ_HOME']
#os.environ['SAQ_ENC'] = 'ace'
#sys.stderr.write("\n\nsaq_home = {}\n\n".format(saq_home))

# additional config files are stored in SAQ_CONFIG_PATHS env var which are
# loaded from load_local_environment bash script sourced by load_environment
path = os.path.join(saq_home, 'load_local_environment')
if os.path.exists(path):
    # we execute a shell and source the script then output the value and capture the output
    from subprocess import Popen, PIPE
    p = Popen(['/bin/bash', '-c', 'source {} && echo $SAQ_CONFIG_PATHS'.format(path)], stdout=PIPE, universal_newlines=True)
    _stdout, _stderr = p.communicate()
    os.environ['SAQ_CONFIG_PATHS'] = _stdout.strip()

# adjust search path
sys.path.append(os.path.join(saq_home, 'lib'))
sys.path.append(os.path.join(saq_home))

logging_config_path = os.environ.get(ENV_ACE_LOG_CONFIG_PATH, os.path.join("etc", "logging_configs", "app_logging.yaml"))

# initialize saq
# note that config paths are determined by the env vars we dug out above
# NOTE that we do NOT set use_flask here YET since we're still using the Flask-SQLAlchemy extension
initialize_environment(saq_home=saq_home, config_paths=None, logging_config_path=logging_config_path)

# initialize flask
application = app.create_app() # fix this hard coded string

# tell ACE to use the session scope provided by the sqlalchemy-flask extension
#set_db(app.db.session) # ???
