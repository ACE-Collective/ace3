
from datetime import datetime
import logging
import logging.config
import os
import sys
from typing import Optional
import yaml


class CustomFileHandler(logging.StreamHandler):
    def __init__(self, log_dir: Optional[str]=".", filename_format: Optional[str]="%Y-%m-%d-%H.log"):
        assert isinstance(log_dir, str) and log_dir
        assert isinstance(filename_format, str) and filename_format
        super().__init__()

        # let this go because later the logic is to close the existing stream
        self.stream = None

        # the directory to store the log files in
        self.log_dir = log_dir

        # the format to use to generate the filename
        self.filename_format = filename_format

        # the current file name we're using
        self.current_filename = None
        self._update_stream()

    def _update_stream(self):
        assert self.filename_format
        assert self.log_dir

        # what should the file name be right now?
        current_filename = datetime.now().strftime(self.filename_format)

        # did the name change?
        if self.current_filename != current_filename:
            # close the current stream
            if self.stream:
                try:
                    self.stream.close()
                except OSError as e:
                    sys.stderr.write(f"error closing stream for {self.current_filename}: {e}\n")
            
            # and open a new one
            self.stream = open(os.path.join(self.log_dir, current_filename), 'a')
            self.current_filename = current_filename

    def emit(self, record: logging.LogRecord):
        self.acquire()
        try:
            self._update_stream()
            super().emit(record)
        finally:
            self.release()

# base configuration for logging
LOGGING_BASE_CONFIG = {
    'version': 1,
    'formatters': {
        'base': {
            'format': 
                '[%(asctime)s] [%(pathname)s:%(funcName)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s',
        },
    },
}

def initialize_logging(logging_config_path: str, log_sql: Optional[bool]=False, fluent_bit_tag: Optional[str]=None):
    assert isinstance(logging_config_path, str) and logging_config_path

    try:
        with open(logging_config_path, "r") as config_file:
            logging_config = yaml.safe_load(config_file)

        if not isinstance(logging_config, dict):
            raise ValueError("logging configuration YAML must parse to a dict")

        if "disable_existing_loggers" not in logging_config:
            logging_config["disable_existing_loggers"] = False

        # allow dynamic fluent-bit tagging
        if fluent_bit_tag:
            if "handlers" in logging_config:
                if "fluent" in logging_config["handlers"]:
                    logging_config["handlers"]["fluent"]["tag"] = fluent_bit_tag

        logging.config.dictConfig(logging_config)

    except Exception as e:
        sys.stderr.write("unable to load logging configuration from {}: {}".format(logging_config_path, e))
        raise e

    # adjust the logging on third party libraries as needed
    logging.getLogger('plyara').setLevel(logging.ERROR)
    logging.getLogger('plyara.core').setLevel(logging.ERROR)
    logging.getLogger('plyara.util').setLevel(logging.ERROR)
    logging.getLogger('olevba').setLevel(logging.CRITICAL)
    logging.getLogger('whois').setLevel(logging.CRITICAL)

    # log all SQL commands if we are running in debug mode
    if log_sql:
        logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.dialects').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.pool').setLevel(logging.DEBUG)
        #logging.getLogger('sqlalchemy.orm').setLevel(logging.DEBUG)

    # disable the verbose logging in the requests module
    logging.getLogger("requests").setLevel(logging.WARNING)
