
from abc import ABC, abstractmethod
import hashlib
import logging
import os
import threading
from typing import Union

from saq.collectors.email import RemoteEmailCollector
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_EMAIL
from saq.database import get_db
from saq.environment import get_data_dir
from saq.error import report_exception
from saq.persistence import Persistable


class EmailUser:
    """Base email user object used as common interface for
    email collectors/processors.

    This exists because we're trying to model email messages
    after the exchangelib API."""
    def __init__(self, email_address: str) -> None:
        self.email_address = email_address


class EmailObject(ABC):
    """Abstract class for email objects used by switchboard and other collectors.

    Exchangelib messages and Graph API messages have different formats. One is a
    class (exchangelib.Message) and the other is just a dictionary. By implementing
    a class that mimics the interface of the exchangelib.Message class, we can have
    mail collectors / email processors that work for both EWS and GraphAPI.

    If adding a new Email vendor/account type, inherit from this class
    and be sure to do the following in your `__init__`:
        - Place all the email data into an object assigned to the `self._message` attribute
        - Create an `EmailUser` object for the sender and assign it to the `self._sender` attributes
        - Fill out the `_to_recipients`, `__cc_recipients`, and `_bcc_recipients` attributes with
        lists filled with EmailUser objects.
        - Define the object type (graph, ews, gmail, etc.)
    """
    def __init__(self, message_object: dict) -> None:
        self._message = message_object
        self._sender: EmailUser = None
        self._to_recipients: list[EmailUser] = []
        self._cc_recipients: list[EmailUser] = []
        self._bcc_recipients: list[EmailUser] = []
        self._obj_type: str = None

    @property
    def sender(self):
        return self._sender

    @property
    def to_recipients(self) -> list[EmailUser]:
        return self._to_recipients

    @property
    def cc_recipients(self) -> list[EmailUser]:
        return self._cc_recipients

    @property
    def bcc_recipients(self) -> list[EmailUser]:
        return self._bcc_recipients

    @property
    @abstractmethod
    def subject(self) -> str:
        pass

    @property
    @abstractmethod
    def datetime_received(self):
        pass

    @property
    @abstractmethod
    def id(self):
        pass

    @property
    @abstractmethod
    def message_id(self):
        pass

    @property
    @abstractmethod
    def body(self):
        pass

    @property
    @abstractmethod
    def mime_content(self):
        pass


class EmailCollectionBaseProcessor(ABC, Persistable):
    def __init__(self, collector: RemoteEmailCollector, *args, process_email_func=None, **kwargs) -> None:
        super(ABC, self).__init__(*args, **kwargs)
        self.collector = collector
        self.target_mailbox: str = None
        self.frequency: int = 60
        self.delete_emails: bool = False
        self.save_unmatched_remotely: bool = False
        self.save_unmatched_locally: bool = False
        self.always_alert: bool = False
        self.analysis_mode: str = ANALYSIS_MODE_EMAIL
        self.add_email_to_alert: bool = False
        self.alert_prefix: str = None
        self.folders: list[str] = []
        self.unmatched_folder: str = None
        self.save_local_dir: str = None
        self.execution_thread: threading.Thread = None
        self.section: str = None
        self._persistence_source_key = None
        self._process_email_func = None

        # the total number of concurrent failures
        self.concurrent_failure_count = 0

        # once this failure count exceeds the limit we start logging error messages
        # defaults to 30 and configurable
        self.concurrent_failure_count_limit = 30

    def load_from_config(self, section: str, **kwargs) -> None:
        logging.debug(f'remote email account loading from {section}')
        _config = kwargs.get('config') or get_config()
        self.target_mailbox = _config[section]['target_mailbox']
        self.frequency = _config[section].getint('frequency', fallback=60)
        self.delete_emails = _config[section].getboolean('delete_emails', fallback=False)
        self.save_unmatched_remotely = _config[section].getboolean('save_unmatched_remotely')
        self.save_unmatched_locally = _config[section].getboolean('save_unmatched_locally')
        self.always_alert = _config[section].getboolean('always_alert', fallback=False)
        self.analysis_mode = _config[section].get('analysis_mode', fallback=ANALYSIS_MODE_EMAIL)
        self.add_email_to_alert = _config[section].getboolean('add_email_to_alert', fallback=False)
        self.alert_prefix = _config[section]['alert_prefix']
        self.section = section
        # Unique persistence source per mailbox/config section
        self._persistence_source_key = f'remote_email_collector:{self.target_mailbox.lower()}'

        # Enumerate folders to pull emails from
        for option, value in _config[section].items():
            if not option.startswith('folder_'):
                continue
            self.folders.append(value)

        if not self.folders:
            logging.error(f"no folder configuration options found for {self.target_mailbox} "
                          f"in configuration section {section}")

        # Get config required if we will be moving emails in GraphApi when they
        # are not matched by the collector
        if self.save_unmatched_remotely:
            self.unmatched_folder = _config[section]['unmatched_folder']
            if not self.unmatched_folder:
                logging.error("move unmatched emails enabled but no unmatched_folder was provided!")

        # Setup local directories for unmatched emails
        if self.save_unmatched_locally:
            self.set_unmatched_local_directory()

        self.concurrent_failure_count_limit = _config[section].getint('concurrent_failure_count_limit', fallback=self.concurrent_failure_count_limit)

    def set_unmatched_local_directory(self, data_dir: str = None) -> None:
        """Set local directory. Create it if it doesn't exist."""
        _data_dir = data_dir or get_data_dir()
        self.save_local_dir = os.path.join(_data_dir, 'review', f'{self.section}_unmatched')
        if not os.path.isdir(self.save_local_dir):
            try:
                logging.debug(f"creating required directory {self.save_local_dir}")
                os.makedirs(self.save_local_dir)
            except Exception as e:
                if not os.path.isdir(self.save_local_dir):
                    logging.error(
                        f"unable to create required directory {self.save_local_dir} for {self}: {e.__class__}, {e}"
                    )

    def handle_unmatched_locally(self, message: EmailObject) -> None:
        """Save unmatched emails to disk."""
        file_name = f"msg_{message.message_id}.eml"

        # Some message IDs can be extremely long, so instead we hash them
        # so that the resulting file name/path is not too long for the filesystem.
        if len(file_name) > 200:
            hash_prefix = hashlib.sha256(message.message_id.encode()).hexdigest()[:32]
            file_name = f"msg_{hash_prefix}.eml"
        path = os.path.join(self.save_local_dir, file_name)
        logging.debug(f"email remote collector didn't match message; writing email to {path}")
        mode = 'w' if isinstance(message.mime_content, str) else 'wb'
        with open(path, mode) as f:
            f.write(message.mime_content)

    def start(self):
        self.execution_thread = threading.Thread(target=self.run, name=f'Email Remote Collection {type(self).__name__}')
        self.execution_thread.start()

    def debug(self):
        self.execute()

    def stop(self):
        pass

    def wait(self, *args, **kwargs):
        return self.execution_thread.join(*args, **kwargs)

    def run(self):
        while not self.collector.is_service_shutdown:
            self.attempt_execution()

            # we only execute this every self.frequency seconds
            if self.collector.service_shutdown_event.wait(self.frequency):
                break

    def execute(self, **kwargs):
        return self._execute(**kwargs)

    def attempt_execution(self):
        try:
            self._execute()
            self.concurrent_failure_count = 0
        except Exception as e:
            self.concurrent_failure_count += 1
            if self.concurrent_failure_count >= self.concurrent_failure_count_limit:
                logging.error(f"uncaught exception: {e.__class__}, {e}")
                report_exception()
            else:
                logging.warning(f"uncaught exception: {e.__class__}, {e}")
        finally:
            get_db().remove()

    @property
    def process_email_func(self):
        return self._process_email_func

    @process_email_func.setter
    def process_email_func(self, some_func):
        self._process_email_func = some_func

    def process_email(self, *args, **kwargs):
        if self._process_email_func is None:
            raise ValueError(
                'cannot handle email because process_email_func not set in EmailCollectorAccountConfig subclass'
            )
        return self._process_email_func(*args, **kwargs)

    @abstractmethod
    def handle_unmatched_remotely(self, message: EmailObject) -> None:
        pass

    @abstractmethod
    def handle_delete_message(self, message: EmailObject) -> None:
        pass

    @abstractmethod
    def _execute(self, **kwargs):
        pass

    @abstractmethod
    def initialize_auth(self, **kwargs) -> bool:
        pass
