from datetime import datetime
import logging
import os
from typing import Generator, Optional
from uuid import uuid4

from minio.api import DeleteObject
from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import Collector, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration.config import get_config, get_config_value, get_config_value_as_int
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_CHECK_FREQUENCY, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH, CONFIG_JOURNAL_EMAIL_COLLECTOR_S3_BUCKET, CONFIG_JOURNAL_EMAIL_COLLECTOR_S3_PREFIX, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, G_TEMP_DIR
from saq.environment import g
from saq.storage.minio import get_minio_client
from saq.util.filesystem import delete_file
from saq.util.time import local_time

from minio import Minio
import yara

class JournalEmailCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.s3_bucket: str = get_config_value(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_S3_BUCKET)
        self.s3_prefix: str = get_config_value(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_S3_PREFIX, "")

        self.client: Minio = get_minio_client()

        # if the bucket does not exist, create it
        if not self.client.bucket_exists(self.s3_bucket):
            self.client.make_bucket(self.s3_bucket)

        # inbound emails are scanned by this yara context to support node assignment
        self.blacklist_yara_rule_path: str = get_config_value(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH)

        # check every N seconds to see if the blacklist yara rule has changed
        self.blacklist_yara_rule_check_frequency: int = get_config_value_as_int(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_CHECK_FREQUENCY)
        self.blacklist_yara_rule_last_check: datetime = local_time()
        self.blacklist_yara_rule_last_mtime: int = 0

        self.yara_context: Optional[yara.Rules] = None

    def should_load_blacklist_yara_rule(self) -> bool:
        """Returns True if the blacklist yara rule should be loaded, False otherwise."""
        if not self.blacklist_yara_rule_path:
            return False

        if not os.path.exists(self.blacklist_yara_rule_path):
            logging.warning(f"blacklist yara rule file {self.blacklist_yara_rule_path} does not exist")
            return False

        if self.yara_context is not None:
            if (local_time() - self.blacklist_yara_rule_last_check).total_seconds() < self.blacklist_yara_rule_check_frequency:
                return False

        # has the file changed?
        return self.blacklist_yara_rule_last_mtime != os.path.getmtime(self.blacklist_yara_rule_path)

    def load_blacklist_yara_rule(self):
        """Loads the blacklist yara rule from the file."""
        self.yara_context = yara.compile(filepath=self.blacklist_yara_rule_path)

    def is_blacklisted(self, email_path: str) -> bool:
        """Returns True if the email is blacklisted, False otherwise."""
        if self.should_load_blacklist_yara_rule():
            self.load_blacklist_yara_rule()

        if self.yara_context is None:
            return False

        yara_matches = self.yara_context.match(email_path)

        # check for blacklisting first
        for match in yara_matches:
            for tag in match.tags:
                if tag == 'blacklist':
                    logging.info(f"{email_path} matched blacklist rule {match.rule}")
                    return True

        return False

    def collect(self) -> Generator[Submission, None, None]:
        object_list = []
        for s3_object in self.client.list_objects(self.s3_bucket, self.s3_prefix, include_user_meta=True):
            object_list.append(s3_object)

            # temp directory for the email and the submission
            email_path = os.path.join(g(G_TEMP_DIR), str(uuid4()))
            logging.info(f"downloading email {s3_object.object_name} to {email_path}")
            self.client.fget_object(self.s3_bucket, s3_object.object_name, email_path)

            if self.is_blacklisted(email_path):
                delete_file(email_path)
                continue

            root_uuid = str(uuid4())
            storage_dir = os.path.join(g(G_TEMP_DIR), root_uuid)

            root = RootAnalysis(
                uuid = root_uuid,
                storage_dir = storage_dir,
                desc = "ACE Mailbox Scanner Detection",
                analysis_mode = ANALYSIS_MODE_EMAIL,
                tool = 'ACE - Mailbox Scanner',
                tool_instance = self.fqdn,
                alert_type = ANALYSIS_TYPE_MAILBOX,
                event_time = local_time(),
                #event_time = datetime.fromtimestamp(os.path.getmtime(email_path)),
                details = {},
            )
            root.initialize_storage()
            email_observable = root.add_file_observable(email_path, target_path="email.rfc822", move=True)
            if email_observable:
                email_observable.add_directive(DIRECTIVE_NO_SCAN)
                email_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                email_observable.add_directive(DIRECTIVE_ARCHIVE)

            yield Submission(root, key=s3_object.object_name)

        logging.info(f"collected {len(object_list)} emails from {self.s3_bucket}/{self.s3_prefix}")
        if object_list:
            for delete_error in self.client.remove_objects(self.s3_bucket, [DeleteObject(s3_object.object_name) for s3_object in object_list]):
                logging.error(f"unable to delete {delete_error.object_name}: {delete_error.error}")

class JournalEmailCollectorService(CollectorService):
    def __init__(self, *args, **kwargs):
        super().__init__(collector=JournalEmailCollector(), config=CollectorServiceConfiguration.from_config(get_config()[CONFIG_JOURNAL_EMAIL_COLLECTOR]), *args, **kwargs)