from datetime import datetime
import logging
import os
from typing import Generator, Type
from uuid import uuid4

from pydantic import Field
from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import Collector, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, SERVICE_EMAIL_COLLECTOR
from saq.environment import get_data_dir, get_temp_dir

import yara

from saq.error.reporting import report_exception


class EmailCollector(Collector):
    """Collects emails received by local email system."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # the location of the incoming emails
        self.email_dir = os.path.join(get_data_dir(), get_config().email.email_dir)

        # the datetime format string used to create the subdirectories that contain the emails
        self.subdir_format = get_config().email.subdir_format

        # a list (set) of subdirs that we tried to delete but couldn't
        # we keep this list so we don't keep trying to delete them
        self.invalid_subdirs = set()

        # inbound emails are scanned by this yara context to support node assignment
        self.yara_context = None
        self.assignment_yara_rule_path = get_service_config(SERVICE_EMAIL_COLLECTOR).assignment_yara_rule_path
        self.blacklist_yara_rule_path = get_service_config(SERVICE_EMAIL_COLLECTOR).blacklist_yara_rule_path

        rule = ""

        if self.assignment_yara_rule_path:
            if os.path.exists(self.assignment_yara_rule_path):
                logging.debug(f"reading assignment rules from {self.assignment_yara_rule_path}")
                with open(self.assignment_yara_rule_path, 'r') as fp:
                    rule += fp.read()

        if self.blacklist_yara_rule_path:
            if os.path.exists(self.blacklist_yara_rule_path):
                logging.debug(f"reading blacklist rules from {self.blacklist_yara_rule_path}")
                with open(self.blacklist_yara_rule_path, 'r') as fp:
                    rule += "\n\n" # just make it easier to read if we ever have to look at it
                    rule += fp.read()

        if rule:
            try:
                self.yara_context = yara.compile(source=rule)
            except Exception as e:
                logging.error(f"unable to compile email collector assignment and blacklist yara rule: {e}")
                report_exception()

    def collect(self) -> Generator[Submission, None, None]:

        # first get a list of the sub-directories in this directory
        # each directory has the format YYYYMMDDHH
        # these should be sorted from oldest to newest
        subdirs = sorted(filter(os.path.isdir, [os.path.join(self.email_dir, _) for _ in os.listdir(self.email_dir)]), key=os.path.getmtime)

        # total number of submitted emails
        submitted_emails = 0

        for subdir_name in subdirs:
            target_dir = os.path.join(self.email_dir, subdir_name)
            # skip the ones we couldn't delete
            if target_dir in self.invalid_subdirs:
                continue

            logging.debug(f"checking for emails in {target_dir}")
            email_count = 0

            for email_file in os.listdir(target_dir):
                email_count += 1
                # emails are written to a file with a .new extension while being written
                # then renamed without with .new when completed
                if email_file.endswith(".new"):
                    continue

                email_path = os.path.join(target_dir, email_file)
                logging.info(f"found email {email_file}")

                group_assignments = []

                # yara rules can control what groups the email actually gets sent to
                yara_matches = []
                if self.yara_context:
                    logging.debug(f"matching {email_path} against yara rules")
                    yara_matches = self.yara_context.match(email_path)

                # check for blacklisting first
                blacklisted = False
                for match in yara_matches:
                    for tag in match.tags:
                        if tag == 'blacklist':
                            logging.info(f"{email_path} matched blacklist rule {match.rule}")
                            blacklisted = True
                            break

                if blacklisted:
                    # we just delete it and move on
                    try:
                        os.remove(email_path)
                    except Exception as e:
                        logging.error(f"unable to delete {email_path}: {e}")

                    continue

                for match in yara_matches:
                    group_assignments = match.tags[:]
                    logging.info(f"assigning email {email_path} to groups {','.join(group_assignments)}")

                # create a new submission request for this
                root_uuid = str(uuid4())
                root = RootAnalysis(
                    storage_dir = os.path.join(get_temp_dir(), root_uuid),  # noqa: F821
                    desc = 'ACE Mailbox Scanner Detection - {}'.format(email_file),
                    analysis_mode = ANALYSIS_MODE_EMAIL,
                    tool = 'ACE - Mailbox Scanner',
                    tool_instance = self.fqdn,
                    alert_type = ANALYSIS_TYPE_MAILBOX,
                    event_time = datetime.fromtimestamp(os.path.getmtime(email_path)),
                    details = {},
                    #observables = [ { 'type': F_FILE,
                                    #'value': 'email.rfc822',
                                    #'directives': [ DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_ARCHIVE ], } ],
                    #files=[(email_path, 'email.rfc822')],
                )
                root.initialize_storage()
                email_observable = root.add_file_observable(email_path, target_path="email.rfc822", move=True)
                if email_observable:
                    email_observable.add_directive(DIRECTIVE_NO_SCAN)
                    email_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                    email_observable.add_directive(DIRECTIVE_ARCHIVE)

                yield Submission(root, group_assignments=group_assignments)
                submitted_emails += 1

            # was this directory empty?
            if email_count == 0:
                # does the current directory name not equal the current YYYYMMDDHH?
                if subdir_name != datetime.now().strftime(self.subdir_format):
                    try:
                        logging.info(f"deleting empty email directory {target_dir}")
                        os.rmdir(target_dir)
                    except Exception as e:
                        # a race condition can lead to this failing if another process adds in between these steps
                        # in that case the other process will clean up
                        logging.info(f"unable to delete {target_dir}: {e}")
                        #self.invalid_subdirs.add(target_dir)

    def update(self) -> None:
        pass

    def cleanup(self) -> None:
        pass

class EmailCollectorConfig(CollectorServiceConfiguration):
    assignment_yara_rule_path: str = Field(..., description="The path to the yara rule for assigning emails to collectors.")
    blacklist_yara_rule_path: str = Field(..., description="The path to the yara rule for blacklisting emails.")
    blacklist_yara_rule_check_frequency: int = Field(..., description="The frequency of checking the blacklist yara rule in seconds.")

class EmailCollectorService(CollectorService):
    def __init__(self, *args, **kwargs):
        super().__init__(collector=EmailCollector(), config=get_config().get_service_config(SERVICE_EMAIL_COLLECTOR), *args, **kwargs)

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return EmailCollectorConfig