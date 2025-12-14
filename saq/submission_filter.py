import io
import json
import logging
import os
import tempfile

import plyara
import yara

from saq.configuration.config import get_config
from saq.constants import F_FILE
from saq.environment import get_data_dir, get_temp_dir
from saq.util import abs_path, create_timedelta, local_time
from yara_scanner import YaraScanner


def get_submission_target_buffer(submission):
    """Returns the buffer used for scanning submission details as a bytes object."""
    from saq.analysis.root import Submission
    from saq.json_encoding import _JSONEncoder

    assert isinstance(submission, Submission)

    details_json = json.dumps(submission.root.details, indent=True, sort_keys=True, cls=_JSONEncoder)
    observables_json = json.dumps(submission.root.observables, indent=True, sort_keys=True, cls=_JSONEncoder)
    return f"""
description = {submission.root.description}
analysis_mode = {submission.root.analysis_mode}
tool = {submission.root.tool}
tool_instance = {submission.root.tool_instance}
type = {submission.root.alert_type}
event_time = {submission.root.event_time}
tags = {','.join([tag.name for tag in submission.root.tags])}

{observables_json}

{details_json}
""".encode('utf8', errors='backslashreplace')


# list of valid tuning targets
TUNING_TARGET_SUBMISSION = 'submission'
TUNING_TARGET_OBSERVABLE = 'observable'
TUNING_TARGET_FILES = 'files'
TUNING_TARGET_ALL = 'all'
VALID_TUNING_TARGETS = [ 
    TUNING_TARGET_SUBMISSION,
    TUNING_TARGET_FILES,
    TUNING_TARGET_OBSERVABLE,
    TUNING_TARGET_ALL
]

class SubmissionFilter:
    """A filtering object that takes submissions to ACE and runs filtering yara rules on them.
       Submission that match one or more filtering rules are discarded (and optionally logged.)"""

    def __init__(self):

        # this YaraScanner is only used to track changes to the directories that contain the yara rules
        self.tracking_scanner = None

        # dictionary of tuning scanners
        # see initialize_tuning_rules()
        self.tuning_scanners = {} # key = tuning target (see VALID_TUNING_TARGETS), value = YaraScanner

        # temporary directory used for the "all" target
        self.tuning_temp_dir = get_config().collection.tuning_temp_dir
        if not self.tuning_temp_dir:
            self.tuning_temp_dir = get_temp_dir()

        if not os.path.isabs(self.tuning_temp_dir):
            self.tuning_temp_dir = os.path.join(get_data_dir(), self.tuning_temp_dir)

        if not os.path.isdir(self.tuning_temp_dir):
            try:
                logging.info(f"creating tuning temp directory {self.tuning_temp_dir}")
                os.makedirs(self.tuning_temp_dir)
            except Exception as e:
                # if we cannot create the directory then we just disable target type all tuning
                logging.error(f"unable to create tuning temp directory {self.tuning_temp_dir}: {e}")
                logging.warning("tuning target \"all\" disabled")
                self.tuning_temp_dir = None

        # controls how often submission filters check to see if the tuning rules are updated
        self.tuning_update_frequency = create_timedelta(get_config().collection.tuning_update_frequency)
        self.next_update = None

    def load_tuning_rules(self):
        logging.info("loading tuning rules for submissions")
        # when will the next time be that we check to see if the rules need to be updated?
        self.next_update = local_time() + self.tuning_update_frequency

        # get the list of tuning rule directories we're going to track
        yara_dirs = []
        for yara_dir in get_config().collection.tuning_dirs:
            yara_dir = abs_path(yara_dir)
            if not os.path.isdir(yara_dir):
                logging.error(f"tuning directory {yara_dir} does not exist or is not a directory")
                continue

            logging.debug(f"added tuning directory {yara_dir}")
            yara_dirs.append(yara_dir)

        # are we not tuning anything?
        if not yara_dirs:
            return

        # we use this to track changes to the directories containing yara rules
        # this is because we actually split the rules into tuning targets
        # so that is actually loaded doesn't match what is on disk
        self.tracking_scanner = YaraScanner()
        for yara_dir in yara_dirs:
            self.tracking_scanner.track_yara_dir(yara_dir)

        # now we need to split the rules according to what they target
        tuning_scanners = {}
        tuning_rules = {}
        for target in VALID_TUNING_TARGETS:
            tuning_scanners[target] = YaraScanner()
            tuning_rules[target] = tempfile.mkstemp(suffix='.yar',
                                                    prefix=f'tuning_{target}_',
                                                    dir=get_temp_dir())

        for yara_dir in yara_dirs:
            for yara_file in os.listdir(yara_dir):
                if not yara_file.endswith('.yar'):
                    continue

                yara_file = os.path.join(yara_dir, yara_file)
                logging.debug(f"parsing tuning rule {yara_file}")

                # make sure this yara code compiles
                # plyara doesn't raise syntax errors
                try:
                    yara.compile(filepath=yara_file)
                except yara.SyntaxError as e:
                    logging.error(f"tuning rule file {yara_file} has syntax error - skipping: {e}")
                    continue
                
                yara_parser = plyara.Plyara()
                with open(yara_file, 'r') as fp:
                    for parsed_rule in yara_parser.parse_string(fp.read()):
                        targets = []
                        if 'metadata' in parsed_rule:
                            for meta in parsed_rule['metadata']:
                                if 'targets' in meta:
                                    targets = [_.strip() for _ in meta['targets'].split(',')]

                        if not targets:
                            logging.error(f"tuning rule {parsed_rule['rule_name']} missing targets directive")
                            continue

                        for target in targets:
                            if target not in VALID_TUNING_TARGETS:
                                logging.error(f"tuning rule {parsed_rule['rule_name']} "
                                              f"has invalid target directive {target}")
                                continue

                            logging.debug(f"adding rule {parsed_rule['rule_name']} to {tuning_rules[target][1]}")
                            os.write(tuning_rules[target][0], 
                                     plyara.utils.rebuild_yara_rule(parsed_rule).encode('utf8'))
                            os.write(tuning_rules[target][0], b'\n')

        for target in VALID_TUNING_TARGETS:
            os.close(tuning_rules[target][0])
            if os.path.getsize(tuning_rules[target][1]):
                #with open(tuning_rules[target][1], 'r') as fp:
                    #print(fp.read())
                tuning_scanners[target].track_yara_file(tuning_rules[target][1])
                tuning_scanners[target].load_rules()
            else:
                logging.debug(f"no rules available for target {target}")
                del tuning_scanners[target]

            # once the rules are compiled we no longer need the temporary source code
            os.remove(tuning_rules[target][1])

        self.tuning_scanners = tuning_scanners

    def update_rules(self):
        # is it time to check to see if the rules needs to be checked for updates?
        need_update = False
        if self.next_update is None:
            need_update = True
        elif self.tracking_scanner is not None:
            if local_time() >= self.next_update:
                need_update = self.tracking_scanner.check_rules()

        if need_update:
            self.load_tuning_rules()

    def get_tuning_matches(self, submission):
        from saq.analysis.root import Submission
        assert isinstance(submission, Submission)

        self.update_rules()
        matches = []
        matches.extend(self.get_tuning_matches_submission(submission))
        matches.extend(self.get_tuning_matches_observable(submission))
        matches.extend(self.get_tuning_matches_files(submission))
        matches.extend(self.get_tuning_matches_all(submission))
        return matches

    def get_tuning_matches_submission(self, submission):
        from saq.analysis.root import Submission

        assert isinstance(submission, Submission)

        if TUNING_TARGET_SUBMISSION not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_SUBMISSION]
        target_buffer = get_submission_target_buffer(submission)
        scanner.scan_data(target_buffer)
        return scanner.scan_results

    def get_tuning_matches_observable(self, submission):
        from saq.json_encoding import _JSONEncoder
        from saq.analysis.root import Submission

        assert isinstance(submission, Submission)

        if TUNING_TARGET_OBSERVABLE not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_OBSERVABLE]

        matches = []
        for observable in submission.root.observables:   
            target_buffer = json.dumps(submission.root.observables, 
                                       indent=True, 
                                       sort_keys=True, 
                                       cls=_JSONEncoder).encode('utf8', errors='backslashreplace')

            scanner.scan_data(target_buffer)
            matches.extend(scanner.scan_results[:])

        return matches

    def get_tuning_matches_files(self, submission):
        from saq.analysis.root import Submission
        assert isinstance(submission, Submission)

        if TUNING_TARGET_FILES not in self.tuning_scanners:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_FILES]
        matches = []
        for file in submission.root.get_observables_by_type(F_FILE):
            target_file = file.full_path
            scanner.scan(target_file)
            matches.extend(scanner.scan_results[:])

        return matches

    def get_tuning_matches_all(self, submission):
        from saq.analysis.root import Submission

        assert isinstance(submission, Submission)

        if TUNING_TARGET_ALL not in self.tuning_scanners:
            return []

        # if we do not have a temp dir to use then we cannot do this
        if self.tuning_temp_dir is None:
            return []

        scanner = self.tuning_scanners[TUNING_TARGET_ALL]
        fd, target_buffer_path = tempfile.mkstemp(suffix=".buffer", prefix="all_", dir=self.tuning_temp_dir)
        try:
            os.write(fd, get_submission_target_buffer(submission))
            for file_observable in submission.root.get_observables_by_type(F_FILE):
                file_path = file_observable.full_path

                with open(file_path, 'rb') as fp:
                    while True:
                        _buffer = fp.read(io.DEFAULT_BUFFER_SIZE)
                        if _buffer == b'':
                            break

                        os.write(fd, _buffer)

            os.close(fd)
            scanner.scan(target_buffer_path)
            return scanner.scan_results

        finally:
            try:
                os.remove(target_buffer_path)
            except Exception as e:
                logging.error(f"unable to delete {target_buffer_path}: {e}")

    def log_tuning_matches(self, submission, tuning_matches):
        from saq.analysis.root import Submission
        assert isinstance(submission, Submission)

        logging.info(f"submission {submission.root.description} matched {len(tuning_matches)} tuning rules")
        for tuning_match in tuning_matches:
            logging.info(f"submission {submission.root.description} matched {tuning_match['rule']} "
                          f"target {tuning_match['target']} "
                          f"strings {tuning_match['strings']}")
            logging.info(f"tuning_match: {tuning_match}")