from datetime import datetime
import gc
import json
import logging
import os
import re
import shutil
import socket
from subprocess import PIPE, Popen
from typing import override

import distorm3
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import AnalysisPresenter, register_analysis_presenter
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER, AnalysisExecutionResult, DIRECTIVE_NO_SCAN, DIRECTIVE_SANDBOX, F_FILE, F_INDICATOR, F_SIGNATURE_ID, F_YARA_RULE, F_YARA_STRING, create_yara_string
from saq.database import Observable as db_Observable, ObservableDetection as db_ObservableDetection
from saq.database.pool import get_db
from saq.environment import get_base_dir, get_data_dir
from saq.error.reporting import report_exception
from saq.json_encoding import _JSONEncoder
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.disassembly import disassemble
from saq.observables.file import FileObservable
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN, YARA_RULE_MATCH
from saq.util.filesystem import abs_path
from saq.yara_scanning_service import get_validated_git_repo_dirs

import yara
import yara_scanner

from saq.util.strings import format_item_list_for_summary


# meta values returned by yara-python can be bool, int, or str depending on how the analyst
# wrote them in the rule (e.g. `enabled = false` vs `enabled = "false"`)
_FALSE_META_VALUES = {"false", "no", "0", "off", "disabled"}


def _rule_enabled(match_result: dict) -> bool:
    """Returns False only if the rule's `enabled` meta is set to a falsy value. Defaults to True."""
    meta = match_result.get("meta") or {}
    if "enabled" not in meta:
        return True

    value = meta["enabled"]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() not in _FALSE_META_VALUES


def _rule_queue(match_result: dict) -> str | None:
    """Returns the non-empty `queue` meta value for a rule, or None if not specified."""
    queue = (match_result.get("meta") or {}).get("queue")
    if queue is None:
        return None
    queue = str(queue).strip()
    return queue or None


def _yara_detection_signature(match_result: dict) -> tuple[str, str]:
    """Returns (signature_uuid, signature_version) for a yara match detection.

    signature_uuid is the rule's `uuid` meta; warn-but-detect: a rule with no
    uuid still produces a detection, attributed to the built-in YARA_RULE_MATCH
    fallback signature. signature_version is the rule repo's commit hash (the
    `commit` key resolved by the yara_scanner library) or SIGNATURE_VERSION_UNKNOWN
    when the rule did not come from a git repo."""
    rule_uuid = (match_result.get("meta") or {}).get("uuid")
    if not rule_uuid:
        logging.warning("yara rule %s has no uuid meta - using built-in fallback signature", match_result.get("rule"))
        rule_uuid = YARA_RULE_MATCH.uuid
    return rule_uuid, match_result.get("commit") or SIGNATURE_VERSION_UNKNOWN


def _parse_yara_string_key_id(string_key: str) -> int | None:
    """Extracts the trailing row id from a generated yara string key.

    Handles both `$obsd_12` and `$obsd_json_12` (and their legacy `$obs_` equivalents). Returns None
    if the key does not end in an integer."""
    try:
        return int(string_key.rsplit('_', 1)[1])
    except (IndexError, ValueError):
        return None


class YaraScanResults_v3_4(Analysis):
    """What yara rules match this file?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "scan_results": []
        }

    @override
    @property
    def display_name(self) -> str:
        return "Yara Scan Results"

    @property
    def scan_results(self):
        return self.details["scan_results"]
    
    @scan_results.setter
    def scan_results(self, value):
        self.details["scan_results"] = value

    @property
    def jinja_template_path(self):
        return 'analysis/yara_analysis_v3_4.html'

    def generate_summary(self):
        if self.details is not None:
            return f"{self.display_name}: matched yara rules {format_item_list_for_summary([x['rule'] for x in self.scan_results])}"

        return None

#
# this module has two modes of operation
# the default mode is to use the Yara Scanner Server (see /opt/yara_scanner)
# if this is unavailable then local yara scanning will be used until the server is available again
#

class YaraScannerConfig(AnalysisModuleConfig):
    context_bytes: int = Field(..., description="Number of context bytes to capture around matches.")
    local_scanner_lifetime: int = Field(..., description="The amount of time (in minutes) a local scanner is used before it expires.")
    save_scan_failures: bool = Field(default=False, description="If this is True then files that fail scanning are saved for later analysis.")
    save_qa_scan_results: bool = Field(default=True, description="Returns True if we should save the results of yara rules in QA mode into self.qa_dir.")
    qa_dir: str = Field(..., description="Location of files and yara scan results for rules set to 'qa mode' (relative to saq.DATA_DIR).")

class YaraScanner_v3_4(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> type[AnalysisModuleConfig]:
        return YaraScannerConfig

    @property
    def context_bytes(self):
        return self.config.context_bytes

    @property
    def local_scanner_lifetime(self):
        """The amount of time (in minutes) a local scanner is used before it expires."""
        return self.config.local_scanner_lifetime

    @property
    def base_dir(self):
        """Base directory of the yara_scanner server."""
        return get_base_dir()

    @property
    def socket_dir(self):
        """Relative directory of the socket directory of the yara scanner server."""
        return os.path.join(get_data_dir(), get_service_config(SERVICE_YARA_SCANNER).socket_dir)

    @property
    def signature_dir(self):
        """Relative or absolute path to directory containing sub directories of yara rules."""
        return abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir)

    @property
    def git_repo_dirs(self):
        """The subdirectories of signature_dir that are part of a git repository, so
        rules loaded from them report their repo's commit as signature_version."""
        return get_validated_git_repo_dirs()

    @property
    def save_scan_failures(self):
        """If this is True then files that fail scanning are saved for later analysis."""
        return self.config.save_scan_failures

    @property
    def save_qa_scan_results(self):
        """Returns True if we should save the results of yara rules in QA mode into self.qa_dir."""
        return self.config.save_qa_scan_results

    @property
    def qa_dir(self):
        """Relative directory of the directory to store QA mode matches."""
        return os.path.join(get_data_dir(), self.config.qa_dir)

    @property
    def generated_analysis_type(self):
        return YaraScanResults_v3_4

    @property
    def valid_observable_types(self):
        return F_FILE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # this is where we place files that fail scanning
        self.scan_failure_dir = os.path.join(get_data_dir(), get_service_config(SERVICE_YARA_SCANNER).scan_failure_dir)
        if not os.path.exists(self.scan_failure_dir):
            try:
                os.makedirs(self.scan_failure_dir)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(self.scan_failure_dir, str(e)))
                report_exception()
                self.scan_failure_dir = None

        # in the case where the yara scanning server is unavailable a local scanner is used
        self.scanner = None

        # we use it for N minutes defined in the configuration
        self.scanner_start_time = None

    def initialize_local_scanner(self):
        logging.info("initializing local yara scanner")
        # initialize the scanner and compile the rules
        self.scanner = yara_scanner.YaraScanner(
            signature_dir=self.signature_dir, git_repo_dirs=self.git_repo_dirs)
        self.scanner.load_rules()
        self.scanner_start_time = datetime.now()
        #self.load_blacklist()

    #def load_blacklist(self):
        #if self.scanner is None:
            #return

        # load the list of blacklisted rules
        #if os.path.exists(self.blacklist_path):
            #try:
                #with open(self.blacklist_path, 'r') as fp:
                    #for line in fp:
                        #self.blacklisted_rules.append(line.strip())

                #logging.debug("loaded {0} blacklisted rules from {1}".format(len(self.blacklisted_rules), self.blacklist_path))
                #self.blacklist_mtime = os.path.getmtime(self.blacklist_path)

                #self.scanner.blacklist = self.blacklisted_rules

            #except Exception as e:
                #logging.error("unable to load blacklist file {0}: {1}".format(self.blacklist_path, str(e)))
                #report_exception()
        #else:
            #logging.warning("blacklist file {0} does not exist".format(self.blacklist_path))

    def auto_reload(self):
        # have the signatures changed?
        #logging.debug("checking for rule modifications")
        if self.scanner:
            if self.scanner.check_rules():
                logging.info("detected yara rules modification - reloading")
                self.scanner.load_rules()

        # did the blacklist change?
        #try:
            #if self.blacklist_mtime is None or self.blacklist_mtime != os.path.getmtime(self.blacklist_path):
                #self.load_blacklist()
        #except Exception as e:
            #logging.error("unable to check blacklist {0}: {1}".format(self.blacklist_path, str(e)))

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        # does this file exist as an attachment?
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {0}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # skip zero length files
        if _file.size == 0:
            return AnalysisExecutionResult.COMPLETED

        # skip files that we do not want to scan with yara
        if _file.has_directive(DIRECTIVE_NO_SCAN):
            logging.debug("skipping yara scan of file {} (directive {})".format(_file, DIRECTIVE_NO_SCAN))
            return AnalysisExecutionResult.COMPLETED

        meta_tags = _file.yara_meta_tags or None

        analysis = None

        # scan it with yara
        try:
            no_alert_rules = set() # the set of rules that matches that have the no_alert modifier
            matches_found = False # set to True if at least one rule matched

            try:
                # this path needs to be absolute for the yara scanner server to know where to find it
                _full_path = local_file_path
                if not os.path.isabs(local_file_path):
                    _full_path = os.path.join(os.getcwd(), local_file_path)
                result = yara_scanner.scan_file(_full_path, base_dir=self.base_dir, socket_dir=self.socket_dir, meta_tags=meta_tags)
                matches_found = bool(result)

                logging.debug("scanned file {} with yss (matches found: {})".format(_full_path, matches_found))

                # if that worked and we have a local scanner see if we still need it
                # we keep it around for some length of time
                # even when we get the yara scanner server back
                if self.scanner:
                    if (datetime.now() - self.scanner_start_time).total_seconds() * 60 >= self.local_scanner_lifetime:
                        # get rid of it
                        logging.info("releasing local yara scanner")
                        self.scanner = None
                        self.scanner_start_time = None
                        gc.collect()
                
            except (yara.TimeoutError, TimeoutError) as e:
                logging.warning("yara scanner server timed out scanning file %s: %s", _full_path, e)
                matches_found = False

            except socket.error as e:
                logging.warning("failed to connect to yara socket server: {}".format(e))
                if not self.scanner:
                    self.initialize_local_scanner()

                matches_found = self.scanner.scan(local_file_path, meta_tags=meta_tags)
                result = self.scanner.scan_results
                # we want to keep using it for now...
                self.scanner_start_time = datetime.now()

            #if self.scanner.scan(local_file_path):
            if matches_found:
                # drop matches from rules an analyst has disabled in place via `enabled = false`.
                # a file matching only disabled rules then behaves exactly like no match at all.
                result = [r for r in result if _rule_enabled(r)]
                if not result:
                    logging.debug("all yara matches for {} were from disabled rules".format(local_file_path))
                    return AnalysisExecutionResult.COMPLETED

                logging.info("got yara results for {}".format(local_file_path))
                analysis = self.create_analysis(_file)
                assert isinstance(analysis, YaraScanResults_v3_4)
                analysis.scan_results = result

                # yara rules can have a meta directive called "modifiers" that changes how the results are interpreted
                # the value is a list of modifiers accepted as listed
                # no_alert - this rule alone does not generate an alert
                # directive=VALUE - add the given directive to the file being scanned where VALUE is the directive to add
                # anything that matches a yara rule is considered suspect

                alertable = False # initially set to False until we hit at least one rule that does NOT have the no_alert modifier
                for match_result in analysis.scan_results:
                    if 'modifiers' in match_result['meta']:
                        modifier_no_alert = False
                        modifier_qa = False

                        modifiers = [x.strip() for x in match_result['meta']['modifiers'].split(',')]
                        logging.debug("yara rule {} has modifiers {}".format(match_result['rule'], ','.join(modifiers)))

                        for modifier in modifiers:
                            if modifier == 'qa':
                                modifier_qa = True
                                modifier_no_alert = True
                                no_alert_rules.add(match_result['rule'])

                                logging.info(f"yara rule {match_result['rule']} matched {_file} in QA mode")

                                if self.save_qa_scan_results:
                                    try:
                                        target_dir = os.path.join(self.qa_dir, match_result['rule'])
                                        os.makedirs(target_dir, exist_ok=True)
                                        target_file = os.path.join(target_dir, f"{_file}-{_file.sha256_hash}")
                                        if not os.path.exists(target_file):
                                            shutil.copy(local_file_path, target_file)
                                            with open(f'{target_file}.json', 'w') as fp:
                                                json.dump(match_result, fp, cls=_JSONEncoder)
                                            logging.info(f"saved file {target_file} for QA review")
                                    except Exception as e:
                                        logging.error(f"unable to save results for QA mode match: {e}")

                                continue

                            if modifier == 'no_alert':
                                modifier_no_alert = True
                                no_alert_rules.add(match_result['rule'])
                                continue

                        # if we're running a rule in QA mode then we don't want to apply any other directives
                        if not modifier_qa:
                            for modifier in modifiers:
                                if modifier.startswith('directive'):
                                    key, modifier_directive = modifier.split('=', 1)
                                    #if modifier_directive not in VALID_DIRECTIVES:
                                        #logging.warning("yara rule {} attempts to add invalid directive {}".format(match_result['rule'], modifier_directive))
                                    #else:
                                    logging.debug("assigned directive {} to {} by modifiers on yara rule {}".format(
                                                  modifier_directive, _file, match_result['rule']))
                                    _file.add_directive(modifier_directive)

                                    continue

                        # did at least one rule NOT have the no_alert modifier?
                        if not modifier_no_alert:
                            alertable = True
                    else:
                        # no modifiers at all?
                        alertable = True

                # if any rule matches (that does not have the no_alert modifier) then the whole thing becomes an alert
                if alertable:
                    #_file.add_tag('yara')

                    # Some file types get decomposed into other files (ie, PDFAnalyzer->PDFTextAnalyzer)
                    # When this is the case, the FileObservable's redirection property is set to reference the
                    # original, un-decomposed file. *That* is the file that should be sandboxed, not the decomposed file.
                    if _file.redirection:
                        _file.redirection.add_directive(DIRECTIVE_SANDBOX)
                    else:
                        _file.add_directive(DIRECTIVE_SANDBOX)

                else:
                    logging.debug("yara results for {} only include rules with no_alert modifiers".format(local_file_path))
            else:
                logging.debug("no yara results for {}".format(local_file_path))
                return AnalysisExecutionResult.COMPLETED
        except Exception as e:
            logging.warning("error scanning file {}: ({}) {}".format(local_file_path, type(e), e))
            report_exception()
            
            # we copy the files we cannot scan to a directory where we can debug it later
            if self.save_scan_failures and self.scan_failure_dir is not None:
                try:
                    dest_path = os.path.join(self.scan_failure_dir, os.path.basename(local_file_path))
                    while os.path.exists(dest_path):
                        dest_path = '{}_{}'.format(dest_path, datetime.now().strftime('%Y%m%d%H%M%S-%f'))
#
                    shutil.copy(local_file_path, dest_path)
                    logging.debug("copied {} to {}".format(local_file_path, dest_path))
                except Exception as e:
                    logging.error("unable to copy {} to {}: {}".format(local_file_path, self.scan_failure_dir, e))
                    report_exception()
            
            return AnalysisExecutionResult.COMPLETED

        if not analysis:
            return AnalysisExecutionResult.COMPLETED

        emitted_signature_ids: set[str] = set()
        for yara_result in analysis.scan_results:
            # Add the matching Yara rule as an observable
            rule_observable = analysis.add_observable_by_spec(F_YARA_RULE, yara_result['rule'])
            if rule_observable is None:
                continue

            # Emit a signature_id observable carrying the rule's uuid meta field,
            # so analysts can filter alerts in the GUI by rule uuid. Most rules
            # have one; the few that don't are skipped silently.
            rule_uuid = (yara_result.get('meta') or {}).get('uuid')
            if rule_uuid and rule_uuid not in emitted_signature_ids:
                analysis.add_observable_by_spec(F_SIGNATURE_ID, rule_uuid)
                emitted_signature_ids.add(rule_uuid)

            # If the thing that matched was a for_detection observable, then add that observable to the alert as well
            if 'strings' in yara_result:
                # add each string in each rule as a yara_string observable
                for (position, string_name, string_value) in yara_result["strings"]:
                    yara_string_observable = analysis.add_observable_by_spec(F_YARA_STRING, create_yara_string(rule_observable.value, string_name))

                try:
                    # yara_result is a dictionary that should have a "strings" key that looks like:
                    # 'strings': [(50, '$obsd_1', b'blah')]
                    string_keys = set([s[1] for s in yara_result['strings']])
                except:
                    string_keys = []

                # Parse the row id out of each string key and add the corresponding type+value to
                # this analysis.
                #
                # $obsd_<id> is an observable_detections row, which is what the export emits now.
                # $obs_<id> is an observables row -- the format used before detections moved to
                # their own table. Rules generated before that change are still on disk, so both are
                # resolved for one release. The legacy branch can be deleted after every deployed
                # rule set has been re-exported.
                for string_key in string_keys:
                    if string_key.startswith('$obsd_'):
                        model, row_id = db_ObservableDetection, _parse_yara_string_key_id(string_key)
                    elif string_key.startswith('$obs_'):
                        model, row_id = db_Observable, _parse_yara_string_key_id(string_key)
                    else:
                        continue

                    if not row_id:
                        continue

                    row = get_db().query(model).get(row_id)
                    if not row:
                        continue

                    logging.debug(f'found {model.__tablename__} row {row_id} in database matching the yara hit')
                    # observables.value is a BLOB, observable_detections.value is text
                    value = row.value.decode() if isinstance(row.value, bytes) else row.value
                    try:
                        obs = analysis.add_observable_by_spec(row.type, value)
                        # Add the Yara rule name as a tag to the observable
                        if obs:
                            obs.add_tag(yara_result['rule'])
                    except Exception as e:
                        logging.error(f"unable to add observable value {value}: {e}")


            # if this yara rule did not have the no_alert modifier then it becomes a detection point.
            if yara_result['rule'] not in no_alert_rules:
                detection_signature_uuid, detection_signature_version = _yara_detection_signature(yara_result)
                rule_observable.add_detection_point(
                    "{} matched yara rule {}".format(_file, yara_result['rule']),
                    queue=_rule_queue(yara_result),
                    signature_uuid=detection_signature_uuid,
                    signature_version=detection_signature_version)

            # yara rules can get generated automatically from SIP data using the ace export-sip-yara-rules output_dir command
            # so if the name of the rule starts with SIP_ then we also want to add indicators as observables
            if yara_result['rule'].startswith('SIP_'):
                for string_match in yara_result['strings']:
                    position, string_id, value = string_match
                    # example: '0x45cf:$5537d11dbcb87f5c8053ae55: /webstat/image.php?id='
                    m = re.match(r'^\$sip_([0-9]+)$', string_id)
                    if m:
                        analysis.add_observable_by_spec(F_INDICATOR, 'sip:{}'.format(m.group(1)))



            yara_result['context'] = []
            for position, string_id, value in yara_result['strings']:
                # we want some context around what we matched
                start_byte = position - self.context_bytes
                if start_byte < 0:
                    start_byte = 0

                length = self.context_bytes + len(value) + self.context_bytes

                with open(local_file_path, 'rb') as fp:
                    try:
                        fp.seek(start_byte)
                        context_data = fp.read(length)
                    except Exception as e:
                        logging.error("unable to seek to position {} in {}: {}".format(start_byte, local_file_path, e))
                        report_exception()

                    p = Popen(['hexdump', '-C'], stdin=PIPE, stdout=PIPE)
                    p.stdin.write(context_data)
                    stdout, _ = p.communicate()
                    p.wait()
                    yara_result['context'].append([position, string_id, value, stdout])

                # build disassembly output if the rule specifies this
                if 'asm' in yara_result['tags']:
                    decoder = None
                    if string_id.endswith('x86'):
                        # 32-bit x86
                        decoder = distorm3.Decode32Bits
                    elif string_id.endswith('x64'):
                        decoder = distorm3.Decode64Bits
                        # 64-bit x86
                        pass
                    elif string_id.endswith('A32'):
                        # 32-bit ARM
                        pass
                    elif string_id.endswith('A64'):
                        #64-bit ARM
                        pass
                    if decoder:
                        try:
                            first_instr_offset = position - start_byte
                            # Add a fifth item to the context list of the last yara_result added. app/templates/analysis/yara_analysis* will render this appropriately
                            yara_result['context'][-1].append(disassemble(_full_path, position, first_instr_offset, len(value), context_data, decoder))
                        except Exception:
                            report_exception()
                            yara_result['context'][-1].append(disassemble('Failed to disassemble'))

            # did this rule have any tags?
            for tag in yara_result['tags']:
                #rule_observable.add_tag(tag)
                _file.add_tag(tag)
                # if the yara rule is whitelisted, we need to make sure the analysis is whitelisted in ACE
                if tag == "whitelisted":
                    _file.whitelist()

        return AnalysisExecutionResult.COMPLETED


class YaraScanResults_v3_4_Presenter(AnalysisPresenter):
    """Presenter for YaraScanResults_v3_4."""
    
    @property
    def template_path(self) -> str:
        return "analysis/yara_analysis_v3_4.html"


register_analysis_presenter(YaraScanResults_v3_4, YaraScanResults_v3_4_Presenter)