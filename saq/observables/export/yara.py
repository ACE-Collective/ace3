"""Exports the observables enabled for detection as yara rules.

One rule file per observable type is written into a dedicated subdirectory of the yara scanner's
signature directory, so the scanner picks them up with no configuration of its own.

Each detection becomes a yara string named ``$obsd_<id>``, where the id is the
``observable_detections`` row. FileTypeAnalyzer parses that id back out of a match to report which
detection fired -- see saq/modules/file_analysis/yara.py.

Settings come from the existing ``yara_export:`` and ``yara_export_string_modifiers:`` config blocks.
Types listed in ``yara_export_string_boundaries:`` get a regex string instead of a text string, one
that only matches the value as a whole token (see ``format_bounded_yara_regex``).

Note that ``export_minimum_length`` drops very short values, which for the ``ip`` observable type
means abbreviated IPv6 addresses like ``::1`` and ``fe80::`` are not exported. That is intended --
strings that short match everything and are worthless as yara content.
"""

from datetime import date
import io
import json
import logging
import os
import re

from saq.configuration import get_config
from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.observables.export.base import (
    ExportEntry,
    ObservableExport,
    ObservableExportList,
    select_detections,
)
from saq.util.filesystem import abs_path, create_directory

# where the generated rules go, relative to service_yara.signature_dir. The yara scanner loads rules
# from each subdirectory of the signature dir, so this needs no scanner-side configuration.
OBSERVABLE_EXPORT_DIR = "observable_export"

DEFAULT_TEMPLATE = "default.template"
RULE_FILE_EXTENSION = ".yar"

# placeholders a template may use
TEMPLATE_RULE_NAME = "TEMPLATE_RULE_NAME"
TEMPLATE_TAGS = "TEMPLATE_TAGS"
TEMPLATE_DATE_STRING = "TEMPLATE_DATE_STRING"
TEMPLATE_STRINGS = "TEMPLATE_STRINGS"


def format_yara_string(value: str) -> str:
    """Escapes an observable value for use as a yara text string."""
    return value.replace('\\', '\\\\').replace('"', '\\"').replace("\n", "").replace("\r", "")


def format_yara_json_string(value: str) -> str:
    """Escapes an observable value as it would appear inside a JSON document.

    JSON escapes the backslashes itself, so a value embedded in JSON carries twice as many as the
    raw form. Exporting both means the rule hits in JSON files as well as plain content.
    """
    return value.replace('\\', '\\\\\\\\').replace('"', '\\"').replace("\n", "").replace("\r", "")


# bumped whenever the generated strings change shape, so the next export rewrites every rule file
# even though the detections themselves did not change (see fingerprint_salt)
YARA_EXPORT_FORMAT_VERSION = "2"

# characters that are special inside a yara /regex/ (the slash ends the regex)
YARA_REGEX_SPECIAL = frozenset('\\/^$.|?*+()[]{}')

# A boundary family: the characters that make up a "word" on each side. A bounded value may not have a
# word character directly before or after it. dot_aware: a "." after the value only counts as a boundary
# when no word character follows it, so evil.com.au is rejected but "block evil.com." at the end of a
# sentence still hits. The class strings are valid in Python regexes too (get_string_boundary relies on it).
BOUNDARY_FAMILIES = {
    "hostname": {"left": r"a-zA-Z0-9_\-", "right": r"a-zA-Z0-9_\-", "dot_aware": True},
    # "." and "+" are legal in the local part, so neither may precede the address
    "email_address": {"left": r"a-zA-Z0-9_\-.+", "right": r"a-zA-Z0-9_\-", "dot_aware": True},
    # 1.2.3.4 must not sit inside 5.1.2.3.4, 11.2.3.4, 1.2.3.45 or 1.2.3.4.5
    "ipv4": {"left": r"0-9.", "right": r"0-9", "dot_aware": True},
    "ipv6": {"left": r"0-9a-fA-F:", "right": r"0-9a-fA-F:", "dot_aware": False},
    "hex": {"left": r"a-fA-F0-9", "right": r"a-fA-F0-9", "dot_aware": False},
}

# libyara (4.5) stops matching a regex string once the match is about 1KB long -- 1023 characters
# ascii, 511 wide -- while a text string of any length still matches. A value longer than this keeps
# its text string, so a long detection can never silently stop firing.
MAX_BOUNDED_VALUE_LENGTH = 500


def format_yara_regex(value: str) -> str:
    """Escapes an observable value for use inside a yara /regex/."""
    value = value.replace("\n", "").replace("\r", "")
    return "".join("\\" + c if c in YARA_REGEX_SPECIAL else c for c in value)


def format_bounded_yara_regex(value: str, family: str) -> str:
    """The value as a yara regex that only matches when it is not part of a longer token.

    `value` is the literal text to find (already in its raw or JSON-escaped form). A side only gets a
    boundary when the value's edge character is a word character of the family, so a partial url
    ending in "/" or "=" still matches whatever follows it.
    """
    spec = BOUNDARY_FAMILIES[family]
    core = format_yara_regex(value)

    left = ""
    if value and re.fullmatch(f"[{spec['left']}]", value[0]):
        left = f"(^|[^{spec['left']}])"

    right = ""
    if value and re.fullmatch(f"[{spec['right']}]", value[-1]):
        if spec["dot_aware"]:
            right = f"([^{spec['right']}.]|\\.[^{spec['right']}]|\\.?$)"
        else:
            right = f"([^{spec['right']}]|$)"

    return f"/{left}{core}{right}/"


class YaraObservableExport(ObservableExport):

    @property
    def export_dir(self) -> str:
        """The directory the generated rule files are written to."""
        return os.path.join(
            abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir), OBSERVABLE_EXPORT_DIR)

    @property
    def template_dir(self) -> str:
        """The directory holding the rule templates (relative to SAQ_HOME unless absolute)."""
        return abs_path(get_config().yara_export.export_template_dir)

    def get_string_modifiers(self, observable_type: str) -> str:
        """The yara string modifiers to apply to values of the given observable type.

        Types without an explicit mapping use the `default` entry.
        """
        modifiers = get_config().yara_export_string_modifiers or {}
        return modifiers.get(observable_type.lower(), modifiers.get("default", ""))

    def get_string_boundary(self, observable_type: str, value: str) -> str | None:
        """The boundary family for a value of this type, or None to keep a plain text string."""
        boundaries = get_config().yara_export_string_boundaries or {}
        family = boundaries.get(observable_type.lower())
        if family == "ip":
            family = "ipv6" if ":" in value else "ipv4"

        if family is not None and family not in BOUNDARY_FAMILIES:
            logging.error(f"unknown yara export boundary {family} for {observable_type} - using a text string")
            return None

        return family

    def fingerprint_salt(self) -> str:
        # the generated strings depend on the format and on both string config blocks, not only on
        # the detections, so a change to any of them has to republish
        return YARA_EXPORT_FORMAT_VERSION + json.dumps(
            [get_config().yara_export_string_boundaries, get_config().yara_export_string_modifiers],
            sort_keys=True)

    def build_export_list(self, detections: dict[str, list[dict]]) -> ObservableExportList:
        """The detections of a configured type that are long enough to be worth a yara string.
        """
        export_list = get_config().yara_export.export_list
        minimum_length = get_config().yara_export.export_minimum_length

        entries = []
        for observable_type, detection in select_detections(detections, export_list):
            if len(detection["value"]) < minimum_length:
                continue

            entries.append(
                ExportEntry(id=detection["id"], type=observable_type, value=detection["value"]))

        return ObservableExportList(entries)

    def publish(self, export_list: ObservableExportList, force: bool = False) -> None:
        # accepted for the interface: this target rewrites everything on every publish,
        # so there is nothing for force to skip past
        import yara
        yara.set_config(max_strings_per_rule=int(get_config().yara_export.max_strings_per_rule))

        create_directory(self.export_dir)

        exported_types = []
        for observable_type, entries in export_list.entries_by_type().items():
            if self._export_type(observable_type, entries):
                exported_types.append(observable_type)

        self._prune(exported_types)

    def _export_type(self, observable_type: str, entries: list[ExportEntry]) -> bool:
        """Writes the rule file for one observable type. Returns False if nothing was written."""
        import yara

        template = self._load_template(observable_type)
        if template is None:
            return False

        modifiers = self.get_string_modifiers(observable_type)

        rule_data = io.StringIO()
        count = 0
        skip_count = 0
        for entry in entries:
            string_data = self._format_strings(entry, modifiers)

            # compile each string on its own so one bad value doesn't take out the whole type
            try:
                yara.compile(source=template.replace(TEMPLATE_STRINGS, string_data))
            except Exception as e:
                logging.error(f"observable type {observable_type} id {entry.id} "
                              f"value {entry.value} invalid for yara: {e}")
                skip_count += 1
                continue

            count += 1
            rule_data.write(string_data)

        if count == 0:
            logging.info(f"no observables of type {observable_type} available for export")
            return False

        rule = template.replace(TEMPLATE_STRINGS, rule_data.getvalue())
        try:
            yara.compile(source=rule)
        except Exception as e:
            logging.error(f"unable to compile rules for {observable_type}: {e}")
            return False

        output_file = os.path.join(self.export_dir, f"{observable_type}{RULE_FILE_EXTENSION}")
        if os.path.exists(output_file):
            with open(output_file, "r") as fp:
                if fp.read() == rule:
                    logging.debug(f"no changes detected for {observable_type}")
                    # unchanged, but still an exported type -- it must not be pruned
                    return True

        with open(output_file, "w") as fp:
            fp.write(rule)

        logging.info(f"exported {count} skipped {skip_count} observables of type "
                     f"{observable_type} to {output_file}")
        return True

    def _format_strings(self, entry: ExportEntry, modifiers: str) -> str:
        """The yara strings for one detection: the raw value, plus its JSON form if that differs."""
        family = self.get_string_boundary(entry.type, entry.value)

        raw = entry.value.replace("\n", "").replace("\r", "")
        json_form = raw.replace("\\", "\\\\").replace('"', '\\"')
        if family is not None and len(json_form) > MAX_BOUNDED_VALUE_LENGTH:
            logging.debug(f"observable type {entry.type} id {entry.id} is too long for a bounded "
                          f"yara string - using a text string")
            family = None

        string_data = io.StringIO()

        if family is None:
            yara_value = format_yara_string(entry.value)
            string_data.write(f'          $obsd_{entry.id} = "{yara_value}" {modifiers}\n')

            yara_json_value = format_yara_json_string(entry.value)
            if yara_value != yara_json_value:
                string_data.write(f'          $obsd_json_{entry.id} = "{yara_json_value}" {modifiers}\n')

            return string_data.getvalue()

        # the regex consumes the boundary character, so fullword would test the character beyond it
        # and reject a plain "a evil.com"
        modifiers = " ".join(modifier for modifier in modifiers.split() if modifier != "fullword")

        string_data.write(f'          $obsd_{entry.id} = {format_bounded_yara_regex(raw, family)} {modifiers}\n')
        if json_form != raw:
            string_data.write(
                f'          $obsd_json_{entry.id} = {format_bounded_yara_regex(json_form, family)} {modifiers}\n')

        return string_data.getvalue()

    def _load_template(self, observable_type: str) -> str | None:
        """The rule template for the given type, with everything but TEMPLATE_STRINGS filled in.

        Falls back to the default template when the type has none of its own. Returns None if no
        template could be read at all, so one missing file skips a type instead of aborting the run.
        """
        template_path = os.path.join(self.template_dir, f"{observable_type}.template")
        if not os.path.exists(template_path):
            template_path = os.path.join(self.template_dir, DEFAULT_TEMPLATE)

        try:
            with open(template_path, "r") as fp:
                template = fp.read()
        except Exception as e:
            logging.error(f"unable to read yara export template {template_path} "
                          f"for {observable_type}: {e}")
            return None

        logging.debug(f"using template {template_path} for {observable_type}")

        rule_name = re.sub(r'[^a-zA-Z0-9_]', '', observable_type)
        template = template.replace(TEMPLATE_RULE_NAME, rule_name)
        template = template.replace(TEMPLATE_TAGS, rule_name)
        template = template.replace(TEMPLATE_DATE_STRING, date.today().strftime("%m/%d/%Y"))
        return template

    def _prune(self, exported_types: list[str]) -> None:
        """Removes rule files for types that no longer have anything to export.

        Without this a detection an analyst disabled would keep firing until someone noticed the
        stale file.
        """
        try:
            existing = os.listdir(self.export_dir)
        except Exception as e:
            logging.error(f"unable to list {self.export_dir}: {e}")
            return

        for file_name in existing:
            if not file_name.endswith(RULE_FILE_EXTENSION):
                continue

            if file_name[:-len(RULE_FILE_EXTENSION)] in exported_types:
                continue

            target = os.path.join(self.export_dir, file_name)
            try:
                os.remove(target)
                logging.info(f"removed stale observable export rule file {target}")
            except Exception as e:
                logging.error(f"unable to remove {target}: {e}")
