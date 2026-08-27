"""Exports the observables enabled for detection as yara rules.

One rule file per observable type is written into a dedicated subdirectory of the yara scanner's
signature directory, so the scanner picks them up with no configuration of its own.

Each detection becomes a yara string named ``$obsd_<id>``, where the id is the
``observable_detections`` row. FileTypeAnalyzer parses that id back out of a match to report which
detection fired -- see saq/modules/file_analysis/yara.py.

Settings come from the existing ``yara_export:`` and ``yara_export_string_modifiers:`` config blocks.

Note that ``export_minimum_length`` drops very short values, which for the ``ip`` observable type
means abbreviated IPv6 addresses like ``::1`` and ``fe80::`` are not exported. That is intended --
strings that short match everything and are worthless as yara content.
"""

from datetime import date
import io
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
        string_data = io.StringIO()

        yara_value = format_yara_string(entry.value)
        string_data.write(f'          $obsd_{entry.id} = "{yara_value}" {modifiers}\n')

        yara_json_value = format_yara_json_string(entry.value)
        if yara_value != yara_json_value:
            string_data.write(f'          $obsd_json_{entry.id} = "{yara_json_value}" {modifiers}\n')

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
