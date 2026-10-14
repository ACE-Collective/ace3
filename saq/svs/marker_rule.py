"""The marker rule (docs/SVS.md, Part 3, *Where the SVS router looks*): a built-in `no_alert` YARA
rule that finds run markers inside file contents, so a marker in a dropped script or document is
recorded in the file's YaraScanResults like any other match.

Scanning happens in the yara service, which compiles only what is under service_yara.signature_dir,
so ACE writes the rule there as its own namespace, the same way observable export writes
observable_export/ (FR-25). Two properties of the scanner shape how:

    * subdirectories of signature_dir are listed once, when a scanner is built. The yara service
      writes the rule before it starts its server and the module's fallback scanner before it
      builds one, so both load the namespace and watch it.
    * a rule change is detected by mtime, so rewriting the same bytes recompiles every rule. The
      file is written only when its content differs from MARKER_RULE.
"""

import logging
import os
import tempfile

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.util.filesystem import abs_path

MARKER_RULE_DIR = "svs_marker"
MARKER_RULE_FILE = "svs_marker.yar"
MARKER_RULE_NAME = "SVS_Marker"

# the same matches as saq.svs.markers.MARKER_REGEX. yara has no lookbehind, so the boundary
# characters are matched rather than asserted: a match's data can carry one of them on each side,
# and NULs when the text is UTF-16 (wide). saq.svs.markers.find_markers_in_match reads it back
MARKER_RULE = f"""\
rule {MARKER_RULE_NAME}
{{
    meta:
        description = "An SVS test run marker (docs/SVS_RUNS.md). Written by ACE; do not edit."
        modifiers = "no_alert"
    strings:
        $marker = /(^|[^a-z0-9])svs-[a-z2-7]{{26}}([^a-z0-9]|$)/ nocase ascii wide
    condition:
        $marker
}}
"""


def marker_rule_path(signature_dir: str | None = None) -> str:
    """Where the marker rule is written: <signature_dir>/svs_marker/svs_marker.yar. signature_dir
    defaults to service_yara.signature_dir."""
    if signature_dir is None:
        signature_dir = abs_path(get_service_config(SERVICE_YARA_SCANNER).signature_dir)

    return os.path.join(signature_dir, MARKER_RULE_DIR, MARKER_RULE_FILE)


def install_marker_rule(signature_dir: str | None = None) -> bool:
    """Writes the marker rule into signature_dir unless it is already there unchanged. Returns True
    when the file was written. Never raises: this runs as the yara service starts, and a scanner
    without the marker rule is better than no scanner."""
    path = marker_rule_path(signature_dir)
    try:
        try:
            with open(path, "r") as fp:
                if fp.read() == MARKER_RULE:
                    return False
        except FileNotFoundError:
            pass

        rule_dir = os.path.dirname(path)
        os.makedirs(rule_dir, exist_ok=True)

        # a uniquely named temp file that the scanner ignores (it reads only .yar and .yara),
        # renamed into place, so a scanner never compiles half a file. several processes may get
        # here at once; each writes the same content
        fd, temp_path = tempfile.mkstemp(dir=rule_dir, prefix=f".{MARKER_RULE_FILE}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fp:
                fp.write(MARKER_RULE)

            os.chmod(temp_path, 0o644)
            os.replace(temp_path, path)
        except BaseException:
            try:
                os.remove(temp_path)
            except OSError:
                pass

            raise

    except OSError as e:
        logging.error("unable to write the svs marker rule to %s: %s", path, e)
        return False

    logging.info("wrote the svs marker rule to %s", path)
    return True
