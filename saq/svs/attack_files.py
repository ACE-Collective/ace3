"""Where the vendored ATT&CK extracts are (docs/SVS_COVERAGE.md, *The ATT&CK release*).

Kept free of imports from saq, because the config schema validates svs.attack_release with it
while the configuration is still being loaded. The extracts ship with the code (etc/ is copied
into the image), so the path is relative to the code, not to any runtime setting.
"""

import re
from pathlib import Path

ATTACK_DIR = Path(__file__).resolve().parents[2] / "etc" / "attack"

# how a release is named: v20.0 is etc/attack/v20.0.json, built by bin/update-attack-catalog v20.0
RELEASE_RE = re.compile(r"^v\d+\.\d+$")


def release_path(release: str) -> Path:
    if not RELEASE_RE.match(release):
        raise ValueError(f"{release!r} is not an ATT&CK release name (for example v20.0)")
    return ATTACK_DIR / f"{release}.json"
