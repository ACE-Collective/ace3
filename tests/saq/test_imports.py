"""What `import saq` needs installed."""

import subprocess
import sys

import pytest

from saq.environment import get_base_dir

pytestmark = pytest.mark.unit


def test_saq_imports_without_yara_scanner():
    # the drift check (.github/workflows/check-model-drift.yml) installs only
    # installer/requirements-pinned.txt, and its alembic env imports saq; yara_scanner_v2 comes from
    # git in the image, so nothing on that path may import it. The API is held to the same rule.
    code = ("import sys\n"
            "sys.modules['yara_scanner'] = None\n"
            "import saq, aceapi_v2.application\n"
            "from saq.database.meta import Base\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr[-4000:]


def test_saq_does_not_import_the_api():
    # aceapi_v2 imports the analysis tree and saq.svs at module level, so saq importing aceapi_v2
    # back makes a cycle that breaks whichever side is imported first
    code = ("import sys\n"
            "import saq, saq.svs.association, saq.svs.attribution, saq.svs.maintenance\n"
            "api = sorted(name for name in sys.modules if name.split('.')[0] == 'aceapi_v2')\n"
            "assert not api, api\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr[-4000:]
