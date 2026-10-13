"""What `import saq` needs installed."""

import subprocess
import sys

import pytest

from saq.environment import get_base_dir

pytestmark = pytest.mark.unit


def test_saq_imports_without_yara_scanner():
    # the drift check (.github/workflows/check-model-drift.yml) installs only
    # installer/requirements-pinned.txt, and its alembic env imports saq, which imports the API;
    # yara_scanner_v2 comes from git in the image, so nothing on that path may import it
    code = ("import sys\n"
            "sys.modules['yara_scanner'] = None\n"
            "import saq, aceapi_v2.application\n"
            "from saq.database.meta import Base\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr[-4000:]
