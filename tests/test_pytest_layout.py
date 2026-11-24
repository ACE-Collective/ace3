"""pytest runs an integration's tests where they are, with the suite's fixtures and hooks.

The run is in a scratch checkout with this checkout's pytest.ini and root conftest.py, a core
``tests`` package whose ``harness`` stands in for tests/harness.py, and two integrations: ``alpha``
directly under integrations/, whose tests/ is a package, and ``beta`` inside a repository that holds
several, whose tests/ is not. Each has a test module named like the other's and like a core one.
The checkout still has the link to alpha's tests that ``ace integration install`` used to make.
It is a separate pytest process, not this checkout's: the session lock refuses a second run of it.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

HARNESS = '''\
import os
import sys

import pytest


@pytest.fixture
def core_fixture():
    return "core"


def pytest_sessionstart(session):
    # what tests/harness.py does for every integration's src/
    sys.path.insert(0, os.path.join(str(session.config.rootpath), "integrations", "alpha", "src"))
'''

ALPHA_TEST = '''\
import pytest

import alpha_pkg
from tests.util import CORE_HELPER

from .helper import ALPHA_HELPER


@pytest.mark.unit
def test_alpha(core_fixture, alpha_fixture):
    assert (core_fixture, alpha_fixture, ALPHA_HELPER, CORE_HELPER, alpha_pkg.VALUE) == ("core", "alpha", 1, 2, 3)
'''

BETA_TEST = '''\
import pytest


@pytest.mark.unit
def test_beta(core_fixture):
    assert core_fixture == "core"
'''

CORE_TEST = '''\
import pytest


@pytest.mark.unit
def test_core(core_fixture):
    assert core_fixture == "core"
'''


def _write(root: Path, files: dict[str, str]):
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)


@pytest.mark.unit
@pytest.mark.parametrize("args, passed", [
    # the bare command, so that testpaths is what finds the integrations
    ([], 3),
    (["integrations"], 2),
])
def test_integration_tests_run_in_place_with_the_suites_fixtures(tmp_path, args, passed):
    _write(tmp_path, {
        "pytest.ini": (REPO / "pytest.ini").read_text(),
        "conftest.py": (REPO / "conftest.py").read_text(),
        "tests/__init__.py": "",
        "tests/harness.py": HARNESS,
        "tests/util.py": "CORE_HELPER = 2\n",
        "tests/test_same_name.py": CORE_TEST,
        "integrations/alpha/integration.md": "# alpha\n",
        "integrations/alpha/src/alpha_pkg/__init__.py": "VALUE = 3\n",
        "integrations/alpha/tests/__init__.py": "",
        "integrations/alpha/tests/conftest.py": "import pytest\n\n@pytest.fixture\ndef alpha_fixture():\n    return 'alpha'\n",
        "integrations/alpha/tests/helper.py": "ALPHA_HELPER = 1\n",
        "integrations/alpha/tests/test_same_name.py": ALPHA_TEST,
        "integrations/group-repo/beta/integration.md": "# beta\n",
        "integrations/group-repo/beta/tests/test_same_name.py": BETA_TEST,
    })
    (tmp_path / "tests" / "test_external_integration_alpha").symlink_to("../integrations/alpha/tests")
    # nothing of this run's: its checkout on the path would put the real tests package first
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith("PYTEST_")}

    result = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:randomly", *args], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120)

    assert result.returncode == 0, result.stdout + result.stderr
    assert f" {passed} passed" in result.stdout, result.stdout


@pytest.mark.unit
def test_a_left_over_integration_test_link_is_not_committable(tmp_path):
    (tmp_path / ".gitignore").write_text((REPO / ".gitignore").read_text())
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, timeout=30)

    result = subprocess.run(["git", "check-ignore", "-q", "tests/test_external_integration_alpha"], cwd=tmp_path,
                            timeout=30)

    assert result.returncode == 0


@pytest.mark.unit
@pytest.mark.parametrize("name", ["pytest.ini", "conftest.py"])
def test_the_image_has_the_root_files_that_load_the_suite(name):
    # COPY lines naming files that land directly in /opt/ace (the image runs the suite without the checkout)
    copied = set()
    for line in (REPO / "Dockerfile").read_text().splitlines():
        words = line.split()
        if words[:1] == ["COPY"] and words[-1] == "/opt/ace/":
            copied.update(word for word in words[1:-1] if not word.startswith("--"))

    assert name in copied
