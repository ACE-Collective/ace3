"""shared fixtures for the standalone amc test suite.

these tests must run with only `amc/requirements.txt` installed; nothing here
imports from the surrounding ACE codebase.
"""

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

AMC_DIR = Path(__file__).resolve().parent.parent


def _load_script(name: str) -> types.ModuleType:
    """import an amc/*.py script as a module by absolute path."""
    path = AMC_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def amc_dir() -> Path:
    return AMC_DIR


@pytest.fixture()
def amc_mda_s3():
    return _load_script("amc_mda_s3")


@pytest.fixture()
def amc_s3_service():
    return _load_script("amc_s3_service")


@pytest.fixture()
def tmp_spool(tmp_path) -> Path:
    spool = tmp_path / "spool"
    spool.mkdir()
    return spool


@pytest.fixture()
def tiny_yara_rule(tmp_path) -> Path:
    """write a yara rule that allows on 'GOOD' and blocks on 'BAD'."""
    rule_path = tmp_path / "rules.yar"
    rule_path.write_text(
        """
rule allow_good : allow {
    strings:
        $g = "GOOD"
    condition:
        $g
}

rule block_bad : block {
    strings:
        $b = "BAD"
    condition:
        $b
}
""".strip()
    )
    return rule_path
