"""Guards for the shape of the shipped analysis mode configuration.

`etc/saq.default.yaml` once lost the `analysis_mode_cli:` section header, leaving that mode's
keys sitting as duplicate keys inside the `analysis_mode_analysis:` mapping. YAML keeps the
last value for a duplicate key, so the block silently registered as `cli` and the `analysis`
mode -- the engine's own `default_analysis_mode` -- ceased to exist. Work falling back to it
ran zero analysis modules and then tripped a ValueError in post-analysis.

Nothing in the suite resolved a shipped mode against config, which is why that survived for
months. These tests close that gap.
"""
import logging
import subprocess

import pytest
import yaml

from saq.configuration.config import get_config, get_engine_config
from saq.configuration.yaml_parser import YAMLConfig
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CLI

ANALYSIS_MODE_PREFIX = "analysis_mode_"


def _shipped_config() -> dict:
    """etc/saq.default.yaml on its own, before any overlay is merged over it."""
    return yaml.safe_load(open("etc/saq.default.yaml"))


def _shipped_analysis_mode_blocks() -> dict:
    """The analysis_mode_* blocks exactly as etc/saq.default.yaml declares them."""
    return {
        k: v for k, v in _shipped_config().items() if k.startswith(ANALYSIS_MODE_PREFIX)
    }


@pytest.mark.unit
def test_every_shipped_mode_block_key_matches_its_name():
    """The registry keys modes off the inner `name:`, not the section key, so a block whose
    two disagree registers a mode nobody can find under the name they wrote."""
    mismatched = {
        key: block.get("name")
        for key, block in _shipped_analysis_mode_blocks().items()
        if key[len(ANALYSIS_MODE_PREFIX):] != block.get("name")
    }
    assert not mismatched, (
        f"analysis mode blocks whose section key and name: disagree: {mismatched}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("analysis_mode", [ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CLI])
def test_shipped_mode_resolves(analysis_mode):
    """Both halves of the block that was mangled must resolve. `analysis` is the default for
    ace_api.submit(), `./ace submit` and the add_workload fallback; `cli` is what
    `./ace correlate` looks up unguarded."""
    config = get_config().get_analysis_mode_config(analysis_mode)
    assert config.name == analysis_mode


@pytest.mark.unit
def test_analysis_and_cli_are_distinct_modes():
    """They were one block for months. They are not the same mode -- cli deliberately does not
    clean up after itself."""
    analysis = get_config().get_analysis_mode_config(ANALYSIS_MODE_ANALYSIS)
    cli = get_config().get_analysis_mode_config(ANALYSIS_MODE_CLI)

    assert analysis is not cli
    assert analysis.cleanup is True
    assert cli.cleanup is False


@pytest.mark.unit
def test_shipped_default_analysis_mode_resolves():
    """This is the assertion that would have caught the original defect at its worst point.

    etc/saq.default.yaml ships `default_analysis_mode: analysis`, and every fallback lands
    there -- a submission with no mode, an unknown mode, a module declaring no modes. When the
    `analysis` block registered itself as `cli` instead, that default pointed at nothing.

    Checked against the shipped file rather than the merged runtime config on purpose: the
    unittest overlay pins default_analysis_mode to test_single, so the runtime check below
    cannot see a break in what we actually ship.
    """
    shipped = _shipped_config()
    default_analysis_mode = shipped["service_engine"]["default_analysis_mode"]
    defined = {block.get("name") for block in _shipped_analysis_mode_blocks().values()}
    assert default_analysis_mode in defined, (
        f"etc/saq.default.yaml ships default_analysis_mode {default_analysis_mode!r}, which is "
        f"not one of its defined modes {sorted(defined)}"
    )


@pytest.mark.unit
def test_runtime_default_analysis_mode_resolves():
    """Same check against whatever config this process actually merged."""
    default_analysis_mode = get_engine_config().default_analysis_mode
    defined = {mode.name for mode in get_config().analysis_modes}
    assert default_analysis_mode in defined, (
        f"default_analysis_mode {default_analysis_mode!r} is not a defined mode; "
        f"defined modes are {sorted(defined)}"
    )


@pytest.mark.unit
def test_no_duplicate_keys_in_any_tracked_config_yaml(caplog):
    """A duplicate key is how the original defect got in, and YAML will not complain about one
    on its own. Load every config file we ship and assert the loader stayed quiet."""
    tracked = subprocess.run(
        ["git", "ls-files", "etc/*.yaml", "etc/**/*.yaml"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    assert tracked, "expected to find tracked config yaml files"

    config = YAMLConfig()
    with caplog.at_level(logging.WARNING):
        for path in tracked:
            try:
                config._load_yaml_file(path)
            except ValueError:
                # not a mapping at the root (logging configs and friends) -- not our concern
                continue

    duplicates = [r.getMessage() for r in caplog.records if "duplicate key" in r.getMessage()]
    assert not duplicates, "duplicate keys in shipped config:\n" + "\n".join(duplicates)


@pytest.mark.unit
def test_engine_reports_an_unresolvable_default_analysis_mode(caplog):
    """The check that would have made the original defect loud instead of silent.

    A default_analysis_mode naming no defined mode is not fatal -- an existing deployment
    with this wrong should not fail to start on upgrade -- but it must not pass in silence,
    because every fallback path then produces an empty module list.
    """
    from saq.engine.engine_configuration import EngineConfiguration

    with caplog.at_level(logging.ERROR):
        EngineConfiguration(default_analysis_mode="no_such_mode")

    errors = [
        r.getMessage() for r in caplog.records
        if "default_analysis_mode" in r.getMessage() and "not a defined analysis mode" in r.getMessage()
    ]
    assert len(errors) == 1
    # the message has to be actionable: name the bad value and what was available
    assert "no_such_mode" in errors[0]
    assert ANALYSIS_MODE_ANALYSIS in errors[0]


@pytest.mark.unit
def test_engine_is_quiet_for_a_resolvable_default_analysis_mode(caplog):
    from saq.engine.engine_configuration import EngineConfiguration

    with caplog.at_level(logging.ERROR):
        EngineConfiguration(default_analysis_mode=ANALYSIS_MODE_ANALYSIS)

    assert not [
        r for r in caplog.records if "not a defined analysis mode" in r.getMessage()
    ]
