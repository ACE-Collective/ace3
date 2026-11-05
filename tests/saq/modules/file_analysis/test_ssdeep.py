import hashlib
import logging
import os
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_analysis_module_config
from saq.constants import DIRECTIVE_SANDBOX
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.ssdeep import SsdeepAnalysis
from saq.util.uuid import get_storage_dir

MODULE = "ssdeep"
# what the ssdeep binary prints for _known_sample_bytes(), and the score it gives _variant_of() against it
KNOWN_SAMPLE_HASH = "192:QR5v46+ftzkszIVlmW82ziEEHnwSzIzVM7/QPcY:QR521zAwQauq74PF"
VARIANT_SCORE = 99


def _analyze(root_analysis, path: Path):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module(MODULE, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


def _known_sample_bytes() -> bytes:
    return b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(256))


@pytest.fixture
def known_sample(tmp_path):
    """A known sample, and a hashes file holding its fuzzy hash."""
    sample = tmp_path / "known.sample"
    sample.write_bytes(_known_sample_bytes())
    hashes = tmp_path / "hashes.ssdeep"
    hashes.write_text(f'ssdeep,1.1--blocksize:hash:hash,filename\n{KNOWN_SAMPLE_HASH},"{sample}"\n')
    get_analysis_module_config(MODULE).ssdeep_hashes = str(hashes)
    return sample, hashes


def _variant_of(sample: Path, tmp_path: Path) -> Path:
    # a few bytes appended keep the fuzzy hash close to, but not the same as, the sample's
    variant = tmp_path / "variant.bin"
    variant.write_bytes(sample.read_bytes() + b"appended")
    return variant


@pytest.mark.integration
def test_similar_file_is_tagged_and_sent_to_the_sandbox(root_analysis, tmp_path, known_sample):
    sample, _ = known_sample
    # a score at the threshold counts
    get_analysis_module_config(MODULE).ssdeep_match_threshold = VARIANT_SCORE

    target = _analyze(root_analysis, _variant_of(sample, tmp_path))

    assert target.has_tag("ssdeep")
    assert target.has_directive(DIRECTIVE_SANDBOX)
    analysis = target.get_and_load_analysis(SsdeepAnalysis)
    assert analysis.details["matches"] == [{"file": str(sample), "score": VARIANT_SCORE}]
    assert analysis.generate_summary() == f"Ssdeep Analysis (1 matches {VARIANT_SCORE}% highest match)"


@pytest.mark.integration
def test_match_below_the_threshold_is_ignored(root_analysis, tmp_path, known_sample):
    sample, _ = known_sample
    get_analysis_module_config(MODULE).ssdeep_match_threshold = VARIANT_SCORE + 1

    target = _analyze(root_analysis, _variant_of(sample, tmp_path))

    assert not target.has_tag("ssdeep")
    assert target.get_analysis(SsdeepAnalysis) is False


@pytest.mark.integration
def test_bad_line_in_the_hashes_file_does_not_hide_the_good_ones(root_analysis, tmp_path, known_sample, caplog):
    sample, hashes = known_sample
    # ssdeep warns about the bad line on stderr and still matches against the others
    with hashes.open("a") as fp:
        fp.write("not a hash\n")

    with caplog.at_level(logging.WARNING):
        target = _analyze(root_analysis, _variant_of(sample, tmp_path))

    assert target.has_tag("ssdeep")
    assert len(target.get_and_load_analysis(SsdeepAnalysis).details["matches"]) == 1
    assert any(r.levelno == logging.WARNING and "Bad hash in line 3" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_unreadable_hashes_file_is_logged_as_an_error(root_analysis, tmp_path, known_sample, caplog):
    sample, hashes = known_sample
    hashes.write_text("garbage\n")
    variant = _variant_of(sample, tmp_path)

    with caplog.at_level(logging.ERROR):
        target = _analyze(root_analysis, variant)

    assert target.get_analysis(SsdeepAnalysis) is False
    records = [r for r in caplog.records if getattr(r, "ssdeep_hashes", None) == str(hashes)]
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert "exit code 1" in records[0].getMessage()
    assert "Invalid file header" in records[0].getMessage()


@pytest.mark.integration
@pytest.mark.parametrize("size", [1023, 4097])
def test_files_outside_the_size_limits_are_skipped(root_analysis, tmp_path, known_sample, caplog, size):
    _, hashes = known_sample
    get_analysis_module_config(MODULE).maximum_size = 4096
    # an unreadable hashes file would fail any file that reached ssdeep
    hashes.write_text("garbage\n")
    path = tmp_path / "sized.bin"
    path.write_bytes(os.urandom(size))

    target = _analyze(root_analysis, path)

    assert target.get_analysis(SsdeepAnalysis) is False
    assert "ssdeep failed" not in caplog.text
