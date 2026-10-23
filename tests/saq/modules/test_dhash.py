"""The dhash image analyzer: images compared against the ones in the analyst data repo."""

import logging
import random

import pytest
from PIL import Image

from saq.analysis.root import load_root
from saq.constants import DIRECTIVE_DHASH
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_global_runtime_settings
from saq.modules.dhash import DHashImageAnalysis
from saq.signatures.builtin import DHASH_IMAGE_MATCH
from saq.util.uuid import get_storage_dir


def _gradient(path, reverse: bool = False):
    image = Image.new("L", (64, 64))
    image.putdata([(255 - x * 4 if reverse else x * 4) for _ in range(64) for x in range(64)])
    image.save(path, "PNG")


def _noise(path):
    rng = random.Random(1)
    image = Image.new("L", (64, 64))
    image.putdata([rng.randint(0, 255) for _ in range(64 * 64)])
    image.save(path, "PNG")


def _truncated(path):
    _noise(path)
    data = path.read_bytes()
    path.write_bytes(data[:len(data) // 2])


@pytest.fixture
def source_dir(tmp_path, monkeypatch):
    analyst_data_dir = tmp_path / "analyst_data"
    (analyst_data_dir / "dhash").mkdir(parents=True)
    monkeypatch.setattr(get_global_runtime_settings(), "analyst_data_dir", str(analyst_data_dir))
    return analyst_data_dir / "dhash"


def _source(source_dir, name: str, make, threshold: float | None):
    make(source_dir / name)
    if threshold is not None:
        (source_dir / f"{name}.score").write_text(str(threshold))


def _analyze(root_analysis, tmp_path, make):
    target = tmp_path / "target.png"
    make(target)
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_file_observable(str(target))
    observable.add_directive(DIRECTIVE_DHASH)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("dhash", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root = load_root(get_storage_dir(root_analysis.uuid))
    observable = root.get_observable(observable.uuid)
    return observable, observable.get_and_load_analysis(DHashImageAnalysis)


@pytest.mark.integration
def test_a_matching_image_is_a_detection(root_analysis, tmp_path, source_dir):
    _source(source_dir, "login_page.png", _gradient, 90)
    _source(source_dir, "other_brand.png", lambda path: _gradient(path, reverse=True), 90)
    # neither a png nor an image: skipped
    (source_dir / "notes.txt").write_text("not an image")
    (source_dir / "fake.png").write_text("not an image either")

    observable, analysis = _analyze(root_analysis, tmp_path, _gradient)

    scores = {score["image_file"]: score for score in analysis.scores}
    assert set(scores) == {"login_page.png", "other_brand.png"}
    assert scores["login_page.png"]["score"] == 100.0
    assert scores["other_brand.png"]["score"] < 90
    assert analysis.generate_summary().startswith("DHash Image Analysis: ")
    assert "login_page.png 100.00% of 90.00%" in analysis.generate_summary()

    [detection] = observable.detections
    assert detection.description == "matches login_page.png 100.00% (threshold 90.00%)"
    assert detection.signature_uuid == DHASH_IMAGE_MATCH.uuid


@pytest.mark.integration
def test_no_match_records_the_scores(root_analysis, tmp_path, source_dir):
    _source(source_dir, "login_page.png", _noise, 99)

    observable, analysis = _analyze(root_analysis, tmp_path, _gradient)

    assert [score["image_file"] for score in analysis.scores] == ["login_page.png"]
    assert not observable.detections


@pytest.mark.integration
def test_a_source_image_without_a_score_or_unreadable_is_skipped(root_analysis, tmp_path, source_dir, caplog):
    _source(source_dir, "a_no_score.png", _gradient, None)
    _source(source_dir, "b_truncated.png", _truncated, 90)
    _source(source_dir, "c_login_page.png", _gradient, 90)

    with caplog.at_level(logging.ERROR):
        observable, analysis = _analyze(root_analysis, tmp_path, _gradient)

    # the source images after the bad ones are still compared
    assert [score["image_file"] for score in analysis.scores] == ["c_login_page.png"]
    assert len(observable.detections) == 1
    [no_score] = [r for r in caplog.records if "unable to load score threshold" in r.getMessage()]
    [truncated] = [r for r in caplog.records if "unable to hash dhash source image" in r.getMessage()]
    assert no_score.exc_info is not None and truncated.exc_info is not None
    assert "b_truncated.png" in truncated.getMessage()


@pytest.mark.integration
def test_a_truncated_image_is_not_analyzed(root_analysis, tmp_path, source_dir, caplog):
    _source(source_dir, "login_page.png", _gradient, 90)

    with caplog.at_level(logging.INFO):
        observable, analysis = _analyze(root_analysis, tmp_path, _truncated)

    # the module ran and produced nothing
    assert analysis is False
    assert "unable to hash image" in caplog.text
    # handled, not a module crash
    assert "analysis module crash recorded" not in caplog.text


@pytest.mark.integration
@pytest.mark.parametrize("make", [
    lambda path: path.write_bytes(b""),
    lambda path: path.write_text("not an image"),
])
def test_files_that_are_not_images_are_not_analyzed(root_analysis, tmp_path, source_dir, make):
    _, analysis = _analyze(root_analysis, tmp_path, make)

    # the module ran and produced nothing
    assert analysis is False


@pytest.mark.integration
def test_no_source_directory(root_analysis, tmp_path, source_dir, caplog):
    source_dir.rmdir()

    _, analysis = _analyze(root_analysis, tmp_path, _gradient)

    # the module ran and produced nothing
    assert analysis is False
    assert "missing dhash source directory" in caplog.text


@pytest.mark.unit
def test_analysis_without_scores():
    analysis = DHashImageAnalysis()
    assert analysis.generate_summary() is None
    assert analysis.display_name == "DHash Image Analysis"
    analysis.details = None
    assert analysis.scores == []
