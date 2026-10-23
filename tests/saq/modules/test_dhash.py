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
from saq.modules.dhash import DHashImageAnalysis, _image_hash
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


def _noise_image(mode: str, bands: int, seed: int) -> Image.Image:
    rng = random.Random(seed)
    image = Image.new(mode, (97, 61))
    image.putdata([
        tuple(rng.randint(0, 255) for _ in range(bands)) if bands > 1 else rng.randint(0, 255)
        for _ in range(97 * 61)])
    return image


@pytest.mark.unit
@pytest.mark.parametrize("name, make, expected", [
    ("L", lambda: _noise_image("L", 1, 1), 0x1936ab35975b91587726233a54b6b4fa7d0b9b57a9753b4dd8e5b142b896ced8f1866a7dce0711f9fd8fe648093dbde0642892978c23725849cdf74b21264cc9),
    ("RGB", lambda: _noise_image("RGB", 3, 2), 0xccb962b63135c993889d364cc6195573c9b59ab4312d36ac0d68d23169976cd399e36efe2665d10289b737cc8a0974726d079ad4017b04ac69489ee1e334fc9e),
    # transparency is flattened onto white
    ("RGBA", lambda: _noise_image("RGBA", 4, 3), 0x6ac9324955725552d72c2732a393c569ce39d29c95285b2bb2b5ab12b2f152d1db9822d9fa6761d292096f682216b7c0cc7f07b8059f5a4a3080cb7a3ee79251),
    ("LA", lambda: _noise_image("LA", 2, 4), 0xa867a59db52d324d354c594dd4ad6c558cd0c654eacc358e313cb2649f4a15c940cecf10b53e02c32e0c791094abe3ec3d130674da810f8e713866c5c83e279a),
    ("P", lambda: _noise_image("RGB", 3, 5).convert("P"), 0x2a9494b36d8d6394db8655295929c3336a9a6ad243393b6d9da5a766416d4aaf6a1d90a218494ff1f204241e70e99f67af9f60800cb77f58f9a1043287718b27),
])
def test_image_hash_matches_the_dhash_package(tmp_path, name, make, expected):
    # the expected values are dhash.dhash_int(image, size=16) from dhash 1.4, which this replaced
    path = tmp_path / f"{name}.png"
    make().save(path)
    assert _image_hash(str(path)) == expected
