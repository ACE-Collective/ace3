import zipfile
from pathlib import Path

import pytest

from saq.analysis.root import load_root
from saq.constants import F_FILE
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.file_analysis.dmg import DMGAnalysis, DMGAnalyzer
from saq.sandbox.runner import SandboxResult
from saq.util.uuid import get_storage_dir


def _analyze(root_analysis, path: Path):
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("dmg_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    return root.get_observable(file_observable.uuid)


@pytest.fixture
def fake_dmg2img(monkeypatch):
    """dmg2img converts the image; here it writes an archive 7z can list in its place."""
    real_run = DMGAnalyzer.run_sandboxed_tool

    def _run(self, args, target, **kwargs):
        if args[0] == "dmg2img":
            [image] = kwargs["outputs"].values()
            with zipfile.ZipFile(image, "w") as zip_fp:
                zip_fp.writestr("Installer/", "")
                zip_fp.writestr("Installer/payload.app", b"payload" * 100)
                zip_fp.writestr("Installer/.DS_Store", b"ds")
            return SandboxResult(0, "dmg2img converted", "")
        return real_run(self, args, target, **kwargs)

    monkeypatch.setattr(DMGAnalyzer, "run_sandboxed_tool", _run)


@pytest.mark.integration
def test_dmg(root_analysis, tmp_path, fake_dmg2img):
    path = tmp_path / "Installer.dmg"
    path.write_bytes(b"koly" * 10)

    target = _analyze(root_analysis, path)

    analysis = target.get_and_load_analysis(DMGAnalysis)
    [image] = [o for o in analysis.observables if o.type == F_FILE]
    assert image.file_name == "Installer.img"
    assert analysis.details["image_file"] == image.full_path
    assert analysis.details["stdout"] == "dmg2img converted"
    assert image.has_tag("dmg") and image.has_tag("macos")
    assert image.redirection.uuid == target.uuid
    # files only, not directories
    listed = [line.split()[-1] for line in analysis.details["file_list"]]
    assert sorted(listed) == ["Installer/.DS_Store", "Installer/payload.app"]


@pytest.mark.integration
def test_dmg2img_fails(root_analysis, tmp_path):
    path = tmp_path / "broken.dmg"
    path.write_bytes(b"not really a disk image")

    target = _analyze(root_analysis, path)

    analysis = target.get_and_load_analysis(DMGAnalysis)
    assert analysis.details["image_file"] is None
    assert not [o for o in analysis.observables if o.type == F_FILE]
    assert analysis.error.startswith("dmg2img ")
    assert analysis.error.endswith(", without writing an image")


@pytest.mark.integration
def test_not_a_dmg(root_analysis, tmp_path):
    path = tmp_path / "Installer.zip"
    path.write_bytes(b"PK")

    assert not _analyze(root_analysis, path).get_and_load_analysis(DMGAnalysis)
