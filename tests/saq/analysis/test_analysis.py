import logging
import os
import pytest

from saq.configuration.config import get_config
from saq.observables.file import FileObservable

@pytest.mark.unit
def test_add_file_observable(root_analysis, tmpdir):
    # file must exist
    assert root_analysis.add_file_observable("does_not_exist") is None

    target_file = tmpdir / "test_file.txt"
    target_file.write_binary(b"test")
    target_file = str(target_file)

    file_observable = root_analysis.add_file_observable(target_file)
    assert isinstance(file_observable, FileObservable)
    assert file_observable.value == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert file_observable.sha256_hash == file_observable.value
    assert file_observable.full_path == os.path.join(root_analysis.file_dir, "test_file.txt")
    assert file_observable.file_path == "test_file.txt"
    # original file should still exist
    assert os.path.exists(target_file)
    # should only have a single hardcopy
    assert len(os.listdir(root_analysis.hardcopy_dir)) == 1

    # now test adding the exact same file under a different name
    target_file = tmpdir / "other_file.txt"
    target_file.write_binary(b"test")
    target_file = str(target_file)

    file_observable_copy = root_analysis.add_file_observable(target_file)
    # should not be the exact previous observable
    assert file_observable_copy is not file_observable
    # value should be the same
    assert file_observable_copy.value == file_observable.value
    # however, these are not considered the same by ACE because the metadata is different
    assert file_observable_copy != file_observable
    # paths should be different
    assert file_observable_copy.file_path != file_observable.file_path
    # and there should only be a single hard copy
    assert len(os.listdir(root_analysis.hardcopy_dir)) == 1
    # original file should still exist
    assert os.path.exists(target_file)
    # adding the exact same file should return the existing observable
    file_observable_duplicate = root_analysis.add_file_observable(target_file)
    assert file_observable_duplicate is file_observable_copy

    # now test adding a third file with request to move
    target_file = tmpdir / "move_me.txt"
    target_file.write_binary(b"test")
    target_file = str(target_file)

    file_observable_move = root_analysis.add_file_observable(target_file, move=True)
    # file should exist in new spot
    assert file_observable_move.exists
    # and should no longer exist in the old spot
    assert not os.path.exists(target_file)

    # now test adding a file to a different path
    target_file = tmpdir / "change_me.txt"
    target_file.write_binary(b"test")
    target_file = str(target_file)

    file_observable_rename = root_analysis.add_file_observable(target_file, target_path="relative/blah.txt")
    assert file_observable_rename.exists
    assert file_observable_rename.file_path == "relative/blah.txt"

    # now test adding a file already in the correct place
    target_file = os.path.join(root_analysis.file_dir, "already_exists.txt")
    with open(target_file, "wb") as fp:
        fp.write(b"different")

    file_observable_in_place = root_analysis.add_file_observable(target_file)
    assert file_observable_in_place.full_path == target_file
    assert os.path.exists(target_file)
    assert os.path.exists(os.path.join(root_analysis.hardcopy_dir, "9d6f965ac832e40a5df6c06afe983e3b449c07b843ff51ce76204de05c690d11")) # new hardcopy for new file

    # same thing but with move, which should not have a different result
    file_observable_in_place_move = root_analysis.add_file_observable(target_file, move=True)
    assert file_observable_in_place.full_path == target_file
    assert os.path.exists(target_file)


@pytest.mark.unit
def test_module_path_memoized_and_instance_validated():
    """module_path is computed once per (type, instance) and recomputed when
    instance is assigned after construction (deserialization path)."""
    from saq.analysis.analysis import Analysis
    from saq.analysis.module_path import MODULE_PATH

    class MemoTestAnalysis(Analysis):
        pass

    analysis = MemoTestAnalysis()
    base = analysis.module_path
    assert base == MODULE_PATH(analysis)
    # cached value returned (same object)
    assert analysis.module_path is base

    # assigning instance invalidates the memo
    analysis.instance = "second"
    assert analysis.module_path == f"{base}:second"

@pytest.mark.unit
def test_load_analysis_from_module_path_success():
    from saq.analysis.analysis import load_analysis_from_module_path
    from saq.modules.test import GenericTestAnalysis

    analysis = load_analysis_from_module_path("saq.modules.test:GenericTestAnalysis")
    assert isinstance(analysis, GenericTestAnalysis)

@pytest.mark.unit
def test_load_analysis_from_module_path_missing_logs_error(caplog):
    from saq.analysis.analysis import UnknownAnalysis, load_analysis_from_module_path

    caplog.set_level(logging.DEBUG)
    analysis = load_analysis_from_module_path("saq.modules.test:DoesNotExist")

    assert isinstance(analysis, UnknownAnalysis)
    assert analysis.module_path == "saq.modules.test:DoesNotExist"

    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "saq.modules.test:DoesNotExist" in errors[0].getMessage()

@pytest.mark.unit
def test_load_analysis_from_module_path_deprecated_logs_debug(caplog, monkeypatch):
    from saq.analysis.analysis import UnknownAnalysis, load_analysis_from_module_path

    monkeypatch.setattr(get_config(), "deprecated_modules", ["saq.modules.test:DoesNotExist"])

    caplog.set_level(logging.DEBUG)
    analysis = load_analysis_from_module_path("saq.modules.test:DoesNotExist")

    assert isinstance(analysis, UnknownAnalysis)
    assert analysis.module_path == "saq.modules.test:DoesNotExist"

    # a deprecated module is expected to be missing, so nothing above DEBUG is logged
    assert not [r for r in caplog.records if r.levelno > logging.DEBUG]
    debug_messages = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("saq.modules.test:DoesNotExist" in m for m in debug_messages)

@pytest.mark.unit
def test_is_deprecated_module_path(monkeypatch):
    from saq.analysis.analysis import is_deprecated_module_path

    monkeypatch.setattr(get_config(), "deprecated_modules", [])
    assert not is_deprecated_module_path("saq.modules.test:SomeAnalysis")

    monkeypatch.setattr(get_config(), "deprecated_modules", ["saq.modules.test:SomeAnalysis"])
    assert is_deprecated_module_path("saq.modules.test:SomeAnalysis")
    assert not is_deprecated_module_path("saq.modules.test:OtherAnalysis")

    # an entry without an :instance suffix covers every instance of that module
    assert is_deprecated_module_path("saq.modules.test:SomeAnalysis:instance1")

    # an entry with an :instance suffix covers only that instance
    monkeypatch.setattr(get_config(), "deprecated_modules", ["saq.modules.test:SomeAnalysis:instance1"])
    assert is_deprecated_module_path("saq.modules.test:SomeAnalysis:instance1")
    assert not is_deprecated_module_path("saq.modules.test:SomeAnalysis:instance2")
    assert not is_deprecated_module_path("saq.modules.test:SomeAnalysis")

    # a value that is not a module path at all is not deprecated
    assert not is_deprecated_module_path("not a module path")
