import json
import logging
import os
import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.presenter import create_analysis_presenter
from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import F_TEST
from saq.observables.file import FileObservable

@pytest.mark.unit
def test_add_file_observable_skips_a_refused_file(root_analysis, tmp_path):
    """A file the file manager refuses (here a link out of the files directory, as an archive can
    contain) is skipped, not raised, so the module adding it keeps going."""
    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("secret")
    os.makedirs(root_analysis.file_dir, exist_ok=True)
    link = os.path.join(root_analysis.file_dir, "secret.lnk")
    os.symlink(outside_file, link)

    assert root_analysis.add_file_observable(link) is None
    assert not [o for o in root_analysis.all_observables if o.type == "file"]
    assert not os.path.exists(root_analysis.hardcopy_dir) or not os.listdir(root_analysis.hardcopy_dir)

@pytest.mark.unit
def test_add_file_observable_raises_a_failure_that_is_not_a_refusal(root_analysis, tmp_path, monkeypatch, caplog):
    """Only a refusal skips the file: any other ValueError is logged and raised, not taken for one."""
    source = tmp_path / "payload.pdf"
    source.write_bytes(b"payload")

    def _fail(path):
        raise ValueError("unreadable")

    monkeypatch.setattr("saq.analysis.file_manager.local_file_manager.sha256_file", _fail)

    with pytest.raises(ValueError, match="unreadable"):
        root_analysis.add_file_observable(str(source))

    assert [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR] == [
        f"unable to add file observable {source}: unreadable (<class 'ValueError'>)"]

@pytest.mark.unit
def test_add_file_observable_with_a_name_no_filesystem_can_hold(root_analysis, tmp_path):
    """Half of a UTF-16 surrogate pair, which a name decoded from JSON can hold, has no bytes on any
    filesystem, so it is replaced and the file is stored."""
    source = tmp_path / "payload.pdf"
    source.write_bytes(b"payload")

    file_observable = root_analysis.add_file_observable(str(source), target_path=json.loads('"\\ud83d report.pdf"'))

    assert isinstance(file_observable, FileObservable)
    assert file_observable.file_path == "_ report.pdf"
    assert os.listdir(root_analysis.file_dir) == ["_ report.pdf"]

@pytest.mark.unit
def test_add_file_observable_with_an_undecodable_name(root_analysis, tmp_path, unlogged):
    """A file whose name is not UTF-8 (an archive member, as os.listdir returns it) is stored under
    that name, not dropped."""
    name = b"\xe9\xe9.pdf".decode("utf-8", "surrogateescape")
    source = tmp_path / name
    source.write_bytes(b"payload")

    file_observable = root_analysis.add_file_observable(str(source))

    assert isinstance(file_observable, FileObservable)
    assert file_observable.file_path == name
    assert os.listdir(os.fsencode(root_analysis.file_dir)) == [b"\xe9\xe9.pdf"]

    root_analysis.save()
    loaded = load_root(root_analysis.storage_dir)
    assert loaded.get_observable(file_observable.uuid).file_path == name

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
def test_load_removed_user_tag_analysis(caplog):
    # the user_tagger module was removed, but saved alerts still reference its analysis
    from saq.analysis.analysis import UnknownAnalysis, load_analysis_from_module_path

    caplog.set_level(logging.DEBUG)
    analysis = load_analysis_from_module_path("saq.modules.user:UserTagAnalysis")

    assert isinstance(analysis, UnknownAnalysis)
    assert not [r for r in caplog.records if r.levelno > logging.DEBUG]

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


class _ErrorAnalysis(Analysis):
    pass


@pytest.mark.unit
def test_error_is_saved_with_the_tree_and_read_without_the_details(root_analysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "test")
    analysis = observable.add_analysis(_ErrorAnalysis())
    analysis.details = {"found": "nothing"}
    analysis.error = "lookup timed out"
    root_analysis.save()

    loaded = load_root(root_analysis.storage_dir)
    loaded_analysis = loaded.get_observable(observable.uuid).get_analysis(_ErrorAnalysis)
    # the tree, the GUI and the engine read it without loading the analysis details
    assert loaded_analysis.error == "lookup timed out"


@pytest.mark.unit
def test_an_analysis_saved_before_errors_existed_has_no_error():
    analysis = Analysis()
    analysis.json = {"uuid": "1", "summary": "old", "completed": True, "delayed": False}

    assert analysis.error is None


@pytest.mark.unit
def test_a_failed_analysis_is_rendered_without_a_summary_or_observables():
    analysis = Analysis()
    assert not create_analysis_presenter(analysis).should_render

    analysis.error = "lookup timed out"
    assert create_analysis_presenter(analysis).should_render
