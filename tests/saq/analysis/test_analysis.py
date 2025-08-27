import os
import pytest

from saq.analysis import (
    RootAnalysis,
)
from saq.analysis.analysis import SummaryDetail
from saq.constants import SUMMARY_DETAIL_FORMAT_PRE
from saq.observables.file import FileObservable

@pytest.mark.unit
def test_summary_detail_conversion():
    detail = SummaryDetail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE)
    d = detail.to_dict()
    assert SummaryDetail.HEADER in d
    assert SummaryDetail.CONTENT in d
    assert SummaryDetail.FORMAT in d
    new_detail = SummaryDetail.from_dict(d)
    assert new_detail == detail

@pytest.mark.integration
def test_add_summary_detail():
    root = RootAnalysis()
    root.add_summary_detail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE)
    assert root.summary_details[0].header == 'test_header'
    assert root.summary_details[0].content == 'test_content'
    assert root.summary_details[0].format == SUMMARY_DETAIL_FORMAT_PRE

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
