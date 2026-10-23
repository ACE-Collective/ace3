"""Tests for the `ace storage` commands."""

import os

import pytest

import saq.cli.commands.storage
from saq.cli.cli_main import get_cli_parser
from saq.storage.local import LocalStorage


@pytest.fixture
def storage(tmp_path, monkeypatch) -> LocalStorage:
    storage = LocalStorage(base_dir=tmp_path / "storage")
    monkeypatch.setattr(saq.cli.commands.storage, "get_storage_system", lambda: storage)
    return storage


def _ace(*argv) -> int:
    args = get_cli_parser().parse_args(["storage", *argv])
    return args.func(args)


@pytest.fixture
def local_file(tmp_path) -> str:
    path = tmp_path / "local.txt"
    path.write_text("contents")
    return str(path)


@pytest.mark.unit
def test_list_buckets(storage, local_file, capsys):
    assert _ace("list-buckets") == os.EX_OK
    assert "No buckets found." in capsys.readouterr().out

    storage.upload_file(local_file, "bucket-a", "file.txt")

    assert _ace("list-buckets") == os.EX_OK
    assert capsys.readouterr().out == "Available buckets:\n  bucket-a\n"


@pytest.mark.unit
def test_list_objects(storage, local_file, capsys):
    storage.upload_file(local_file, "bucket", "dir/file.txt")
    storage.upload_file(local_file, "bucket", "other.txt")

    assert _ace("list-objects", "bucket") == os.EX_OK
    output = capsys.readouterr().out
    assert output.startswith("Objects in bucket 'bucket'\n")
    assert "  dir/file.txt\n" in output
    assert "  other.txt\n" in output

    assert _ace("list-objects", "bucket", "-p", "dir") == os.EX_OK
    assert capsys.readouterr().out == "Objects in bucket 'bucket' with prefix 'dir'\n  dir/file.txt\n"

    assert _ace("list-objects", "bucket", "-p", "missing") == os.EX_OK
    assert capsys.readouterr().out == "No objects found in bucket 'bucket' with prefix 'missing'\n"


class _RecordingStorage:
    def __init__(self):
        self.calls = []

    def list_objects(self, bucket, prefix="", recursive=True):
        self.calls.append((bucket, prefix, recursive))
        return []


@pytest.mark.unit
def test_list_objects_without_a_prefix_passes_an_empty_one(monkeypatch):
    """boto3 rejects Prefix=None, so on S3 a listing without -p failed."""
    recording = _RecordingStorage()
    monkeypatch.setattr(saq.cli.commands.storage, "get_storage_system", lambda: recording)

    assert _ace("list-objects", "bucket") == os.EX_OK

    assert recording.calls == [("bucket", "", True)]


@pytest.mark.unit
def test_download(storage, local_file, tmp_path, monkeypatch):
    storage.upload_file(local_file, "bucket", "dir/remote.txt")
    monkeypatch.chdir(tmp_path)

    # without a local path, the remote file name is used
    assert _ace("download", "bucket", "dir/remote.txt") == os.EX_OK
    assert (tmp_path / "remote.txt").read_text() == "contents"

    target = tmp_path / "target.txt"
    assert _ace("download", "bucket", "dir/remote.txt", str(target)) == os.EX_OK
    assert target.read_text() == "contents"


@pytest.mark.unit
def test_download_refuses_to_overwrite_without_force(storage, local_file, tmp_path, capsys):
    storage.upload_file(local_file, "bucket", "remote.txt")
    target = tmp_path / "target.txt"
    target.write_text("keep me")

    assert _ace("download", "bucket", "remote.txt", str(target)) == os.EX_CANTCREAT
    assert target.read_text() == "keep me"
    assert "already exists. Use --force to overwrite." in capsys.readouterr().out

    assert _ace("download", "-f", "bucket", "remote.txt", str(target)) == os.EX_OK
    assert target.read_text() == "contents"


@pytest.mark.unit
def test_download_of_a_missing_object(storage, tmp_path, caplog):
    assert _ace("download", "bucket", "missing.txt", str(tmp_path / "target.txt")) == os.EX_OSERR

    assert "Failed to download bucket/missing.txt" in caplog.text


@pytest.mark.unit
def test_upload(storage, local_file):
    # without a remote path, the local file name is used
    assert _ace("upload", local_file, "bucket") == os.EX_OK
    assert _ace("upload", local_file, "bucket", "dir/remote.txt") == os.EX_OK

    assert sorted(storage.list_objects("bucket")) == ["dir/remote.txt", "local.txt"]


@pytest.mark.unit
def test_upload_of_a_missing_file(storage, tmp_path, capsys):
    missing = str(tmp_path / "missing.txt")

    assert _ace("upload", missing, "bucket") == os.EX_NOINPUT

    assert f"Local file '{missing}' does not exist." in capsys.readouterr().out


@pytest.mark.unit
def test_upload_failure(storage, local_file, caplog):
    # the local backend refuses a path that leaves the bucket
    assert _ace("upload", local_file, "bucket", "../outside.txt") == os.EX_OSERR

    assert f"Failed to upload {local_file} to bucket" in caplog.text


@pytest.mark.unit
@pytest.mark.parametrize("argv", [["list-buckets"], ["list-objects", "bucket"]])
def test_listing_failure(argv, monkeypatch, caplog, capsys):
    def _fail():
        raise RuntimeError("storage is down")

    monkeypatch.setattr(saq.cli.commands.storage, "get_storage_system", _fail)

    assert _ace(*argv) == os.EX_OSERR

    assert "storage is down" in caplog.text
    assert "Error: storage is down" in capsys.readouterr().out
