"""Tests for the analysis module crash report writer (saq/crash_report.py).

The load-bearing property under test is the one in the module docstring: **nothing in here is
allowed to raise**. A crash reporter that can break analysis, or that can keep a wedged process
from reaching os._exit(1), is worse than no crash reporter at all.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime

import pytest

from saq.configuration.config import get_config
from saq.constants import F_FILE, HARDCOPY_SUBDIR
from saq.crash_report import (
    CRASH_TYPE_EXCEPTION,
    CRASH_TYPE_KILLED,
    CRASH_TYPE_TIMEOUT,
    FILE_DIR,
    METADATA_FILE,
    ROOT_JSON_FILE,
    STACK_TRACE_FILE,
    THREAD_STACKS_FILE,
    _capture_thread_stacks,
    arm_hang_stack_dump,
    cancel_hang_stack_dump,
    close_hang_stacks_file,
    discard_hang_stacks,
    drain_index_spool,
    find_crash_report_dir,
    get_crash_report_dir,
    get_hang_stacks_dir,
    get_hang_stacks_path,
    get_index_pending_dir,
    index_crash_report,
    is_valid_crash_id,
    open_hang_stacks_file,
    prune_stale_hang_stacks,
    read_crash_report,
    record_module_crash,
    take_hang_stacks,
)
from saq.database.model import AnalysisModuleCrash
from saq.database.pool import get_db


def _raise(message="boom"):
    """Produce a real exception with a real traceback."""
    try:
        raise ValueError(message)
    except ValueError as e:
        return e


def _read_metadata(crash_id):
    crash_dir = find_crash_report_dir(crash_id)
    assert crash_dir is not None
    with open(os.path.join(crash_dir, METADATA_FILE)) as fp:
        return json.load(fp)


@pytest.mark.unit
def test_is_valid_crash_id():
    assert is_valid_crash_id(str(uuid.uuid4()))

    # everything that is not a uuid4 is refused, because this value becomes a filesystem path
    # and then an archive of live malware handed to an analyst
    for bad in (
        "../../../etc/passwd",
        "not-a-crash-id",
        "",
        None,
        123,
        str(uuid.uuid4()).upper(),
        str(uuid.uuid4()) + "/..",
        f"{uuid.uuid4()}\n",
    ):
        assert not is_valid_crash_id(bad), bad


@pytest.mark.unit
def test_find_crash_report_dir_rejects_bad_id(tmp_path):
    # the traversal is refused before any path is built, not after
    assert find_crash_report_dir("../../etc") is None
    assert find_crash_report_dir("") is None


@pytest.mark.unit
def test_record_exception_crash(root_analysis):
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        module_name="basic_test",
        root=root_analysis,
        exception=_raise("kaboom"),
        index=False,
    )

    assert crash_id is not None
    assert is_valid_crash_id(crash_id)

    crash_dir = find_crash_report_dir(crash_id)
    assert crash_dir is not None
    assert os.path.basename(crash_dir) == crash_id

    metadata = _read_metadata(crash_id)
    assert metadata["crash_type"] == CRASH_TYPE_EXCEPTION
    assert metadata["module_path"] == "saq.modules.test:BasicTestAnalysis"
    assert metadata["module_name"] == "basic_test"
    assert metadata["root_uuid"] == root_analysis.uuid
    assert metadata["analysis_mode"] == root_analysis.analysis_mode
    assert metadata["exception_type"] == "ValueError"
    assert metadata["exception_message"] == "kaboom"
    assert metadata["pid"] == os.getpid()

    # the traceback is in the report, not just in a log line somewhere
    with open(os.path.join(crash_dir, STACK_TRACE_FILE)) as fp:
        stack_trace = fp.read()

    assert "ValueError" in stack_trace
    assert "kaboom" in stack_trace

    # the tree travels with it
    assert os.path.exists(os.path.join(crash_dir, ROOT_JSON_FILE))


@pytest.mark.unit
def test_record_timeout_crash_captures_thread_stacks(root_analysis):
    """A hung module's *stacks* are the point of the timeout report.

    Nothing else in ACE can produce them: every other observer of a hang runs in a different
    process and only ever sees the corpse.
    """
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_TIMEOUT,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        maximum_analysis_time=5,
        elapsed_seconds=6.5,
        include_thread_stacks=True,
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    with open(os.path.join(crash_dir, THREAD_STACKS_FILE)) as fp:
        stacks = fp.read()

    # the dump names this test's own frame, which is what proves it captured live stacks, and
    # it is faulthandler's dump rather than the GIL-bound sys._current_frames() fallback
    assert "test_record_timeout_crash_captures_thread_stacks" in stacks
    assert stacks.startswith(("Thread 0x", "Current thread 0x"))

    metadata = _read_metadata(crash_id)
    assert metadata["crash_type"] == CRASH_TYPE_TIMEOUT
    assert metadata["maximum_analysis_time"] == 5
    assert metadata["elapsed_seconds"] == 6.5


@pytest.mark.unit
def test_record_crash_copies_file_observable(root_analysis):
    """The file the module choked on is the artifact an analyst actually wants."""
    path = os.path.join(root_analysis.storage_dir, "malware.doc")
    with open(path, "w") as fp:
        fp.write("Hello, world!")

    observable = root_analysis.add_file_observable(path)
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        observable=observable,
        exception=_raise(),
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    copied = os.path.join(crash_dir, FILE_DIR, "malware.doc")
    assert os.path.exists(copied)
    with open(copied) as fp:
        assert fp.read() == "Hello, world!"

    metadata = _read_metadata(crash_id)
    assert metadata["file_name"] == "malware.doc"
    assert metadata["file_size"] == len("Hello, world!")
    # a file observable's value already IS its sha256, so this is a check that we used it
    assert metadata["file_sha256"] == observable.value
    assert metadata["observable_type"] == F_FILE
    assert metadata["omitted"] == []


@pytest.mark.unit
def test_record_crash_finds_file_by_hardcopy(root_analysis):
    """A file observable that never made it into the saved tree is still recoverable.

    A module that crashes on something it just extracted is exactly the interesting case, and
    with the root-save throttle that observable is not in the tree on disk. The bytes are,
    though -- the file manager stores them content-addressed under hardcopies/<sha256> -- so
    the crash report finds them by value. Without this the most interesting crash reports would
    silently contain no file at all.
    """
    path = os.path.join(root_analysis.storage_dir, "extracted.bin")
    with open(path, "w") as fp:
        fp.write("payload")

    observable = root_analysis.add_file_observable(path)
    sha256 = observable.value
    root_analysis.save()

    # the hardcopy exists; simulate the tree not knowing about the observable by passing only
    # the type and value, with no observable object and no match in the tree
    assert os.path.exists(os.path.join(root_analysis.storage_dir, HARDCOPY_SUBDIR, sha256))

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_KILLED,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        observable_type=F_FILE,
        observable_value=sha256,
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    metadata = _read_metadata(crash_id)
    assert metadata["file_name"] is not None
    assert os.path.exists(os.path.join(crash_dir, FILE_DIR, metadata["file_name"]))


@pytest.mark.unit
def test_record_crash_honors_file_size_cap(root_analysis, monkeypatch):
    """An oversized file is skipped *and says so*, rather than looking like it was never there."""
    monkeypatch.setattr(get_config().crash_reporting, "max_file_size", 4)

    path = os.path.join(root_analysis.storage_dir, "big.bin")
    with open(path, "w") as fp:
        fp.write("this is definitely more than four bytes")

    observable = root_analysis.add_file_observable(path)
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        observable=observable,
        exception=_raise(),
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    assert not os.path.exists(os.path.join(crash_dir, FILE_DIR))

    metadata = _read_metadata(crash_id)
    assert metadata["file_name"] is None
    omitted = {entry["what"]: entry for entry in metadata["omitted"]}
    assert FILE_DIR in omitted
    assert "size limit" in omitted[FILE_DIR]["reason"]


@pytest.mark.unit
def test_record_crash_missing_file_is_recorded_not_fatal(root_analysis):
    """A file observable whose bytes are gone produces a report that says so."""
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_KILLED,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        observable_type=F_FILE,
        observable_value="0" * 64,
        index=False,
    )

    assert crash_id is not None
    metadata = _read_metadata(crash_id)
    omitted = {entry["what"]: entry for entry in metadata["omitted"]}
    assert FILE_DIR in omitted


@pytest.mark.unit
def test_record_crash_disabled(root_analysis, monkeypatch):
    monkeypatch.setattr(get_config().crash_reporting, "enabled", False)
    assert record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        index=False,
    ) is None


@pytest.mark.unit
def test_record_crash_never_raises(root_analysis, monkeypatch):
    """The single most important test in this file.

    If this property breaks, a module failure becomes an engine failure and a hung worker stops
    reaching os._exit(1).
    """
    def explode(*args, **kwargs):
        raise PermissionError("nope")

    monkeypatch.setattr("saq.crash_report.os.makedirs", explode)

    assert record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        index=False,
    ) is None


@pytest.mark.unit
def test_record_crash_survives_no_root():
    """The killed path can reach us with a root that could not be loaded."""
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_KILLED,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=None,
        index=False,
    )

    assert crash_id is not None
    metadata = _read_metadata(crash_id)
    assert metadata["root_uuid"] is None


@pytest.mark.unit
def test_read_incomplete_report(root_analysis):
    """A report with no metadata.json is one whose worker was killed while writing it.

    It is reported as incomplete rather than hidden: what made it to disk is still evidence,
    and "the worker died writing its own crash report" is itself a finding.
    """
    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    os.remove(os.path.join(crash_dir, METADATA_FILE))

    metadata = read_crash_report(crash_id)
    assert metadata is not None
    assert metadata["complete"] is False
    assert metadata["crash_id"] == crash_id
    # the traceback that did get written is still listed
    assert any(f["path"] == STACK_TRACE_FILE for f in metadata["files"])


@pytest.mark.unit
def test_read_crash_report_unknown_id():
    assert read_crash_report(str(uuid.uuid4())) is None


@pytest.mark.unit
def test_report_is_retrievable_without_an_index_row(root_analysis):
    """The database row is an index, not the record.

    A crash is when the database is most likely to be the thing that is unwell, so a report
    written with no row must still be findable by id.
    """
    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        index=False,
    )

    # no report_dir hint, as if the row were missing entirely -- the glob fallback finds it
    assert find_crash_report_dir(crash_id, report_dir=None) is not None
    assert read_crash_report(crash_id)["complete"] is True


@pytest.mark.unit
def test_stale_report_dir_hint_falls_back(root_analysis):
    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        index=False,
    )

    assert find_crash_report_dir(crash_id, report_dir="does/not/exist") is not None


@pytest.mark.unit
def test_get_crash_report_dir_is_date_partitioned():
    from datetime import datetime

    crash_id = str(uuid.uuid4())
    path = get_crash_report_dir(crash_id, datetime(2026, 9, 16, 12, 0, 0))
    assert path.endswith(os.path.join("2026", "09", "16", crash_id))


@pytest.mark.unit
def test_report_limit_bounds_a_repeatedly_failing_module(root_analysis, monkeypatch):
    """Crash reporting is on by default and copies files, so one module failing on every file in
    a big tree must not be able to fill the disk. The first few reports say everything."""
    import saq.crash_report

    monkeypatch.setattr(get_config().crash_reporting, "max_reports_per_module_per_root", 2)
    monkeypatch.setattr(saq.crash_report, "_report_counts", {})
    root_analysis.save()

    produced = [
        record_module_crash(
            crash_type=CRASH_TYPE_EXCEPTION,
            module_path="saq.modules.test:BasicTestAnalysis",
            root=root_analysis,
            exception=_raise(),
            index=False,
        )
        for _ in range(5)
    ]

    assert len([crash_id for crash_id in produced if crash_id]) == 2
    assert produced[2] is None


@pytest.mark.unit
def test_report_limit_is_per_module_and_per_root(root_analysis, monkeypatch):
    import saq.crash_report

    monkeypatch.setattr(get_config().crash_reporting, "max_reports_per_module_per_root", 1)
    monkeypatch.setattr(saq.crash_report, "_report_counts", {})
    root_analysis.save()

    assert record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION, module_path="module:A",
        root=root_analysis, exception=_raise(), index=False) is not None

    # a different module on the same root has its own budget
    assert record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION, module_path="module:B",
        root=root_analysis, exception=_raise(), index=False) is not None

    # the same module again is suppressed
    assert record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION, module_path="module:A",
        root=root_analysis, exception=_raise(), index=False) is None


@pytest.mark.unit
def test_report_limit_exempts_the_timeout_watchdog(root_analysis, monkeypatch):
    """The watchdog's report is the only record of where a hung module was stuck."""
    import saq.crash_report

    monkeypatch.setattr(get_config().crash_reporting, "max_reports_per_module_per_root", 1)
    monkeypatch.setattr(saq.crash_report, "_report_counts", {})
    root_analysis.save()

    for _ in range(3):
        assert record_module_crash(
            crash_type=CRASH_TYPE_TIMEOUT,
            module_path="saq.modules.test:BasicTestAnalysis",
            root=root_analysis,
            include_thread_stacks=True,
            index=False,
        ) is not None


@pytest.mark.unit
def test_report_limit_disabled(root_analysis, monkeypatch):
    import saq.crash_report

    monkeypatch.setattr(get_config().crash_reporting, "max_reports_per_module_per_root", 0)
    monkeypatch.setattr(saq.crash_report, "_report_counts", {})
    root_analysis.save()

    for _ in range(4):
        assert record_module_crash(
            crash_type=CRASH_TYPE_EXCEPTION,
            module_path="saq.modules.test:BasicTestAnalysis",
            root=root_analysis, exception=_raise(), index=False) is not None


@pytest.mark.unit
def test_log_fields_truncate_unbounded_values(root_analysis):
    """An observable value is unbounded; the log line is not. The record keeps the full value."""
    from saq.crash_report import LOG_VALUE_MAX_LENGTH, CrashReportMetadata

    long_value = "x" * (LOG_VALUE_MAX_LENGTH * 3)
    metadata = CrashReportMetadata(
        crash_id=str(uuid.uuid4()),
        crash_type=CRASH_TYPE_EXCEPTION,
        timestamp="2026-09-16T12:00:00",
        observable_type="command_line",
        observable_value=long_value,
    )

    logged = metadata.log_fields()["observable_value"]
    assert len(logged) < len(long_value)
    assert "truncated" in logged

    # the full value is still what gets written down
    assert metadata.to_dict()["observable_value"] == long_value


#
# replication to shared object storage (saq/crash_replication.py)
#
# The test double is a real LocalStorage on a tmp dir, not a mock: it implements the whole
# interface, so these exercise actual upload/download/list/delete rather than asserting against
# invented behavior. "The analyst is on a different node" is simulated by deleting the local
# report directory, which is exactly what node B's disk looks like.
#

@pytest.fixture
def shared_storage(tmp_path, monkeypatch):
    """Point the cached storage adapter at a tmp dir and turn replication on."""
    from saq.storage.adapter import StorageAdapter
    from saq.storage.local import LocalStorage

    adapter = StorageAdapter(LocalStorage(base_dir=str(tmp_path / "shared")))
    monkeypatch.setattr("saq.storage.factory.STORAGE_SYSTEM", adapter)
    monkeypatch.setattr(get_config().crash_reporting, "replicate", True)
    return adapter


def _bucket_name():
    return get_config().crash_reporting.storage_bucket


@pytest.mark.unit
def test_replication_is_off_by_default(root_analysis, tmp_path, monkeypatch):
    """Replication is opt-in; nothing about the default path changes."""
    from saq.crash_replication import replication_enabled

    assert replication_enabled() is False


@pytest.mark.unit
def test_replicate_report_round_trip(root_analysis, shared_storage, tmp_path):
    """Upload then fetch reproduces the report directory byte for byte."""
    from saq.crash_replication import fetch_report, replicate_report

    path = os.path.join(root_analysis.storage_dir, "evil.docm")
    with open(path, "w") as fp:
        fp.write("payload")

    observable = root_analysis.add_file_observable(path)
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, observable=observable, exception=_raise(), index=False,
        replicate=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    assert replicate_report(crash_dir, crash_id) is True

    # now pretend we are a different node: the local copy is gone
    import shutil as _shutil
    _shutil.rmtree(crash_dir)
    assert find_crash_report_dir(crash_id) is None

    fetched = fetch_report(crash_id, str(tmp_path / "staging"))
    assert fetched is not None
    assert os.path.basename(fetched) == crash_id

    with open(os.path.join(fetched, METADATA_FILE)) as fp:
        assert json.load(fp)["crash_id"] == crash_id

    with open(os.path.join(fetched, FILE_DIR, "evil.docm")) as fp:
        assert fp.read() == "payload"


@pytest.mark.unit
def test_metadata_json_is_uploaded_last(root_analysis, shared_storage, monkeypatch):
    """The invariant the whole remote-completeness story rests on.

    A <crash_id>/metadata.json key means the remote copy is complete, exactly as the local file
    written last means the local copy is complete. If it were uploaded first, an interrupted
    upload would look complete and serve a report missing its payload.
    """
    from saq.crash_replication import replicate_report

    path = os.path.join(root_analysis.storage_dir, "evil.docm")
    with open(path, "w") as fp:
        fp.write("payload")
    observable = root_analysis.add_file_observable(path)
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, observable=observable, exception=_raise(), index=False,
        replicate=False,
    )

    uploaded = []
    original = shared_storage.upload_file

    def _record(local_path, bucket, remote_path):
        uploaded.append(remote_path)
        return original(local_path, bucket, remote_path)

    monkeypatch.setattr(shared_storage, "upload_file", _record)
    replicate_report(find_crash_report_dir(crash_id), crash_id)

    assert len(uploaded) > 1
    assert uploaded[-1] == f"{crash_id}/{METADATA_FILE}"
    assert all(METADATA_FILE not in key for key in uploaded[:-1])


@pytest.mark.unit
def test_replication_failure_never_raises_and_keeps_the_local_report(
    root_analysis, shared_storage, monkeypatch
):
    """The most important test here: a broken object store must cost cross-node availability
    only -- never the crash report, and never the crash path."""
    from saq.crash_replication import replicate_report

    def explode(*args, **kwargs):
        raise RuntimeError("object store is on fire")

    monkeypatch.setattr(shared_storage, "upload_file", explode)
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, exception=_raise(), index=False,
    )

    # the crash id came back and the local report is intact
    assert crash_id is not None
    crash_dir = find_crash_report_dir(crash_id)
    assert crash_dir is not None
    assert os.path.exists(os.path.join(crash_dir, METADATA_FILE))

    # and calling the synchronous path directly just reports failure
    assert replicate_report(crash_dir, crash_id) is False


@pytest.mark.unit
def test_record_module_crash_does_not_block_on_a_slow_store(
    root_analysis, shared_storage, monkeypatch
):
    """saq/storage has no timeouts, so the upload must not be on the crash path at all."""
    import time as _time
    from saq.crash_replication import replicate_async

    def slow(*args, **kwargs):
        _time.sleep(30)

    monkeypatch.setattr(shared_storage, "upload_file", slow)
    root_analysis.save()

    started = _time.monotonic()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, exception=_raise(), index=False,
    )
    elapsed = _time.monotonic() - started

    assert crash_id is not None
    # the upload is on a daemon thread that is never joined; anything near 30s means it is inline
    assert elapsed < 5, f"record_module_crash blocked for {elapsed}s on a slow object store"


@pytest.mark.unit
def test_watchdog_path_does_not_replicate(root_analysis, shared_storage, monkeypatch):
    """os._exit(1) annihilates daemon threads, so the watchdog defers to `ace crash sync`."""
    from saq.crash_replication import list_replicated_ids

    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_TIMEOUT,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, include_thread_stacks=True, index=False, replicate=False,
    )

    assert crash_id is not None
    assert crash_id not in list_replicated_ids()


@pytest.mark.unit
def test_incomplete_report_replicates_without_metadata(root_analysis, shared_storage):
    """A report whose worker was killed mid-write stays identifiably incomplete remotely too."""
    from saq.crash_replication import list_remote_files, remote_report_exists, replicate_report

    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, exception=_raise(), index=False, replicate=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    os.remove(os.path.join(crash_dir, METADATA_FILE))

    # returns False: the remote copy is not complete, because the local one is not either
    assert replicate_report(crash_dir, crash_id) is False
    assert remote_report_exists(crash_id) is False
    assert STACK_TRACE_FILE in list_remote_files(crash_id)


@pytest.mark.unit
def test_list_replicated_ids_and_delete(root_analysis, shared_storage):
    from saq.crash_replication import (
        delete_report, list_replicated_ids, remote_report_exists, replicate_report,
    )

    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis, exception=_raise(), index=False, replicate=False,
    )
    replicate_report(find_crash_report_dir(crash_id), crash_id)

    assert crash_id in list_replicated_ids()
    assert remote_report_exists(crash_id) is True

    assert delete_report(crash_id) is True
    assert remote_report_exists(crash_id) is False
    assert crash_id not in list_replicated_ids()


@pytest.mark.unit
def test_replication_rejects_invalid_crash_id(shared_storage, tmp_path):
    from saq.crash_replication import fetch_report, replicate_report

    assert replicate_report(str(tmp_path), "../../etc") is False
    assert fetch_report("not-a-crash-id", str(tmp_path)) is None


#
# deferred indexing: the index spool
#


@pytest.fixture
def empty_spool():
    """Start from an empty spool: unit tests elsewhere write unindexed reports and never drain."""
    shutil.rmtree(get_index_pending_dir(), ignore_errors=True)
    yield get_index_pending_dir()
    shutil.rmtree(get_index_pending_dir(), ignore_errors=True)


def _spooled():
    spool_dir = get_index_pending_dir()
    return set(os.listdir(spool_dir)) if os.path.isdir(spool_dir) else set()


def _rows(crash_id):
    get_db().expire_all()
    return get_db().query(AnalysisModuleCrash).filter(AnalysisModuleCrash.uuid == crash_id).all()


def _timeout_crash(root_analysis):
    """Exactly what the in-process watchdog does."""
    root_analysis.save()
    return record_module_crash(
        crash_type=CRASH_TYPE_TIMEOUT,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        maximum_analysis_time=15,
        elapsed_seconds=16.0,
        include_thread_stacks=True,
        index=False,
        replicate=False,
    )


@pytest.mark.integration
def test_watchdog_report_is_spooled_then_indexed(root_analysis, empty_spool):
    """The whole point: the timeout report, the only one with thread stacks, reaches the listing."""
    crash_id = _timeout_crash(root_analysis)

    # the watchdog itself never touches the database
    assert crash_id in _spooled()
    assert _rows(crash_id) == []

    indexed = drain_index_spool()

    assert [m.crash_id for m in indexed] == [crash_id]
    rows = _rows(crash_id)
    assert len(rows) == 1
    assert rows[0].crash_type == CRASH_TYPE_TIMEOUT
    assert rows[0].root_uuid == root_analysis.uuid
    assert rows[0].module_path == "saq.modules.test:BasicTestAnalysis"
    assert find_crash_report_dir(crash_id, rows[0].report_dir) is not None

    # dated by when it crashed, not when it was drained, so newest-first listing stays honest
    crashed_at = datetime.fromisoformat(read_crash_report(crash_id)["timestamp"])
    assert abs((rows[0].insert_date - crashed_at).total_seconds()) < 2

    assert crash_id not in _spooled()


@pytest.mark.integration
def test_drain_is_idempotent(root_analysis, empty_spool):
    """Several workers can start at once and all drain the same spool."""
    crash_id = _timeout_crash(root_analysis)

    # already indexed by someone else, but the spool entry is still here
    assert index_crash_report(crash_id) is not None
    assert crash_id in _spooled()

    assert [m.crash_id for m in drain_index_spool()] == [crash_id]
    assert drain_index_spool() == []
    assert len(_rows(crash_id)) == 1
    assert _spooled() == set()


@pytest.mark.integration
def test_drain_keeps_the_entry_when_the_database_is_unwell(root_analysis, empty_spool, monkeypatch):
    crash_id = _timeout_crash(root_analysis)

    def broken_db():
        raise RuntimeError("database is down")

    monkeypatch.setattr("saq.database.pool.get_db", broken_db)

    # never raises, and the entry stays for the next drain
    assert drain_index_spool() == []
    assert crash_id in _spooled()

    monkeypatch.undo()
    assert [m.crash_id for m in drain_index_spool()] == [crash_id]


@pytest.mark.integration
def test_failed_inline_insert_is_spooled(root_analysis, empty_spool, monkeypatch):
    """A row lost to an unwell database at crash time is retried rather than lost."""
    root_analysis.save()

    def broken_db():
        raise RuntimeError("database is down")

    monkeypatch.setattr("saq.database.pool.get_db", broken_db)
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        replicate=False,
    )
    monkeypatch.undo()

    assert crash_id is not None
    assert crash_id in _spooled()

    drain_index_spool()
    assert len(_rows(crash_id)) == 1


@pytest.mark.integration
def test_inline_indexed_report_is_not_spooled(root_analysis, empty_spool):
    root_analysis.save()
    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_EXCEPTION,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        exception=_raise(),
        replicate=False,
    )

    assert len(_rows(crash_id)) == 1
    assert _spooled() == set()


@pytest.mark.unit
def test_drain_drops_entries_for_reports_that_are_gone(empty_spool):
    """A pruned report can never be indexed; its entry must not block the spool forever."""
    os.makedirs(empty_spool, exist_ok=True)
    gone = str(uuid.uuid4())
    open(os.path.join(empty_spool, gone), "w").close()

    # and things that are not crash ids (an interrupted atomic write) are left alone
    open(os.path.join(empty_spool, f"{uuid.uuid4()}.tmp"), "w").close()

    assert drain_index_spool() == []
    assert gone not in _spooled()
    assert len(_spooled()) == 1


@pytest.mark.unit
def test_drain_with_no_spool_is_a_noop(empty_spool):
    assert drain_index_spool() == []


#
# thread stacks and the pre-kill hang dump
#


@pytest.mark.unit
def test_capture_thread_stacks_uses_faulthandler():
    """faulthandler needs a real file descriptor; handed a StringIO it raised and every report
    silently fell back to the pure Python dump."""
    stacks = _capture_thread_stacks()

    assert stacks.startswith(("Thread 0x", "Current thread 0x"))
    assert "test_capture_thread_stacks_uses_faulthandler" in stacks


@pytest.fixture
def hang_stacks_file():
    """This process's hang dump file, open, and always disarmed and removed afterwards so no
    faulthandler timer can leak into another test."""
    assert open_hang_stacks_file()
    path = get_hang_stacks_path(os.getpid())
    try:
        yield path
    finally:
        close_hang_stacks_file()
        discard_hang_stacks(os.getpid())


def _read(path):
    with open(path) as fp:
        return fp.read()


@pytest.mark.unit
def test_armed_hang_dump_fires(hang_stacks_file):
    """The timer fires on its own, halfway to a short maximum_analysis_time."""
    arm_hang_stack_dump(0.4)
    time.sleep(1.0)

    # dump_traceback_later heads its dump with "Timeout (<delay>)!", then faulthandler's threads
    stacks = _read(hang_stacks_file)
    assert stacks.startswith("Timeout (")
    assert "Thread 0x" in stacks
    assert "test_armed_hang_dump_fires" in stacks
    assert take_hang_stacks(os.getpid()) == stacks


@pytest.mark.unit
def test_armed_hang_dump_fires_while_the_gil_is_held(hang_stacks_file):
    """The case this exists for: a regex in _sre holds the GIL, which starves every Python
    thread (the watchdog), but not faulthandler's C thread."""
    arm_hang_stack_dump(0.4)
    # a match that runs about a second without releasing the GIL
    re.match(r"(a+)+$", "a" * 24 + "b")

    assert "test_armed_hang_dump_fires_while_the_gil_is_held" in _read(hang_stacks_file)


@pytest.mark.unit
def test_cancelled_hang_dump_writes_nothing(hang_stacks_file):
    arm_hang_stack_dump(0.4)
    cancel_hang_stack_dump()
    time.sleep(0.6)

    assert _read(hang_stacks_file) == ""
    assert take_hang_stacks(os.getpid()) is None


@pytest.mark.unit
def test_rearming_replaces_the_previous_timer(hang_stacks_file):
    arm_hang_stack_dump(0.4)
    arm_hang_stack_dump(60)
    time.sleep(0.6)

    assert _read(hang_stacks_file) == ""


@pytest.mark.unit
def test_arm_and_cancel_truncate_a_previous_dump(hang_stacks_file):
    """A dump from a module that ran long but finished never survives into the next module."""
    arm_hang_stack_dump(0.2)
    time.sleep(0.5)
    assert _read(hang_stacks_file)

    cancel_hang_stack_dump()
    assert _read(hang_stacks_file) == ""

    # and after a truncate the next dump starts at offset 0 rather than past a hole
    arm_hang_stack_dump(0.2)
    time.sleep(0.5)
    assert _read(hang_stacks_file).startswith("Timeout (")


@pytest.mark.unit
def test_arm_without_a_file_or_a_limit_is_a_noop():
    close_hang_stacks_file()
    arm_hang_stack_dump(0.2)
    cancel_hang_stack_dump()

    assert open_hang_stacks_file()
    try:
        arm_hang_stack_dump(None)
        arm_hang_stack_dump(0)
        time.sleep(0.3)
        assert _read(get_hang_stacks_path(os.getpid())) == ""
    finally:
        close_hang_stacks_file()
        discard_hang_stacks(os.getpid())


def _dead_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def _write_hang_file(pid: int, content: str = "Thread 0x1 (most recent call first):\n", age: float = 0):
    path = get_hang_stacks_path(pid)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        fp.write(content)
    if age:
        then = time.time() - age
        os.utime(path, (then, then))
    return path


@pytest.mark.unit
def test_take_and_discard_hang_stacks():
    pid = _dead_pid()
    path = _write_hang_file(pid, "Thread 0x1 (most recent call first):\n  File \"x.py\", line 1 in f\n")

    assert "x.py" in take_hang_stacks(pid)
    discard_hang_stacks(pid)
    assert not os.path.exists(path)

    # missing is fine, and so is no pid at all
    assert take_hang_stacks(pid) is None
    discard_hang_stacks(pid)
    assert take_hang_stacks(None) is None

    # an empty file is a dump that never landed
    _write_hang_file(pid, "")
    assert take_hang_stacks(pid) is None
    discard_hang_stacks(pid)


@pytest.mark.unit
def test_prune_stale_hang_stacks():
    shutil.rmtree(get_hang_stacks_dir(), ignore_errors=True)

    dead_old = _write_hang_file(_dead_pid(), age=3600)
    dead_recent = _write_hang_file(_dead_pid())
    alive_old = _write_hang_file(os.getpid(), age=3600)
    not_ours = os.path.join(get_hang_stacks_dir(), "notes.txt")
    with open(not_ours, "w") as fp:
        fp.write("x")

    try:
        assert prune_stale_hang_stacks() == 1

        assert not os.path.exists(dead_old)
        # a replacement worker may still be about to collect this one
        assert os.path.exists(dead_recent)
        assert os.path.exists(alive_old)
        assert os.path.exists(not_ours)
    finally:
        shutil.rmtree(get_hang_stacks_dir(), ignore_errors=True)


@pytest.mark.unit
def test_killed_report_carries_the_pre_kill_dump(root_analysis):
    root_analysis.save()
    stacks = "Thread 0x1 (most recent call first):\n  File \"m.py\", line 3 in stuck\n"

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_KILLED,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        thread_stacks=stacks,
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    assert _read(os.path.join(crash_dir, THREAD_STACKS_FILE)) == stacks
    assert not any(o["what"] == THREAD_STACKS_FILE for o in _read_metadata(crash_id)["omitted"])


@pytest.mark.unit
def test_killed_report_without_a_dump_says_so(root_analysis):
    root_analysis.save()

    crash_id = record_module_crash(
        crash_type=CRASH_TYPE_KILLED,
        module_path="saq.modules.test:BasicTestAnalysis",
        root=root_analysis,
        index=False,
    )

    crash_dir = find_crash_report_dir(crash_id)
    assert not os.path.exists(os.path.join(crash_dir, THREAD_STACKS_FILE))
    assert any(o["what"] == THREAD_STACKS_FILE for o in _read_metadata(crash_id)["omitted"])
