from datetime import datetime
import os
import uuid
import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.io_tracking import _get_io_read_count, _get_io_write_count
from saq.analysis.root import RootAnalysis, Submission
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_DELIVERY, F_FQDN, F_TEST
from saq.database.database_observable import get_observable_disposition_history
from saq.database.model import Alert
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.environment import get_global_runtime_settings
from saq.observables.file import FileObservable
from saq.observables.generator import create_observable
from tests.saq.helpers import create_root_analysis, track_io

class TestRootAnalysis:
    @pytest.mark.unit
    def test_submission(self, tmp_path):
        analysis = RootAnalysis(storage_dir=str(tmp_path))
        analysis.initialize_storage()
        observable = analysis.add_observable_by_spec(F_TEST, 'test')
        observable.add_tag('test_tag')
        observable.add_directive('test_directive')
        sample_file = tmp_path / 'sample.txt'
        sample_file.write_text('Hello, world!')
        analysis.add_file_observable(sample_file)
        analysis.add_tag('test')
        analysis.playbook_url = "http://playbook"
        submission = analysis.create_submission()

        assert isinstance(submission, Submission)
        assert submission.root is analysis

@pytest.mark.skip(reason="Revisit. Serialization of Analysis objects is being refactored.")
@pytest.mark.unit
def test_root_load_json_extra(tmp_path):
    # mock the root analysis class
    class MockRootAnalysis(RootAnalysis):
        def __init__(self):
            self.uuid = 'plumbus'
            self.is_loaded = False
        @property
        def json_path(self):
            return tmp_path / 'extra.json'
        def _materialize(self):
            pass
        @property
        def json(self):
            return self._json
        @json.setter
        def json(self, value):
            self._json = value
    root = MockRootAnalysis()

    # create fake root analysis json to load with extra data at the end
    with open(tmp_path / 'extra.json', 'w') as f:
        f.write('{"hello":"world"}extra')

    # load the fake root analysis json
    root.load()

    # verify the json was loaded properly
    assert root.json == { 'hello': 'world' }

@pytest.mark.unit
def test_analysis_add_file(tmpdir):
    root = create_root_analysis()
    root.initialize_storage()

    with open(tmpdir / "test.exe", "w") as fp:
        fp.write("test")

    observable = root.add_file_observable(tmpdir / 'test.exe')
    assert isinstance(observable, FileObservable)

    with open(observable.path, "r") as fp:
        assert fp.read() == "test"

@pytest.mark.unit
def test_is_on_detection_path():
    root = RootAnalysis()
    o1 = root.add_observable_by_spec(F_TEST, "test1")
    assert not o1.is_on_detection_path()
    o1.add_detection_point("test")
    assert o1.is_on_detection_path()

    root = RootAnalysis()
    o1 = root.add_observable_by_spec(F_TEST, "test1")
    analysis = Analysis()
    o1.add_analysis(analysis)
    assert not analysis.is_on_detection_path()
    o1.add_detection_point("test")
    assert analysis.is_on_detection_path()

    root = RootAnalysis()
    o1 = root.add_observable_by_spec(F_TEST, "test1")
    analysis = Analysis()
    o1.add_analysis(analysis)
    assert not analysis.is_on_detection_path()
    analysis.add_detection_point("test")
    assert analysis.is_on_detection_path()

    root = RootAnalysis()
    assert not root.is_on_detection_path()
    root.add_detection_point("test")
    assert not root.is_on_detection_path()
    
    o1 = root.add_observable_by_spec(F_TEST, "test1")
    analysis = Analysis()
    o1.add_analysis(analysis)
    assert not analysis.is_on_detection_path()

@pytest.mark.unit
def test_too_many_observables(monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "observable_limits", {F_TEST: 1})
    root = RootAnalysis(tool="test", tool_instance="test", alert_type="test", uuid=str(uuid.uuid4()))
    assert root.add_observable_by_spec(F_TEST, "test") is not None
    # exceeding the per-type limit returns None
    assert root.add_observable_by_spec(F_TEST, "test2") is None

    # types without a limit are unrestricted
    assert root.add_observable_by_spec(F_FQDN, "example.com") is not None
    assert root.add_observable_by_spec(F_FQDN, "example.org") is not None

    # raising the limit allows more of the limited type
    monkeypatch.setattr(get_global_runtime_settings(), "observable_limits", {F_TEST: 2})
    assert root.add_observable_by_spec(F_TEST, "test2") is not None
    assert root.add_observable_by_spec(F_TEST, "test3") is None

@pytest.mark.unit
def test_move_root_analysis(tmpdir, root_analysis):
    root_analysis.save()
    target_dir = tmpdir / "new_dir"
    assert root_analysis.move(str(target_dir))
    assert root_analysis.storage_dir == str(target_dir)

    # make sure we can load it from the new directory
    new_root = RootAnalysis(storage_dir=str(target_dir))
    new_root.load()
    assert new_root.uuid == root_analysis.uuid

@pytest.mark.integration
def test_create():
    root = create_root_analysis()
    root.initialize_storage()
    # make sure the defaults are what we expect them to be
    assert isinstance(root.action_counters, dict)
    assert root.details == {}
    assert isinstance(root.state, dict)
    assert root.location == get_config().global_settings.node
    assert root.company_id == get_config().global_settings.company_id
    assert root.company_name == get_config().global_settings.company_name
    assert root.submission is None

@pytest.mark.unit
def test_save():
    root = create_root_analysis()
    root.initialize_storage()
    root.save()

@pytest.mark.unit
def test_concurrent_save_no_temp_race():
    # Concurrent saves of the same root previously raced on a fixed <json_path>.tmp
    # temp file: one thread's rename removed the temp file before another thread's
    # rename ran, raising FileNotFoundError. The serializer now uses a unique temp
    # file per write, so concurrent saves must all succeed with no stray temp files.
    import json
    import threading

    root = create_root_analysis()
    root.initialize_storage()

    errors = []

    def _save():
        try:
            for _ in range(25):
                root.save()
        except BaseException as e:  # noqa: BLE001 - surface any raised error to the test
            errors.append(e)

    threads = [threading.Thread(target=_save) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []

    # the final data.json is present and valid
    with open(root.json_path) as fp:
        json.load(fp)

    # no leftover temp files in the storage directory
    leftovers = [f for f in os.listdir(os.path.dirname(root.json_path)) if f.endswith('.tmp')]
    assert leftovers == []

@pytest.mark.unit
def test_load():
    root = create_root_analysis()
    root.initialize_storage()
    root.save()
    root.load()

@pytest.mark.unit
def test_log_error_on_load_default(caplog):
    root = create_root_analysis()
    root.initialize_storage()
    root.save()
    # the flag defaults to False so load() should not log an error
    assert root.log_error_on_load is False
    root.load()
    assert not [r for r in caplog.records if r.levelname == "ERROR"]

@pytest.mark.unit
def test_log_error_on_load_enabled(caplog):
    root = create_root_analysis()
    root.initialize_storage()
    root.save()
    root.set_log_error_on_load(True)
    assert root.log_error_on_load is True
    root.load()
    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(error_records) == 1
    assert root.storage_dir in error_records[0].getMessage()

@pytest.mark.skip(reason="Skipping IO count tests for now.")
@pytest.mark.unit
@track_io
def test_io_count():
    root = create_root_analysis()
    root.initialize_storage()
    root.save()
    # we should have one write at this point
    assert _get_io_write_count() == 1
    root = create_root_analysis()
    root.load()
    # and then one read
    assert _get_io_read_count() == 1

@pytest.mark.unit
def test_has_observable():
    root = create_root_analysis()
    root.initialize_storage()
    o_uuid = root.add_observable_by_spec(F_TEST, 'test').uuid
    assert root.has_observable_by_spec(F_TEST, 'test')
    assert not root.has_observable_by_spec(F_TEST, 't3st')
    assert root.has_observable(create_observable(F_TEST, 'test'))
    assert not root.has_observable(create_observable(F_TEST, 't3st'))

@pytest.mark.unit
def test_find_observables():
    root = create_root_analysis()
    root.initialize_storage()

    o1 = root.add_observable_by_spec(F_TEST, 'test_1')
    o2 = root.add_observable_by_spec(F_TEST, 'test_2')
    o_all = sorted([o1, o2])

    # search by type, single observable
    assert root.find_observable(lambda o: o.type == F_TEST).uuid in [ o.uuid for o in o_all]
    # search by type, multi observable
    assert sorted(root.find_observables(lambda o: o.type == F_TEST)) == o_all

    # search by lambda, single observable
    assert root.find_observable(lambda o: o.type == F_TEST).uuid in [ o.uuid for o in o_all]
    # search by lambda, multi observable
    assert sorted(root.find_observables(lambda o: o.type == F_TEST)) == o_all

@pytest.mark.unit
def test_analysis_save_load_details():
    root = create_root_analysis()
    root.initialize_storage()
    root.details = { "hello": "world" }
    root.save()

    root = RootAnalysis(storage_dir=root.storage_dir)
    root.load()
    assert root.details == { "hello": "world" }

@pytest.mark.unit
def test_analysis_missing_details():
    root = create_root_analysis()
    root.initialize_storage()
    root.details = { "hello": "world" }
    root.save()

    root = RootAnalysis(storage_dir=root.storage_dir)
    root.load()
    assert root.details == { "hello": "world" }

    # zero length analysis details file
    with open(os.path.join(root.storage_dir, '.ace', root.external_details_path), 'w') as fp:
        pass

    root = RootAnalysis(storage_dir=root.storage_dir)
    root.load()
    assert root.details == {}

    # missing analysis details file
    os.remove(os.path.join(root.storage_dir, '.ace', root.external_details_path))
    root = RootAnalysis(storage_dir=root.storage_dir)
    root.load()
    assert root.details == {}

@pytest.mark.integration
def test_disposition_history():
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, 'localhost.localdomain')
    assert observable
    root.save()

    ALERT(root)

    alert = get_alert_by_uuid(root.uuid)
    assert isinstance(alert, Alert)

    disposition_history = get_observable_disposition_history(observable)
    assert disposition_history
    assert disposition_history.history == {'OPEN': 1}

    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_FQDN, 'localhost.localdomain')
    assert observable
    root.save()

    ALERT(root)
    alert = get_alert_by_uuid(root.uuid)
    assert isinstance(alert, Alert)

    alert.disposition = DISPOSITION_DELIVERY
    alert.disposition_time = datetime.now()
    alert.sync()

    disposition_history = get_observable_disposition_history(observable)
    assert disposition_history
    assert disposition_history.history == {'OPEN': 1, 'DELIVERY': 1}

@pytest.mark.integration
def test_archive_root_analysis(tmpdir):

    root = create_root_analysis()
    root.initialize_storage()

    target_file = tmpdir / "target.bin"
    target_file.write_binary(b'0')
    
    file_observable = root.add_file_observable(target_file)
    root.save()

    # mock creating a "untracked" directory that contains random stuff
    untracked_dir = os.path.join(root.storage_dir, 'untracked')
    os.mkdir(untracked_dir)
    untracked_file = os.path.join(untracked_dir, 'test.txt')
    with open(untracked_file, 'w') as fp:
        fp.write('test')

    root.archive()

    # original file should still exist
    assert os.path.exists(target_file)

    # untracked dir should be gone
    assert not os.path.exists(untracked_dir)