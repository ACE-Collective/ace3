from multiprocessing import Event, Process
import uuid
import pytest

from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_EMAIL, ANALYSIS_MODE_HTTP
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.node import assign_node_analysis_modes, get_node_included_analysis_modes, get_node_excluded_analysis_modes
from saq.environment import get_global_runtime_settings
from tests.saq.helpers import insert_alert

@pytest.mark.integration
def test_assign_node_analysis_modes():
    # make sure we have a node assigned
    assert get_global_runtime_settings().saq_node_id

    # clear them all
    assign_node_analysis_modes()

    # no modes have been assigned
    assert not get_node_included_analysis_modes()
    assert not get_node_excluded_analysis_modes()

    assign_node_analysis_modes(analysis_modes=[ANALYSIS_MODE_CORRELATION], excluded_analysis_modes=[ANALYSIS_MODE_EMAIL])
    assert get_node_included_analysis_modes() == [ ANALYSIS_MODE_CORRELATION ]
    assert get_node_excluded_analysis_modes() == [ ANALYSIS_MODE_EMAIL ]

    assign_node_analysis_modes(analysis_modes=[ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_ANALYSIS], excluded_analysis_modes=[ANALYSIS_MODE_EMAIL, ANALYSIS_MODE_HTTP])
    assert set(get_node_included_analysis_modes()) == set([ ANALYSIS_MODE_CORRELATION, ANALYSIS_MODE_ANALYSIS ])
    assert set(get_node_excluded_analysis_modes()) == set([ ANALYSIS_MODE_EMAIL, ANALYSIS_MODE_HTTP ])

    assign_node_analysis_modes()
    assert not get_node_included_analysis_modes()
    assert not get_node_excluded_analysis_modes()

@pytest.mark.integration
def test_lock():
    alert = insert_alert()

    lock_uuid = str(uuid.uuid4())
    acquire_lock(alert.uuid, lock_uuid)
    assert lock_uuid
    # something that was locked is locked
    assert alert.is_locked()
    # and can be locked again
    assert acquire_lock(alert.uuid, lock_uuid)
    # can be unlocked
    assert release_lock(alert.uuid, lock_uuid)
    # truely is unlocked
    assert not alert.is_locked()
    # cannot be unlocked again  
    assert not release_lock(alert.uuid, lock_uuid)
    # and can be locked again
    assert acquire_lock(alert.uuid, lock_uuid)
    assert alert.is_locked()

@pytest.mark.system
def test_multiprocess_lock():
    alert = insert_alert()
    sync0 = Event()
    sync1 = Event()
    sync2 = Event()


    def p1(alert_id):
        lock_uuid = str(uuid.uuid4())
        session = get_db()
        alert = session.query(Alert).filter(Alert.id == alert_id).one()
        acquire_lock(alert.uuid, lock_uuid)
        # tell parent to get the lock
        sync0.set()
        # wait for parent to signal
        sync1.wait()
        release_lock(alert.uuid, lock_uuid)
        sync2.set()

    p = Process(target=p1, args=(alert.id,))
    p.start()

    try:
        sync0.wait()
        
        # lock should already be locked
        assert alert.is_locked()
        # should not be able to lock the lock
        lock_uuid = str(uuid.uuid4())
        assert not acquire_lock(alert.uuid, lock_uuid)

        sync1.set()
        sync2.wait()
        # lock should be unlocked
        assert not alert.is_locked()
        # and we should be able to lock it
        assert acquire_lock(alert.uuid, lock_uuid)
        assert alert.is_locked()
        assert release_lock(alert.uuid, lock_uuid)
        assert not alert.is_locked()
        
        p.join()
        p = None
    finally:
        if p:
            p.terminate()
            p.join()

@pytest.mark.integration
def test_expired_lock(monkeypatch: pytest.MonkeyPatch):
    # set locks to expire immediately
    monkeypatch.setattr(get_global_runtime_settings(), "lock_timeout_seconds", 0)
    alert = insert_alert()
    lock_uuid = str(uuid.uuid4())
    assert acquire_lock(alert.uuid, lock_uuid)
    # should expire right away
    assert not alert.is_locked()
    # and we are able to lock it again
    assert acquire_lock(alert.uuid, lock_uuid)