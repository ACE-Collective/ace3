from datetime import timedelta
import time
import pytest
from sqlalchemy import func

from saq.database.model import Persistence
from saq.database.pool import get_db
from saq.persistence import Persistable

@pytest.mark.integration
def test_persistent_value():
    obj = Persistable()
    obj.register_persistence_source('test_source')
    obj.save_persistent_data('test_key', 'test_data')
    get_db().close()
    assert obj.load_persistent_data('test_key') == 'test_data'
    assert obj.persistent_data_exists('test_key')

@pytest.mark.integration
def test_persistant_value_update():
    obj = Persistable()
    obj.register_persistence_source('test_source')
    obj.save_persistent_key('test_key')
    get_db().close()
    old_persistence = get_db().query(Persistence).filter(Persistence.uuid == 'test_key').first()
    assert old_persistence
    time.sleep(1) # XXX
    obj.save_persistent_key('test_key')
    get_db().close()
    assert get_db().query(func.count(Persistence.id)).scalar() == 1
    new_persistence = get_db().query(Persistence).filter(Persistence.uuid == 'test_key').first()
    assert old_persistence.last_update < new_persistence.last_update

@pytest.mark.integration
def test_truncate_key():
    obj = Persistable()
    obj.register_persistence_source("test_source")

    # Save a key that is too long
    long_key = "a" * 1024
    obj.save_persistent_key(long_key)

    # The persistent data should be there
    assert obj.persistent_data_exists(long_key)

    # But the key should have been truncated to 512, so we should be able to access it with that key as well
    assert obj.persistent_data_exists("a" * 512)

    # You should also be able to delete it using the long key
    obj.delete_persistent_key(long_key)

    # And it should no longer exist using either version of the key
    assert not obj.persistent_data_exists(long_key)
    assert not obj.persistent_data_exists("a" * 512)

@pytest.mark.integration
def test_delete_expired():
    obj = Persistable()
    obj.register_persistence_source("test_source")
    obj.save_persistent_data("test", "value")
    assert obj.load_persistent_data("test") == "value"
    # delete by insert date
    obj.delete_expired_persistent_keys(timedelta(seconds=-1), timedelta(hours=1))
    with pytest.raises(KeyError):
        obj.load_persistent_data("test")

    obj.save_persistent_data("test", "value")
    assert obj.load_persistent_data("test") == "value"
    obj.delete_expired_persistent_keys(timedelta(hours=1), timedelta(seconds=-1))
    # delete by last update
    with pytest.raises(KeyError):
        obj.load_persistent_data("test")

    obj.save_persistent_data("test", "value")
    assert obj.load_persistent_data("test") == "value"
    obj.delete_expired_persistent_keys(timedelta(hours=1), timedelta(hours=1))
    assert obj.load_persistent_data("test") == "value"