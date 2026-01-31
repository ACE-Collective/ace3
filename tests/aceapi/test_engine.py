import json
import os
import shutil
import tarfile
import tempfile
import uuid
from flask import url_for
import pytest

from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.database.util.locking import acquire_lock
from saq.environment import get_temp_dir
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis

@pytest.mark.integration
def test_download(test_client):

    # first create something to download
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    with open(root.create_file_path('test.dat'), 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(root.create_file_path('test.dat'))
    root.save()

    # ask for a download
    result = test_client.get(url_for('engine.download', uuid=root.uuid), headers = { 'x-ace-auth': get_config().api.api_key })

    # we should get back a tar file
    tar_path = os.path.join(get_temp_dir(), 'download.tar')
    output_dir = os.path.join(get_temp_dir(), 'download')

    try:
        with open(tar_path, 'wb') as fp:
            for chunk in result.response:
                fp.write(chunk)

        with tarfile.open(name=tar_path, mode='r|') as tar:
            tar.extractall(path=output_dir, filter="data")

        root = RootAnalysis(storage_dir=output_dir)
        root.load()

        assert 'hello' in root.details
        assert 'world' == root.details['hello']

        file_observable = root.get_observable(file_observable.uuid)
        assert file_observable.exists
        with open(file_observable.full_path, 'r') as fp:
            assert fp.read() == 'test'

    finally:
        try:
            os.remove(tar_path)
        except:
            pass

        try:
            shutil.rmtree(output_dir)
        except:
            pass

@pytest.mark.integration
def test_upload(test_client):
    
    # first create something to upload
    root = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=os.path.join(get_temp_dir(), 'test_upload'))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    file_path = root.create_file_path("test.dat")
    with open(file_path, 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(file_path)
    root.save()

    # create a tar file of the entire thing
    fp, tar_path = tempfile.mkstemp(suffix='.tar', prefix='upload_{}'.format(root.uuid), dir=get_temp_dir())
    tar = tarfile.open(fileobj=os.fdopen(fp, 'wb'), mode='w|')
    tar.add(root.storage_dir, '.')
    tar.close()

    # upload it
    with open(tar_path, 'rb') as fp:
        result = test_client.post(url_for('engine.upload', uuid=root.uuid), data={ 
                                    'upload_modifiers' : json.dumps({
                                        'overwrite': False,
                                        'sync': True,
                                    }),
                                    'archive': (fp, os.path.basename(tar_path))}, headers = { 'x-ace-auth': get_config().api.api_key })

    # make sure it uploaded
    root = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
    root.load()

    assert root.details == { 'hello': 'world' }

@pytest.mark.integration
def test_upload_move(test_client):
    
    # first create something to upload
    root = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=os.path.join(get_temp_dir(), 'test_upload'))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    file_path = root.create_file_path("test.dat")
    with open(file_path, 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(file_path)
    root.save()

    # turn this into an existing alert
    ALERT(root)
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    alert.load()

    # for the purposes of testing, we'll change the location to a different node
    # lucky for me, I did a poor job on this part of the database design
    alert.location = "some node"
    alert.sync()

    # create a tar file of the entire thing
    fp, tar_path = tempfile.mkstemp(suffix='.tar', prefix='upload_{}'.format(root.uuid), dir=get_temp_dir())
    tar = tarfile.open(fileobj=os.fdopen(fp, 'wb'), mode='w|')
    tar.add(root.storage_dir, '.')
    tar.close()

    # upload it
    with open(tar_path, 'rb') as fp:
        result = test_client.post(url_for('engine.upload', uuid=root.uuid), data={ 
                                    'upload_modifiers' : json.dumps({
                                        'overwrite': False,
                                        'sync': False,
                                        'move': True,
                                    }),
                                    'archive': (fp, os.path.basename(tar_path))}, headers = { 'x-ace-auth': get_config().api.api_key })

    # make sure it moved
    get_db().close() # clear the stale session
    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
    assert alert.storage_dir != root.storage_dir
    assert alert.location != "some node"

    new_root = RootAnalysis(storage_dir=alert.storage_dir)
    new_root.load()

    assert new_root.details == { 'hello': 'world' }

@pytest.mark.integration
def test_clear(test_client):

    # first create something to clear
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    file_path = root.create_file_path("test.dat")
    with open(file_path, 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(file_path)
    root.save()

    lock_uuid = str(uuid.uuid4())

    # get a lock on it
    assert acquire_lock(root.uuid, lock_uuid)

    # clear it
    result = test_client.get(url_for('engine.clear', uuid=root.uuid, lock_uuid=lock_uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 200

    # make sure the directory is gone
    assert not os.path.exists(root.storage_dir)

@pytest.mark.integration
def test_clear_invalid_lock(test_client):

    # first create something to clear
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    file_path = root.create_file_path("test.dat")
    with open(file_path, 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(file_path)
    root.save()

    lock_uuid = str(uuid.uuid4())

    # get a lock on it
    assert acquire_lock(root.uuid, lock_uuid)

    # clear it but with the wrong lock uuid
    result = test_client.get(url_for('engine.clear', uuid=root.uuid, lock_uuid=str(uuid.uuid4())), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400

    # directory is still there
    assert os.path.exists(root.storage_dir)

@pytest.mark.integration
def test_clear_unknown_uuid(test_client):

    # first create something to clear
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    root.details = { 'hello': 'world' }
    file_path = root.create_file_path("test.dat")
    with open(file_path, 'w') as fp:
        fp.write('test')
    file_observable = root.add_file_observable(file_path)
    root.save()

    lock_uuid = str(uuid.uuid4())

    # get a lock on it
    assert acquire_lock(root.uuid, lock_uuid)

    # clear it with the wrong uuid
    result = test_client.get(url_for('engine.clear', uuid=str(uuid.uuid4()), lock_uuid=lock_uuid), headers = { 'x-ace-auth': get_config().api.api_key })
    assert result.status_code == 400

    # directory is still there
    assert os.path.exists(root.storage_dir)