# vim: sw=4:ts=4:et
#
# ACE API engine routines

import shutil
from aceapi.auth import api_auth_check
from aceapi.blueprints import engine_bp

import io
import json
import logging
import os
import os.path
import tarfile
import tempfile
import uuid as uuidlib

from aceapi.json import json_result
from saq.configuration.config import get_engine_config
from saq.database.pool import get_db_connection
from saq.environment import get_global_runtime_settings, get_temp_dir

from saq.analysis import RootAnalysis
from saq.error import report_exception
from saq.util import validate_uuid, storage_dir_from_uuid, workload_storage_dir

from flask import request, abort, Response, make_response


KEY_UUID = 'uuid'
KEY_LOCK_UUID = 'lock_uuid'

@engine_bp.route('/download/<uuid>', methods=['GET'])
@api_auth_check("alert", "read")
def download(uuid):

    validate_uuid(uuid)

    target_dir = storage_dir_from_uuid(uuid)
    if get_engine_config().work_dir and not os.path.isdir(target_dir):
        target_dir = workload_storage_dir(uuid)

    if not os.path.isdir(target_dir):
        logging.error("request to download unknown target {}".format(target_dir))
        abort(make_response("unknown target {}".format(target_dir), 400))
        #abort(Response("unknown target {}".format(target_dir)))

    logging.info("received request to download {} to {}".format(uuid, request.remote_addr))

    path = os.path.join(get_temp_dir(), f"download_{uuid}_{str(uuidlib.uuid4())}.tar")  # noqa: F821
    tar = tarfile.open(path, mode='w')
    tar.add(target_dir, '.')
    tar.close()

    def _iter_send(_path):
        with open(_path, 'rb') as fp:
            while True:
                data = fp.read(io.DEFAULT_BUFFER_SIZE)
                if data == b'':
                    break

                yield data

        try:
            os.remove(_path)
        except Exception as e:
            logging.error(f"unable to remove {path}: {e}")

    return Response(_iter_send(path), mimetype='application/octet-stream')

KEY_UPLOAD_MODIFIERS = 'upload_modifiers'
KEY_OVERWRITE = 'overwrite'
KEY_ARCHIVE = 'archive'
KEY_SYNC = 'sync'
KEY_MOVE = 'move'
KEY_IS_ALERT = 'is_alert'

@engine_bp.route('/upload/<uuid>', methods=['POST'])
@api_auth_check("alert", "create")
def upload(uuid):
    
    validate_uuid(uuid)

    if KEY_UPLOAD_MODIFIERS not in request.values:
        abort(Response("missing key {} in request".format(KEY_UPLOAD_MODIFIERS), 400))

    if KEY_ARCHIVE not in request.files:
        abort(Response("missing files key {}".format(KEY_ARCHIVE), 400))

    upload_modifiers = json.loads(request.values[KEY_UPLOAD_MODIFIERS])
    if not isinstance(upload_modifiers, dict):
        abort(Response("{} should be a dict".format(KEY_UPLOAD_MODIFIERS), 400))

    overwrite = False
    if KEY_OVERWRITE in upload_modifiers:
        overwrite = upload_modifiers[KEY_OVERWRITE]
        if not isinstance(overwrite, bool):
            abort(Response("{} should be a boolean".format(KEY_OVERWRITE), 400))

    sync = False
    if KEY_SYNC in upload_modifiers:
        sync = upload_modifiers[KEY_SYNC]
        if not isinstance(sync, bool):
            abort(Response("{} should be a boolean".format(KEY_SYNC), 400))

    move = False
    if KEY_MOVE in upload_modifiers:
        move = upload_modifiers[KEY_MOVE]
        if not isinstance(move, bool):
            abort(Response("{} should be a boolean".format(KEY_MOVE), 400))

    is_alert = True
    if KEY_IS_ALERT in upload_modifiers:
        is_alert = upload_modifiers[KEY_IS_ALERT]
        if not isinstance(is_alert, bool):
            abort(Response(f"{KEY_IS_ALERT} should be a boolean", 400))

    logging.info("requested upload for %s overwrite %s sync %s move %s is_alert %s", uuid, overwrite, sync, move, is_alert)

    # does the target directory already exist?
    if not is_alert:
        # if this is not an alert then we use the workload directory, if available
        target_dir = storage_dir_from_uuid(uuid)
    else:
        # otherwise we use the standard storage directory
        target_dir = storage_dir_from_uuid(uuid)

    if os.path.exists(target_dir):
        # are we over-writing it?
        if not overwrite:
            abort(Response("{} already exists (specify overwrite modifier to replace the data)".format(target_dir), 400))

        # if we are overwriting the entry then we need to completely clear the 
        # TODO implement this

    else:
        try:
            os.makedirs(target_dir)
        except Exception as e:
            logging.error("unable to create directory {}: {}".format(target_dir, e))
            report_exception()
            abort(Response("unable to create directory {}: {}".format(target_dir, e), 400))

    logging.debug("target directory for {} is {}".format(uuid, target_dir))

    # save the tar file so we can extract it
    fp, tar_path = tempfile.mkstemp(suffix='.tar', prefix='upload_{}'.format(uuid), dir=get_temp_dir())  # noqa: F821
    os.close(fp)

    try:
        request.files[KEY_ARCHIVE].save(tar_path)

        t = tarfile.open(tar_path, 'r|')
        t.extractall(path=target_dir, filter="data")

        logging.info("extracted {} to {}".format(uuid, target_dir))

        root = RootAnalysis(storage_dir=target_dir)
        root.load()

        #root.storage_dir = target_dir
        root.location = get_global_runtime_settings().saq_node
        root.company_id = get_global_runtime_settings().company_id
        root.company_name = get_global_runtime_settings().company_name
        root.save()

        if is_alert and move:
            with get_db_connection() as db:
                c = db.cursor()
                c.execute("UPDATE alerts SET location = %s, storage_dir = %s WHERE uuid = %s", (root.location, root.storage_dir, uuid))
                db.commit()

            #root.sync()

        if sync:
            root.schedule()

        # looks like it worked
        return json_result({'result': True})

    except Exception as e:
        logging.error("unable to upload {}: {}".format(uuid, e))
        report_exception()
        abort(Response("unable to upload {}: {}".format(uuid, e)))

    finally:
        try:
            os.remove(tar_path)
        except Exception as e:
            logging.error("unable to remove {}: {}".format(tar_path,e ))

@engine_bp.route('/clear/<uuid>/<lock_uuid>', methods=['GET'])
@api_auth_check("lock", "delete")
def clear(uuid, lock_uuid):
    validate_uuid(uuid)
    validate_uuid(lock_uuid)

    # make sure this uuid owns this lock
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s AND lock_uuid = %s", (uuid, lock_uuid))
        row = cursor.fetchone()
        if row is None:
            logging.warning("request to clear uuid {} with invalid lock uuid {}".format(uuid, lock_uuid))
            abort(Response("nope", 400))

    target_dir = storage_dir_from_uuid(uuid)
    if get_engine_config().work_dir and not os.path.isdir(target_dir):
        target_dir = workload_storage_dir(uuid)

    if not os.path.isdir(target_dir):
        logging.error("request to clear unknown target {}".format(target_dir))
        abort(Response("unknown target {}".format(target_dir)))

    logging.info("received request to clear {} from {}".format(uuid, request.remote_addr))

    try:
        logging.info("clearing target directory {}".format(target_dir))
        shutil.rmtree(target_dir)
    except Exception as e:
        logging.error("unable to clear {}: {}".format(target_dir, e))
        report_exception()
        abort(Response("clear failed"))

    return json_result({"result": True})
