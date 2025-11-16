# vim: sw=4:ts=4:et
#
# ACE API analysis routines

from aceapi.auth import api_auth_check
from aceapi.blueprints import analysis_bp

from datetime import datetime
import json
import logging
import os.path
import shutil
import uuid

from aceapi.json import json_result
from saq.analysis.root import Submission
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, EVENT_TIME_FORMAT_JSON_TZ, F_FILE, QUEUE_DEFAULT
from saq.environment import get_local_timezone

from saq.analysis import RootAnalysis
from saq.database import get_db_connection, ALERT
from saq.error import report_exception
from saq.observables.generator import create_observable_from_dict
from saq.submission_filter import SubmissionFilter
from saq.util import parse_event_time, storage_dir_from_uuid, validate_uuid, workload_storage_dir

from flask import request, abort, Response, send_from_directory
from flask import g as g_flask

from saq.util.hashing import sha256_file


KEY_ANALYSIS = 'analysis'

KEY_ANALYSIS_MODE = 'analysis_mode'
KEY_LOG_LEVEL = 'log_level'
KEY_TOOL = 'tool'
KEY_TOOL_INSTANCE = 'tool_instance'
KEY_TYPE = 'type'
KEY_DESCRIPTION = 'description'
KEY_EVENT_TIME = 'event_time'
KEY_DETAILS = 'details'
KEY_OBSERVABLES = 'observables'
KEY_TAGS = 'tags'
KEY_COMPANY_NAME = 'company_name'
KEY_QUEUE = 'queue'
KEY_INSTRUCTIONS = 'instructions'
KEY_EXTENSIONS = 'extensions'
KEY_COMPANY_ID = 'company_id'

KEY_O_TYPE = 'type'
KEY_O_VALUE = 'value'
KEY_O_TIME = 'time'
KEY_O_TAGS = 'tags'
KEY_O_DIRECTIVES = 'directives'
KEY_O_LIMITED_ANALYSIS = 'limited_analysis'

@analysis_bp.route('/submit', methods=['POST'])
@api_auth_check("alert", "create")
def submit():

    if KEY_ANALYSIS not in request.values:
        abort(Response("missing {} field (see documentation)".format(KEY_ANALYSIS), 400))

    r = json.loads(request.values[KEY_ANALYSIS])
    logging.debug("received analysis submission data: {}".format(r))

    # the specified company needs to match the company of this node
    # TODO eventually we'll have a single node that serves API to all configured companies

    if KEY_COMPANY_NAME in r:
        logging.info("Received post with company name field supplied: {}".format(r[KEY_COMPANY_NAME]))
        if r[KEY_COMPANY_NAME] != get_config()['global']['company_name']:
            abort(Response("wrong company {} (are you sending to the correct system?)".format(r[KEY_COMPANY_NAME]), 400))

    if KEY_DESCRIPTION not in r:
        abort(Response("missing {} field in submission".format(KEY_DESCRIPTION), 400))


    # does the engine use a different drive for the workload?
    analysis_mode = r[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in r else get_config()['service_engine']['default_analysis_mode']
    root_uuid = str(uuid.uuid4())
    if analysis_mode != ANALYSIS_MODE_CORRELATION:
        _storage_dir = workload_storage_dir(root_uuid)
    else:
        _storage_dir = storage_dir_from_uuid(root_uuid)

    root = RootAnalysis(uuid=root_uuid, storage_dir=_storage_dir)
    root.initialize_storage()

    try:

        root.analysis_mode = r[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in r else get_config()['service_engine']['default_analysis_mode']
        root.company_id = get_config()['global'].getint('company_id')
        if KEY_COMPANY_ID in r and r[KEY_COMPANY_ID]:
            root.company_id =  r[KEY_COMPANY_ID]
        root.tool = r[KEY_TOOL] if KEY_TOOL in r else 'api'
        root.tool_instance = r[KEY_TOOL_INSTANCE] if KEY_TOOL_INSTANCE in r else 'api({})'.format(request.remote_addr)
        root.alert_type = r[KEY_TYPE] if KEY_TYPE in r else get_config()['api']['default_alert_type']
        root.description = r[KEY_DESCRIPTION]
        root.event_time = get_local_timezone().localize(datetime.now())
        root.queue = r[KEY_QUEUE] if KEY_QUEUE in r else QUEUE_DEFAULT
        root.instructions = r[KEY_INSTRUCTIONS] if KEY_INSTRUCTIONS in r else None
        root.extensions = r[KEY_EXTENSIONS] if KEY_EXTENSIONS in r else None
        if KEY_EVENT_TIME in r:
            try:
                root.event_time = parse_event_time(r[KEY_EVENT_TIME])
            except ValueError:
                abort(Response("invalid event time format for {} (use {} format)".format(r[KEY_EVENT_TIME], EVENT_TIME_FORMAT_JSON_TZ), 400))

        root.details = r[KEY_DETAILS] if KEY_DETAILS in r else {}

        # go ahead and allocate storage
        # XXX use temp dir instead...

        if KEY_TAGS in r:
            for tag in r[KEY_TAGS]:
                root.add_tag(tag)

        file_observable_dicts: list[dict] = []

        # add the observables
        if KEY_OBSERVABLES in r:
            for observable_dict in r[KEY_OBSERVABLES]:
                if observable_dict['type'] == F_FILE:
                    file_observable_dicts.append(observable_dict)
                else:
                    root.add_observable(create_observable_from_dict(observable_dict))

        # save the files to disk and add them as observables of type file
        file_list = []
        for file_object in request.files.getlist('file'):
            logging.info("recording file {}".format(file_object.filename))
            try:

                full_path = root.create_file_path(file_object.filename)

                try:
                    dest_dir = os.path.dirname(full_path)
                    if not os.path.isdir(dest_dir):
                        try:
                            os.makedirs(dest_dir)
                        except Exception as e:
                            logging.error("unable to create directory {}: {}".format(dest_dir, e))
                            abort(400)

                    logging.debug("saving file {}".format(full_path))
                    file_object.save(full_path)

                    #
                    # XXX absolutely ugly code here, sorry
                    # just keeping this working for now until we replace with FastAPI
                    #

                    # find the file observable dict that matches this file
                    file_sha256 = sha256_file(full_path)
                    file_observable_dict = next((f for f in file_observable_dicts if f['value'] == file_sha256), None)

                    # if we don't find one we create one
                    if not file_observable_dict:
                        file_observable_dict = {
                            'value': file_sha256,
                            'file_path': file_object.filename
                        }

                    # add this as a F_FILE type observable
                    file_observable = root.add_file_observable(full_path, target_path=file_observable_dict['file_path'])
                    if file_observable:
                        file_list.append(file_observable.full_path)
                        if file_observable_dict:
                            for tag in file_observable_dict.get('tags', []):
                                file_observable.add_tag(tag)
                            for directive in file_observable_dict.get('directives', []):
                                file_observable.add_directive(directive)
                            for limited_analysis in file_observable_dict.get('limited_analysis', []):
                                file_observable.limit_analysis(limited_analysis)

                except Exception as e:
                    logging.error("unable to copy file from to {} for root {}: {}".format(full_path, root, e))
                    report_exception()
                    abort(400)

            except Exception as e:
                logging.error("unable to deal with file {}: {}".format(file_object, e))
                report_exception()
                abort(400)

        # is this submission tuned out?
        try:
            if not hasattr(g_flask, 'submission_filter'):
                g_flask.submission_filter = SubmissionFilter()
                g_flask.submission_filter.load_tuning_rules()

            submission = Submission(root)
            
            # does this submission match any tuning rules we have?
            tuning_matches = g_flask.submission_filter.get_tuning_matches(submission)
            if tuning_matches:
                g_flask.submission_filter.log_tuning_matches(submission, tuning_matches)
                try:
                    shutil.rmtree(root.storage_dir)
                except Exception as e:
                    logging.error(f"unable to delete {root.storage_dir}: {e}")

                return json_result({'result': {'uuid': root.uuid, 
                                               'tuning_matches': tuning_matches }})
            
        except Exception as e:
            logging.error(f"tuning failed: {e}")
        
        try:
            if not root.save():
                logging.error("unable to save analysis")
                abort(Response("an error occured trying to save the alert - review the logs", 400))

            # if we received a submission for correlation mode then we go ahead and add it to the database
            if root.analysis_mode == ANALYSIS_MODE_CORRELATION:
                ALERT(root)

            # add this analysis to the workload
            root.schedule()

        except Exception as e:
            logging.error("unable to sync to database: {}".format(e))
            report_exception()
            abort(Response("an error occured trying to save the alert - review the logs", 400))

        try:
            root.record_submission(r, file_list)
        except Exception as e:
            logging.error(f"unable to record submission data for {root.uuid}: {e}")

        return json_result({'result': {'uuid': root.uuid}})
    
    except Exception as e:
        logging.error("error processing submit: {}".format(e))
        report_exception()

        try:
            if os.path.isdir(root.storage_dir):
                logging.info("removing failed submit dir {}".format(root.storage_dir))
                shutil.rmtree(root.storage_dir)
        except Exception:
            logging.error("unable to delete failed submit dir {}: {}".format(root.storage_dir, e))

        raise e

@analysis_bp.route('/resubmit/<uuid>', methods=['GET'])
@api_auth_check("alert", "write")
def resubmit(uuid):
    try:
        root = RootAnalysis(storage_dir=storage_dir_from_uuid(uuid))
        root.load()
        root.reset()
        root.schedule()
        return json_result({'result':'success'})
    except Exception as e:
        return json_result({'result':'failed', 'error':str(e)})

@analysis_bp.route('/<uuid>', methods=['GET'])
@api_auth_check("alert", "read")
def get_analysis(uuid):

    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        abort(Response("invalid uuid {}".format(uuid), 400))

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()
    return json_result({'result': root.json})

@analysis_bp.route('/submission/<uuid>', methods=['GET'])
@api_auth_check("alert", "read")
def get_submission(uuid):

    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        abort(Response("invalid uuid {}".format(uuid), 400))

    root = RootAnalysis(storage_dir=storage_dir)
    if root.submission is None:
        abort(Response("no submission data available", 404))

    return json_result({'result': root.submission})

@analysis_bp.route('/status/<uuid>', methods=['GET'])
@api_auth_check("alert", "read")
def get_status(uuid):

    try:
        validate_uuid(uuid)
    except ValueError as e:
        abort(Response(str(e), 400))

    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        abort(Response("invalid uuid {}".format(uuid), 400))

    result = {
        'workload': None,
        'delayed_analysis': [],
        'locks': None,
        'alert': None
    }

    with get_db_connection() as db:
        c = db.cursor()

        # is this still in the workload?
        c.execute("""
SELECT 
    id, 
    uuid, 
    node_id, 
    analysis_mode, 
    insert_date
FROM
    workload
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['workload'] = {
                'id': row[0],
                'uuid': row[1],
                'node_id': row[2],
                'analysis_mode': row[3],
                'insert_date': row[4]
            }

        # is this an alert?
        c.execute("""
SELECT 
    id, 
    uuid,
    location,
    insert_date,
    storage_dir,
    disposition,
    disposition_time,
    detection_count
FROM
    alerts
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['alert'] = {
                'id': row[0],
                'uuid': row[1],
                'location': row[2],
                'insert_date': row[3],
                'storage_dir': row[4],
                'disposition': row[5],
                'disposition_time': row[6],
                'detection_count': row[7]
            }

        # is there any delayed analysis scheduled for it?
        c.execute("""
SELECT
    id,
    uuid,
    observable_uuid,
    analysis_module,
    insert_date,
    delayed_until,
    node_id
FROM
    delayed_analysis
WHERE
    uuid = %s
ORDER BY
    delayed_until
""", (uuid,))
        for row in c:
            result['delayed_analysis'].append({
                'id': row[0],
                'uuid': row[1],
                'observable_uuid': row[2],
                'analysis_module': row[3],
                'insert_date': row[4],
                'delayed_until': row[5],
                'node_id': row[6]
            })

        # are there any locks on it?
        c.execute("""
SELECT
    uuid,
    lock_uuid,
    lock_time,
    lock_owner
FROM
    locks
WHERE
    uuid = %s
""", (uuid,))
        row = c.fetchone()
        if row is not None:
            result['locks'] = {
                'uuid': row[0],
                'lock_uuid': row[1],
                'lock_time': row[2],
                'lock_owner': row[3]
            }

    return json_result({'result': result})

@analysis_bp.route('/details/<uuid>/<name>', methods=['GET'])
@api_auth_check("alert", "read")
def get_details(uuid, name):
    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()

    # find the analysis with this name
    for analysis in root.all_analysis:
        if analysis.external_details_path == name:
            analysis.load_details()
            return json_result({'result': analysis.details})

    abort(Response("invalid uuid or invalid details name", 400))

@analysis_bp.route('/file/<uuid>/<file_uuid_or_name>', methods=['GET'])
@api_auth_check("alert", "read")
def get_file(uuid, file_uuid_or_name):
    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()

    # is this a UUID?
    try:
        validate_uuid(file_uuid_or_name)
        file_observable = root.get_observable(file_uuid_or_name)
        if file_observable is None:
            abort(Response("invalid file_uuid {}".format(file_uuid_or_name), 400))

    except ValueError:
        file_observable = root.find_observable(lambda o: o.type == F_FILE and o.file_path == file_uuid_or_name)
        if file_observable is None:
            abort(Response("invalid file name {}".format(file_uuid_or_name), 400))
        

    # NOTE we use an absolute path here because if we don't then
    # send_from_directory makes it relavive from the app root path
    # which is (/opt/ace/aceapi)

    target_path = file_observable.full_path
    if not os.path.exists(target_path):
        abort(Response("file path {} does not exist".format(target_path), 400))

    # XXX revisit how we save (name) files
    return send_from_directory(os.path.dirname(target_path), 
                               os.path.basename(target_path), 
                               as_attachment=True,
                               # XXX latin-1 ???
                               download_name=os.path.basename(target_path).encode().decode('latin-1', errors='ignore'))
