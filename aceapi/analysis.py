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
from saq.configuration import get_config
from saq.configuration.config import get_engine_config
from saq.constants import ANALYSIS_MODE_CORRELATION, EVENT_TIME_FORMAT_JSON_TZ, F_FILE, QUEUE_DEFAULT
from saq.environment import get_local_timezone

from saq.analysis import RootAnalysis
from saq.database import ALERT
from saq.error import report_exception
from saq.observables.generator import create_observable_from_dict
from saq.util import parse_event_time, storage_dir_from_uuid

from flask import request, abort, Response

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
KEY_O_DISPLAY_VALUE = 'display_value'
KEY_O_DISPLAY_TYPE = 'display_type'

def reject_if_node_draining():
    """Aborts the request with a 503 if the local node is draining or drained.
    Work submitted through this API is always assigned to the local node, so a
    draining node must reject it for the drain to converge."""
    from saq.constants import NODE_STATUS_DRAINED, NODE_STATUS_DRAINING
    from saq.database.util.node import get_node_status
    from saq.environment import get_global_runtime_settings

    node_id = get_global_runtime_settings().saq_node_id
    if node_id is None:
        return

    if get_node_status(node_id) in [NODE_STATUS_DRAINING, NODE_STATUS_DRAINED]:
        abort(Response("node {} is draining; submit to another node".format(
            get_global_runtime_settings().saq_node), 503))

@analysis_bp.route('/submit', methods=['POST'])
@api_auth_check("alert", "create")
def submit():

    reject_if_node_draining()

    if KEY_ANALYSIS not in request.values:
        abort(Response("missing {} field (see documentation)".format(KEY_ANALYSIS), 400))

    request_dict = json.loads(request.values[KEY_ANALYSIS])
    logging.debug("received analysis submission data: {}".format(request_dict))

    # the specified company needs to match the company of this node
    # TODO eventually we'll have a single node that serves API to all configured companies

    if KEY_COMPANY_NAME in request_dict:
        logging.info("Received post with company name field supplied: {}".format(request_dict[KEY_COMPANY_NAME]))
        if request_dict[KEY_COMPANY_NAME] != get_config().global_settings.company_name:
            abort(Response("wrong company {} (are you sending to the correct system?)".format(request_dict[KEY_COMPANY_NAME]), 400))

    if KEY_DESCRIPTION not in request_dict:
        abort(Response("missing {} field in submission".format(KEY_DESCRIPTION), 400))

    # does the engine use a different drive for the workload?
    analysis_mode = request_dict[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in request_dict else get_engine_config().default_analysis_mode
    root_uuid = str(uuid.uuid4())
    if analysis_mode != ANALYSIS_MODE_CORRELATION:
        _storage_dir = storage_dir_from_uuid(root_uuid)
    else:
        _storage_dir = storage_dir_from_uuid(root_uuid)

    root = RootAnalysis(uuid=root_uuid, storage_dir=_storage_dir)
    root.initialize_storage()

    try:

        root.analysis_mode = request_dict[KEY_ANALYSIS_MODE] if KEY_ANALYSIS_MODE in request_dict else get_engine_config().default_analysis_mode
        root.company_id = get_config().global_settings.company_id
        if KEY_COMPANY_ID in request_dict and request_dict[KEY_COMPANY_ID]:
            root.company_id =  request_dict[KEY_COMPANY_ID]
        root.tool = request_dict[KEY_TOOL] if KEY_TOOL in request_dict else 'api'
        root.tool_instance = request_dict[KEY_TOOL_INSTANCE] if KEY_TOOL_INSTANCE in request_dict else 'api({})'.format(request.remote_addr)
        root.alert_type = request_dict[KEY_TYPE] if KEY_TYPE in request_dict else get_config().api.default_alert_type
        root.description = request_dict[KEY_DESCRIPTION]
        root.event_time = get_local_timezone().localize(datetime.now())
        root.queue = request_dict[KEY_QUEUE] if KEY_QUEUE in request_dict else QUEUE_DEFAULT
        root.instructions = request_dict[KEY_INSTRUCTIONS] if KEY_INSTRUCTIONS in request_dict else None
        root.extensions = request_dict[KEY_EXTENSIONS] if KEY_EXTENSIONS in request_dict else None
        if KEY_EVENT_TIME in request_dict:
            try:
                root.event_time = parse_event_time(request_dict[KEY_EVENT_TIME])
            except ValueError:
                abort(Response("invalid event time format for {} (use {} format)".format(request_dict[KEY_EVENT_TIME], EVENT_TIME_FORMAT_JSON_TZ), 400))

        root.details = request_dict[KEY_DETAILS] if KEY_DETAILS in request_dict else {}

        # go ahead and allocate storage
        # XXX use temp dir instead...

        if KEY_TAGS in request_dict:
            for tag in request_dict[KEY_TAGS]:
                root.add_tag(tag)

        file_observable_dicts: list[dict] = []

        # add the observables
        if KEY_OBSERVABLES in request_dict:
            for observable_dict in request_dict[KEY_OBSERVABLES]:
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
                            if file_observable_dict.get('added_by'):
                                file_observable.added_by = file_observable_dict['added_by']
                            if file_observable_dict.get('added_time'):
                                file_observable.added_time = file_observable_dict['added_time']

                except Exception as e:
                    logging.error("unable to copy file from to {} for root {}: {}".format(full_path, root, e))
                    report_exception()
                    abort(400)

            except Exception as e:
                logging.error("unable to deal with file {}: {}".format(file_object, e))
                report_exception()
                abort(400)

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
            root.record_submission(request_dict, file_list)
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
