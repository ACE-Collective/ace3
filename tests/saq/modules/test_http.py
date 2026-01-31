from datetime import datetime
import json
import pytest
import pytz

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_HTTP, ANALYSIS_TYPE_BRO_HTTP, EVENT_TIME_FORMAT_JSON_TZ, F_FILE, F_FQDN, F_IPV4, F_IPV4_CONVERSATION, F_URL
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_local_timezone

from flask import url_for

from saq.json_encoding import _JSONEncoder
from saq.util.hashing import sha256_file
from saq.util.uuid import get_storage_dir

def verify(root):
    from saq.modules.http import HTTP_DETAILS_READY, HTTP_DETAILS_REQUEST, HTTP_DETAILS_REPLY

    assert HTTP_DETAILS_READY in root.details
    assert HTTP_DETAILS_REQUEST in root.details
    assert HTTP_DETAILS_REPLY in root.details
    assert len(root.details[HTTP_DETAILS_READY]) > 0
    assert len(root.details[HTTP_DETAILS_REQUEST]) > 0
    assert len(root.details[HTTP_DETAILS_REPLY]) > 0
    assert root.find_observable(lambda o: o.type == F_IPV4 and o.value == '67.195.197.75')
    assert root.find_observable(lambda o: o.type == F_IPV4 and o.value == '172.16.139.143')
    assert root.find_observable(lambda o: o.type == F_IPV4_CONVERSATION and o.value == '172.16.139.143_67.195.197.75')
    assert root.find_observable(lambda o: o.type == F_URL and o.value == 'http://www.pdf995.com/samples/pdf.pdf')
    assert root.find_observable(lambda o: o.type == F_FQDN and o.value == 'www.pdf995.com')
    assert root.find_observable(lambda o: o.type == F_FILE and o.file_name == 'CZZiJd1zicZKNMMrV1.0.ready')
    assert root.find_observable(lambda o: o.type == F_FILE and o.file_name == 'CZZiJd1zicZKNMMrV1.0.reply')
    assert root.find_observable(lambda o: o.type == F_FILE and o.file_name == 'CZZiJd1zicZKNMMrV1.0.reply.entity')
    assert root.find_observable(lambda o: o.type == F_FILE and o.file_name == 'CZZiJd1zicZKNMMrV1.0.request')
    assert root.description == 'BRO HTTP Scanner Detection - GET /samples/pdf.pdf'

@pytest.mark.integration
def test_bro_http_analyzer(root_analysis, datadir):
    get_config().get_analysis_mode_config(ANALYSIS_MODE_HTTP).cleanup = False

    root_analysis.alert_type = ANALYSIS_TYPE_BRO_HTTP
    root_analysis.analysis_mode = ANALYSIS_MODE_HTTP
    for file_name in [ 'CZZiJd1zicZKNMMrV1.0.ready', 
                        'CZZiJd1zicZKNMMrV1.0.reply', 
                        'CZZiJd1zicZKNMMrV1.0.reply.entity', 
                        'CZZiJd1zicZKNMMrV1.0.request' ]:
        source_path = str(datadir / 'http_streams' / file_name)
        root_analysis.add_file_observable(source_path)
        
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_HTTP]))
    engine.configuration_manager.enable_module('bro_http_analyzer', ANALYSIS_MODE_HTTP)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    verify(root_analysis)

@pytest.mark.integration
def test_bro_http_submission(test_client, datadir):
    get_config().get_analysis_mode_config(ANALYSIS_MODE_HTTP).cleanup = False

    event_time = get_local_timezone().localize(datetime.now()).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)

    ready_path = str(datadir / 'http_streams' / 'CZZiJd1zicZKNMMrV1.0.ready')
    ready_sha256 = sha256_file(ready_path)
    ready_fp = open(ready_path, 'rb')

    reply_path = str(datadir / 'http_streams' / 'CZZiJd1zicZKNMMrV1.0.reply')
    reply_sha256 = sha256_file(reply_path)
    reply_fp = open(reply_path, 'rb')

    reply_entity_path = str(datadir / 'http_streams' / 'CZZiJd1zicZKNMMrV1.0.reply.entity')
    reply_entity_sha256 = sha256_file(reply_entity_path)
    reply_entity_fp = open(reply_entity_path, 'rb')

    request_path = str(datadir / 'http_streams' / 'CZZiJd1zicZKNMMrV1.0.request')
    request_sha256 = sha256_file(request_path)
    request_fp = open(request_path, 'rb')

    response = test_client.post(url_for('analysis.submit'), data={
        'analysis': json.dumps({
            'analysis_mode': ANALYSIS_MODE_HTTP,
            'tool': 'unittest',
            'tool_instance': 'unittest_instance',
            'type': ANALYSIS_TYPE_BRO_HTTP,
            'description': 'BRO HTTP Scanner Detection - {}'.format('CZZiJd1zicZKNMMrV1.0'),
            'event_time': event_time,
            'details': { },
            'observables': [
                { 'type': F_FILE, 'value': ready_sha256, 'file_path': 'CZZiJd1zicZKNMMrV1.0.ready' },
                { 'type': F_FILE, 'value': reply_sha256, 'file_path': 'CZZiJd1zicZKNMMrV1.0.reply' },
                { 'type': F_FILE, 'value': reply_entity_sha256, 'file_path': 'CZZiJd1zicZKNMMrV1.0.reply.entity' },
                { 'type': F_FILE, 'value': request_sha256, 'file_path': 'CZZiJd1zicZKNMMrV1.0.request' },
            ],
            'tags': [ ],
        }, cls=_JSONEncoder),
        'file': [ (ready_fp, 'CZZiJd1zicZKNMMrV1.0.ready'),
                    (reply_fp, 'CZZiJd1zicZKNMMrV1.0.reply'),
                    (reply_entity_fp, 'CZZiJd1zicZKNMMrV1.0.reply.entity'),
                    (request_fp, 'CZZiJd1zicZKNMMrV1.0.request'), ],
        }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

    ready_fp.close()
    reply_fp.close()
    reply_entity_fp.close()
    request_fp.close()

    json_response = response.get_json()
    assert json_response

    assert 'result' in json_response
    result = json_response['result']
    assert result['uuid']
    uuid = result['uuid']

    # make sure we have a job ready

    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_HTTP]))
    engine.configuration_manager.enable_module('bro_http_analyzer', ANALYSIS_MODE_HTTP)
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(uuid))
    verify(root)