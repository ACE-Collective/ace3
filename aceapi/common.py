# ACE API common routines
from aceapi.auth import api_auth_check
from aceapi.blueprints import common

import logging

from aceapi.json import json_result
from saq.constants import DEPRECATED_OBSERVABLES, DIRECTIVE_DESCRIPTIONS, OBSERVABLE_DESCRIPTIONS, VALID_DIRECTIVES, VALID_OBSERVABLE_TYPES

from saq.database import Company
from saq.database.pool import get_db

@common.route('/ping', methods=['GET'])
@api_auth_check("system", "read")
def ping():
    return json_result({'result': 'pong'})

@common.route('/get_supported_api_version', methods=['GET'])
@api_auth_check("system", "read")
def get_supported_api_version():
    return json_result({'result': 1})

@common.route('/get_valid_companies', methods=['GET'])
@api_auth_check("system", "read")
def get_valid_companies():
    # XXX Does it make more sense for this to return saq.NODE_COMPANIES?
    result = []
    for company in get_db().query(Company):
        result.append(company.json)

    return json_result({'result': result})
    
@common.route('/get_valid_observables', methods=['GET'])
@api_auth_check("system", "read")
def get_valid_observables():
    result = []
    # XXX 03/29/2025 -- something somewhere along the way in the tests is prepending the string 'Any' to this list
    # and I can't find it
    active_observable_types = [o_type for o_type in VALID_OBSERVABLE_TYPES if o_type not in DEPRECATED_OBSERVABLES]
    for o_type in active_observable_types:
        result.append({'name': o_type, 'description': OBSERVABLE_DESCRIPTIONS.get(o_type, "unknown")})

    return json_result({'result': result})

@common.route('/get_valid_directives', methods=['GET'])
@api_auth_check("system", "read")
def get_directives():
    result = []
    for directive in VALID_DIRECTIVES:
        try:
            result.append({'name': directive, 'description': DIRECTIVE_DESCRIPTIONS[directive]})
        except KeyError as e:
            logging.warn('Missing directive description for the "{}" directive.'.format(directive))

    return json_result({'result': result})
