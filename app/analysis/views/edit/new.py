from datetime import UTC, datetime
import logging
import os
import tempfile
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
import pytz
import ace_api
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_TYPE_MANUAL, DIRECTIVE_DESCRIPTIONS, F_FILE, G_TEMP_DIR, GUI_DIRECTIVES, VALID_OBSERVABLE_TYPES, create_file_location
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.engine.node_manager.distributed_node_manager import translate_node
from saq.environment import g
from saq.error.reporting import report_exception
from saq.util.filesystem import abs_path
from saq.util.hashing import sha256_file

@analysis.route('/new_alert', methods=['POST'])
@login_required
def new_alert():
    # get the list of available nodes (for all companies)
    sql = """
SELECT
    nodes.id,
    nodes.name,
    nodes.location,
    company.id,
    company.name
FROM
    nodes LEFT JOIN node_modes ON nodes.id = node_modes.node_id
    JOIN company ON company.id = nodes.company_id OR company.id = %s
WHERE
    nodes.any_mode OR node_modes.analysis_mode = %s
ORDER BY
    company.name,
    nodes.location
"""

    # get the available nodes for the default/primary company id
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(sql, (None, ANALYSIS_MODE_CORRELATION,))
        available_nodes = cursor.fetchall()

    # get submitted data
    insert_date = request.form.get('new_alert_insert_date', datetime.now().strftime('%m-%d-%Y %H:%M:%S'))
    # reformat date
    event_time = datetime.strptime(insert_date, '%m-%d-%Y %H:%M:%S')
    # set the timezone
    try:
        timezone_str = request.form.get('timezone', 'UTC')
        timezone = pytz.timezone(timezone_str)
        event_time = timezone.localize(event_time)
    except Exception as e:
        error_message = f"unable to set timezone to {timezone_str}: {e}"
        logging.error(error_message)
        flash(error_message)
        return redirect(url_for('analysis.manage'))

    comment = ''

    tool = "gui"
    tool_instance = get_config()['global']['instance_name']
    alert_type = ANALYSIS_TYPE_MANUAL
    description = request.form.get('new_alert_description', 'Manual Alert')
    is_local = request.form.get('is_local', None)
    queue = request.form.get('new_alert_queue', 'default')
    node_data = request.form.get('target_node_data', f'{available_nodes[0][0]},{available_nodes[0][2]},{available_nodes[0][3]}').split(',')
    node_id = node_data[0]
    node_location = node_data[1]
    company_id = node_data[2]
    event_time = event_time
    details = {'user': current_user.username, 'comment': comment}

    observables = []
    tags = []
    files = []
    temp_file_paths = []

    try:
        for key in request.form.keys():
            if key.startswith("observables_types_"):
                index = key.split('_')[2]
                # this contains either "multi" or "single" which indicates if the value is a multi value or not
                # a multi value is separated by either newlines or commas
                o_data_sep = request.form.get(f'observable_data_sep_{index}')
                o_type = request.form.get(f'observables_types_{index}')
                o_time = request.form.get(f'observables_times_{index}')
                if o_type not in ['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation', 'file_location']:
                    o_value = request.form.get(f'observables_values_{index}')
                else:
                    o_value_A = request.form.get(f'observables_values_{index}_A')
                    o_value_B = request.form.get(f'observables_values_{index}_B')
                    if 'email' in o_type:
                        o_value = '|'.join([o_value_A, o_value_B])
                    elif 'ipv4_conversation' in o_type:
                        o_value = '_'.join([o_value_A, o_value_B])
                    elif 'ipv4_full_conversation' in o_type:
                        o_value = ':'.join([o_value_A, o_value_B])
                    elif 'file_location' in o_type:
                        o_value = create_file_location(o_value_A, o_value_B)

                # get the directives from the form
                directives = request.form.getlist(f'observables_directives_{index}[]')
                if not directives:
                    o_directives = request.form.get(f'observables_directives_{index}').split(',')
                    for directive in o_directives:
                        d = directive.strip()
                        if d != '':
                            directives.append(d)

                observable = {
                    'type': o_type,
                    'value': o_value,
                    'directives': directives,
                }

                if o_time:
                    o_time = datetime.strptime(o_time, '%m-%d-%Y %H:%M:%S')
                    observable['time'] = timezone.localize(o_time)

                if o_type == F_FILE:
                    if is_local:
                        local_path = request.form.get(f'observables_values_{index}')
                        #observable['value'] = os.path.basename(local_path)
                        observable["value"] = sha256_file(local_path)
                        observable["file_path"] = os.path.basename(local_path)
                        files.append((observable['value'], open(local_path, 'rb')))

                    else:
                        upload_file = request.files.get(f'observables_values_{index}', None)
                        if upload_file:
                            fp, save_path = tempfile.mkstemp(suffix='.upload', dir=os.path.join(g(G_TEMP_DIR)))
                            os.close(fp)

                            temp_file_paths.append(save_path)

                            try:
                                upload_file.save(save_path)
                            except Exception as e:
                                flash(f"unable to save {save_path}: {e}")
                                report_exception()
                                return redirect(url_for('analysis.manage'))

                            files.append((upload_file.filename, open(save_path, 'rb')))

                            observable['value'] = sha256_file(save_path)
                            observable['file_path'] = upload_file.filename

                # multi fields add multiple observables of the same type
                if o_data_sep == "multi":
                    split_char = ',' # default to comma separated
                    # if there is a newline in the data then we assume newline separated
                    if '\r\n' in o_value:
                        split_char = '\r\n'
                    elif '\r' in o_value:
                        split_char = '\r'
                    elif '\n' in o_value:
                        split_char = '\n'

                    for o_value_split in o_value.split(split_char):
                        o_copy = observable.copy()
                        o_copy['value'] = o_value_split.strip()
                        observables.append(o_copy)
                else:
                    observables.append(observable)
            
        try:
            # if we added a multi field then we end up with two different submit buttons
            # one submits a single alert and the other submits one alert per observable
            if request.form.get('submit_type') == 'single':
                # if we only submitted a single obervable then we also modify the description
                if len(observables) == 1:
                    # XXX this is a hack to get the file path to show up in the description
                    if observables[0]['type'] == F_FILE:
                        description += f" ({observables[0]['file_path']})"
                    else:
                        description += f" ({observables[0]['value']})"

                result = ace_api.submit(
                    remote_host = translate_node(node_location),
                    ssl_verification = abs_path(get_config()['SSL']['ca_chain_path']),
                    description = description,
                    analysis_mode = ANALYSIS_MODE_CORRELATION,
                    tool = tool,
                    tool_instance = tool_instance,
                    company_id=company_id,
                    type = alert_type,
                    event_time = event_time,
                    details = details,
                    observables = observables,
                    tags = tags,
                    queue = queue,
                    files = files,
                    api_key = get_config()["api"]["api_key"])

                if 'result' in result and 'uuid' in result['result']:
                    uuid = result['result']['uuid']
                    get_db().execute(Alert.__table__.update().where(Alert.uuid == uuid).values(owner_id=current_user.id, owner_time=datetime.now()))
                    get_db().commit()
                    return redirect(url_for('analysis.index', direct=uuid))
            else:
                for observable in observables:
                    result = ace_api.submit(
                        remote_host = translate_node(node_location),
                        ssl_verification = abs_path(get_config()['SSL']['ca_chain_path']),
                        description = description + f" ({observable['value']})",
                        analysis_mode = ANALYSIS_MODE_CORRELATION,
                        tool = tool,
                        tool_instance = tool_instance,
                        company_id=company_id,
                        type = alert_type,
                        event_time = event_time,
                        details = details,
                        observables = [ observable ],
                        tags = tags,
                        queue = queue,
                        files = files,
                        api_key = get_config()["api"]["api_key"])

                    # in the case of multiple alerts we redirect to the last alert added
                    if 'result' in result and 'uuid' in result['result']:
                        uuid = result['result']['uuid']
                        get_db().execute(Alert.__table__.update().where(Alert.uuid == uuid).values(owner_id=current_user.id, owner_time=datetime.now(UTC)))
                        get_db().commit()

                if 'result' in result and 'uuid' in result['result']:
                    return redirect(url_for('analysis.index', direct=uuid))

        except Exception as e:
            logging.error(f"unable to submit alert: {e}")
            flash(f"unable to submit alert: {e}")
            report_exception()

        return redirect(url_for('analysis.manage'))

    finally:
        for file_path in temp_file_paths:
            try:
                os.remove(file_path)
            except Exception as e:
                logging.error(f"unable to remove {file_path}: {e}")

        for file_name, fp in files:
            try:
                fp.close()
            except:
                logging.error(f"unable to close file descriptor for {file_name}")

@analysis.route('/new_alert_observable', methods=['POST', 'GET'])
@login_required
def new_alert_observable():
    index = request.args['index']
    directives = {directive: DIRECTIVE_DESCRIPTIONS[directive] for directive in GUI_DIRECTIVES}
    return render_template('analysis/new_alert_observable.html', observable_types=VALID_OBSERVABLE_TYPES, directives=directives, index=index)

# XXX I can't remember why this is named /file

@analysis.route('/file', methods=['GET'])
@login_required
def file():
    # get the list of available nodes (for all companies)
    sql = """
SELECT
    nodes.id,
    nodes.name, 
    nodes.location,
    company.id,
    company.name
FROM
    nodes LEFT JOIN node_modes ON nodes.id = node_modes.node_id
    JOIN company ON company.id = nodes.company_id OR company.id = %s
WHERE
    nodes.any_mode OR node_modes.analysis_mode = %s
ORDER BY
    company.name,
    nodes.location
"""

    # get the available nodes for the default/primary company id
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(sql, (None, ANALYSIS_MODE_CORRELATION,))
        available_nodes = cursor.fetchall()

    # XXX secondary shit needs to come OUT

        secondary_companies = get_config()['global'].get('secondary_company_ids', None)
        if secondary_companies is not None:
            secondary_companies = secondary_companies.split(',')
            for secondary_company_id in secondary_companies:
                cursor.execute(sql, (secondary_company_id, ANALYSIS_MODE_CORRELATION,))
                more_nodes = cursor.fetchall()
                for node in more_nodes:
                    if node not in available_nodes:
                        available_nodes = (node,) + available_nodes

    logging.debug("Available Nodes: {}".format(available_nodes))

    directives = {directive: DIRECTIVE_DESCRIPTIONS[directive] for directive in GUI_DIRECTIVES}

    date = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    return render_template('analysis/analyze_file.html', 
                           observable_types=VALID_OBSERVABLE_TYPES,
                           date=date,
                           directives=directives,
                           available_nodes=available_nodes,
                           queue=current_user.queue,
                           tab='advanced',
                           timezones=pytz.common_timezones)