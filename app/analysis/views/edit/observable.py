from datetime import datetime
import uuid as uuidlib
import logging
from flask import flash, redirect, request, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import ANALYSIS_MODE_CORRELATION, VALID_DIRECTIVES
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock, release_lock
from saq.database.util.workload import add_workload
from saq.gui.alert import GUIAlert

@analysis.route('/add_observable', methods=['POST'])
@require_permission('alert', 'write')
def add_observable():
    for expected_form_item in ['alert_uuid', 'add_observable_type', 'add_observable_value', 'add_observable_time']:
        if expected_form_item not in request.form:
            if expected_form_item == 'add_observable_value':
                if {'add_observable_value_A', 'add_observable_value_B'}.issubset(set(request.form.keys())):
                    continue
            logging.error("missing expected form item {0} for user {1}".format(expected_form_item, current_user))
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuid = request.form['alert_uuid']
    o_type = request.form['add_observable_type']
    if o_type not in ['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation']:
        o_value = request.form['add_observable_value']
    else:
        o_value_A = request.form.get('add_observable_value_A')
        o_value_B = request.form.get('add_observable_value_B')
        if 'email' in o_type:
            o_value = '|'.join([o_value_A, o_value_B])
        elif 'ipv4_conversation' in o_type:
            o_value = '_'.join([o_value_A, o_value_B])
        elif 'ipv4_full_conversation' in o_type:
            o_value = ':'.join([o_value_A, o_value_B])

    redirection_params = {'direct': uuid}
    redirection = redirect(url_for('analysis.index', **redirection_params))

    o_time = request.form['add_observable_time']
    try:
        if o_time != '':
            o_time = datetime.strptime(o_time, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        flash("invalid observable time format")
        return redirection

    # get the directives from the form
    directives = request.form.getlist('add_observable_directives[]')
    if not directives:
        o_directives_text = request.form.get('add_observable_directives', '')
        if o_directives_text:
            for directive in o_directives_text.split(','):
                d = directive.strip()
                if d != '' and d in VALID_DIRECTIVES:
                    directives.append(d)

    #if o_type not in VALID_OBSERVABLE_TYPES:
        #flash("invalid observable type {0}".format(o_type))
        #return redirection

    if o_value == '':
        flash("missing observable value")
        return redirection

    try:
        alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
    except Exception as e:
        logging.error("unable to load alert {0} from database: {1}".format(uuid, str(e)))
        flash("internal error")
        return redirection

    lock_uuid = str(uuidlib.uuid4())
    if acquire_lock(uuid=str(alert.uuid), lock_uuid=lock_uuid):
        alert.lock_uuid = lock_uuid
    else:
        flash("unable to modify alert: alert is currently locked")
        return redirection

    logging.info(f"AUDIT: user {current_user} added observable ({o_type},{o_value},{o_time}) to alert {alert}")

    try:
        try:
            alert.load()
        except Exception as e:
            logging.error("unable to load alert {0} from filesystem: {1}".format(uuid, str(e)))
            flash("internal error")
            return redirection

        observable = alert.root_analysis.add_observable_by_spec(o_type, o_value, None if o_time == '' else o_time)

        # apply directives to the observable
        if observable and directives:
            for directive in directives:
                if directive in VALID_DIRECTIVES:
                    observable.add_directive(directive)
            logging.info(f"AUDIT: user {current_user} added directives {directives} to observable {observable}")

        # switch back into correlation mode (we may be in a different post-correlation mode at this point)
        alert.root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION

        try:
            alert.sync()
        except Exception as e:
            logging.error("unable to sync alert: {0}".format(str(e)))
            flash("internal error")
            return redirection

        add_workload(alert.root_analysis)

        flash("added observable")
        return redirection

    finally:
        try:
            if alert.lock_uuid:
                release_lock(str(alert.uuid), alert.lock_uuid)
        except Exception:
            logging.error("unable to release lock {}: {}".format(alert.uuid, lock_uuid))
        