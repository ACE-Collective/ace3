from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import json
import logging
import os
import smtplib
from subprocess import PIPE, Popen
from uuid import uuid4
import uuid
import zipfile
from flask import flash, make_response, redirect, request, send_from_directory, session, url_for
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert, load_current_alert
from app.analysis.views.session.filters import _reset_filters, create_filter, hasFilter
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.csv_builder import CSV
from saq.database.model import DispositionBy, Observable, ObservableMapping, Owner, RemediatedBy, Tag, TagMapping, Comment
from saq.database.pool import get_db
from saq.database.util.locking import acquire_lock
from saq.environment import get_base_dir, get_global_runtime_settings, get_temp_dir
from saq.error.reporting import report_exception
from saq.gui.alert import GUIAlert

@analysis.route('/json', methods=['GET'])
@require_permission('alert', 'read')
def download_json():
    result = {}

    alert = get_current_alert()
    if alert is None:
        return '{}'

    try:
        alert.load()
    except Exception as e:
        logging.error("unable to load alert uuid {0}: {1}".format(request.args.get('uuid'), str(e)))
        return '{}'

    nodes = []
    next_node_id = 1
    for analysis in alert.root_analysis.all_analysis:
        analysis.node_id = 0 if analysis is alert else next_node_id
        next_node_id += 1
        node = {
            'id': analysis.node_id,
            # yellow if it's the alert otherwise white for analysis nodes
            # there is a bug in the library preventing this from working
            # 'fixed': True if analysis is alert else False,
            # 'physics': False if analysis is alert else True,
            'hidden': False,  # TODO try to hide the ones that didn't have any analysis
            'shape': 'box',
            'label': type(analysis).__name__,
            'details': analysis.details,
            'observable_uuid': None if analysis.observable is None else analysis.observable.uuid,
            'module_path': analysis.module_path}

        # if analysis.jinja_template_path is not None:
        # node['details'] = analysis.jinja_display_name

        nodes.append(node)

    for observable in alert.root_analysis.all_observables:
        observable.node_id = next_node_id
        next_node_id += 1
        nodes.append({
            'id': observable.node_id,
            'label': observable.type,
            'details': str(observable)})

    edges = []
    for analysis in alert.root_analysis.all_analysis:
        for observable in analysis.observables:
            edges.append({
                'from': analysis.node_id,
                'to': observable.node_id,
                'hidden': False})
            for observable_analysis in observable.all_analysis:
                edges.append({
                    'from': observable.node_id,
                    'to': observable_analysis.node_id,
                    'hidden': False})

    tag_nodes = {}  # key = str(tag), value = {} (tag node)
    tag_edges = []

    tagged_objects = alert.root_analysis.all_analysis
    tagged_objects.extend(alert.root_analysis.all_observables)

    for tagged_object in tagged_objects:
        for tag in tagged_object.tags:
            if str(tag) not in tag_nodes:
                next_node_id += 1
                tag_node = {
                    'id': next_node_id,
                    'shape': 'star',
                    'label': str(tag)}

                tag_nodes[str(tag)] = tag_node

            tag_node = tag_nodes[str(tag)]
            tag_edges.append({'from': tagged_object.node_id, 'to': tag_node['id']})

    nodes.extend(tag_nodes.values())
    edges.extend(tag_edges)

    response = make_response(json.dumps({'nodes': nodes, 'edges': edges}))
    response.mimetype = 'application/json'
    return response

@analysis.route('/export_alerts_to_csv', methods=['GET'])
@require_permission('alert', 'read')
def export_alerts_to_csv():
    # use default page settings if first visit
    if 'filters' not in session:
        _reset_filters()

    # create alert view by joining required tables
    query = get_db().query(GUIAlert).with_labels()
    query = query.outerjoin(Owner, GUIAlert.owner_id == Owner.id)
    if hasFilter('Disposition By'):
        query = query.outerjoin(DispositionBy, GUIAlert.disposition_user_id == DispositionBy.id)
    if hasFilter('Remediated By'):
        query = query.outerjoin(RemediatedBy, GUIAlert.removal_user_id == RemediatedBy.id)
    if hasFilter('Tag'):
        query = query.join(TagMapping, GUIAlert.id == TagMapping.alert_id).join(Tag, TagMapping.tag_id == Tag.id)
    if hasFilter('Observable'):
        query = query.join(ObservableMapping, GUIAlert.id == ObservableMapping.alert_id).join(Observable, ObservableMapping.observable_id == Observable.id)

    # apply filters
    for filter_dict in session["filters"]:
        _filter = create_filter(filter_dict["name"], inverted=filter_dict["inverted"])
        query = _filter.apply(query, filter_dict["values"])

    # only show alerts from this node
    # NOTE: this will not be necessary once alerts are stored externally
    if get_config().gui.local_node_only:
        query = query.filter(GUIAlert.location == get_global_runtime_settings().saq_node)
    elif get_config().gui.display_node_list:
        # alternatively we can display alerts for specific nodes
        # this was added on 05/02/2023 to support a DR mode of operation
        display_node_list = get_config().gui.display_node_list
        query = query.filter(GUIAlert.location.in_(display_node_list))

    # group by id to prevent duplicates
    query = query.group_by(GUIAlert.id)

    # query alerts
    alerts = query.all()

    # load alert comments
    # NOTE: We should have the alert class do this automatically
    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])).order_by(Comment.insert_date.asc()):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(f'{comment.comment}')

    # converts alerts to csv
    csv = CSV(
        'Event Time',
        'Alert Time', 
        'Disposition Time', 
        'Tool', 
        'Tool Instance', 
        'Alert Type', 
        'Description', 
        'Disposition', 
        'Owner', 
        'UUID', 
        'Queue', 
        'Comments',
    )
    for alert in alerts:
        csv.add_row(
            alert.display_event_time,
            alert.display_insert_date, 
            alert.display_disposition_time if alert.disposition_time is not None else '', 
            alert.tool,
            alert.tool_instance,
            alert.alert_type,
            alert.description,
            alert.disposition,
            alert.owner.gui_display if alert.owner_id is not None else '', 
            alert.uuid,
            alert.queue,
            '\n'.join(comments.get(alert.uuid, [])),
        )

    # send csv to client
    output = make_response(str(csv))
    output.headers["Content-Disposition"] = "attachment; filename=export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@analysis.route('/send_alert_to', methods=['POST'])
@require_permission('alert', 'read')
def send_alert_to():
    remote_host = request.json['remote_host']
    if f"send_to_{remote_host}" not in get_config().raw._data:    
        return f"Unknown remote host: {remote_host}", 400

    remote_path = get_config().raw._data[f"send_to_{remote_host}"].get("remote_path")
    alert_uuid = request.json['alert_uuid']

    # NOTE: If we require the alert to be locked first, it can't be sent to the remote host until it finished analyzing.
    # This also prevents multiple people from trying to transfer the alert at the same time.
    lock_uuid = str(uuid.uuid4())
    if not acquire_lock(alert_uuid, lock_uuid):
        return f"Unable to lock alert {alert_uuid}", 500

    try:
        # Alerts might be large, so execute the rsync in the background instead of possibly timing out the GUI
        from saq.background_exec import add_background_task, BG_TASK_RSYNC_ALERT
        add_background_task(BG_TASK_RSYNC_ALERT, alert_uuid, remote_host, remote_path, lock_uuid)

    except Exception as error:
        logging.error(f"unable to send alert {alert_uuid} to {remote_host}:{remote_path} due to error: {error}")
        return f"Error: {error}", 400
    
    # Instead of using "finally" to release the lock on the alert, the lock is released in the rsync function. This is
    # because the rsync function is executed in the background, so this send_alert_to function would release the lock
    # before the rsync function actually completes.

    return os.path.join(remote_path, alert_uuid), 200

@analysis.route('/download_file', methods=['GET', "POST"])
@require_permission('alert', 'read')
def download_file():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.root_analysis.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    if request.method == "POST":
        file_uuid = request.form['file_uuid']
    else:
        file_uuid = request.args.get('file_uuid', None)

    if file_uuid is None:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    if request.method == "POST":
        mode = request.form['mode']
    else:
        mode = request.args.get('mode', None)

    if mode is None:
        logging.error("missing mode")
        return "missing mode", 500

    response = make_response()

    # find the observable with this uuid
    try:
        file_observable = alert.root_analysis.get_observable(file_uuid)
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if file_observable is None:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # get the full path to the file to expose
    full_path = file_observable.full_path
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if mode == 'raw':
        return send_from_directory(os.path.dirname(full_path), 
                                   os.path.basename(full_path), 
                                   as_attachment=True,
                                   attachment_filename=os.path.basename(full_path).encode().decode('latin-1', errors='ignore'))
    elif mode == 'view':
        return send_from_directory(os.path.dirname(full_path), 
                                   os.path.basename(full_path), 
                                   as_attachment=False,
                                   attachment_filename=os.path.basename(full_path).encode().decode('latin-1', errors='ignore'))

    elif mode == 'hex':
        p = Popen(['hexdump', '-C', full_path], stdout=PIPE)
        (stdout, stderr) = p.communicate()
        response = make_response(stdout)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'zip':
        try:
            dest_file = '{}.zip'.format(os.path.join(get_temp_dir(), str(uuid4())))  # noqa: F821
            logging.debug("creating encrypted zip file {} for {}".format(dest_file, full_path))
            p = Popen(['zip', '-e', '--junk-paths', '-P', 'infected', dest_file, full_path])
            p.wait()

            # XXX we're reading it all into memory here
            with open(dest_file, 'rb') as fp:
                encrypted_data = fp.read()

            response = make_response(encrypted_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = 'filename={}.zip'.format(os.path.basename(full_path))
            return response

        finally:
            try:
                os.remove(dest_file)
            except Exception as e:
                logging.error("unable to remove file {}: {}".format(dest_file, str(e)))
                report_exception()
    elif mode == 'text':
        with open(full_path, 'rb') as fp:
            result = fp.read()

        response = make_response(result)
        response.headers['Content-Type'] = 'text/plain'
        return response
    elif mode == 'html':
        with open(full_path, 'rb') as fp:
            result = fp.read()

        response = make_response(result)
        response.headers['Content-Type'] = 'text/html'
        return response
    elif mode == 'malicious':
        maliciousdir = os.path.join(get_base_dir(), get_config().malicious_files.malicious_dir)
        if not os.path.isdir(maliciousdir):
            logging.error("malicious_dir {} does not exist")
            return "internal error (review logs)", 404
            
        if file_observable.sha256_hash is None:
            if not file_observable.compute_hashes():
                return "unable to compute file hash of {}".format(file_observable.value), 404

        malicioussub = os.path.join(maliciousdir, file_observable.sha256_hash[0:2])
        if not os.path.isdir(malicioussub):
            try:
                os.mkdir(malicioussub)
            except Exception as e:
                logging.error("unable to create dir {}: {}".format(malicioussub, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        lnname = os.path.join(malicioussub, file_observable.sha256_hash)
        if not os.path.exists(lnname):
            try:
                os.symlink(full_path, lnname)
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    full_path, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        if not os.path.exists(lnname + ".alert"):
            fullstoragedir = os.path.join(get_base_dir(), alert.storage_dir)
            try:
                os.symlink(fullstoragedir, lnname + ".alert")
            except Exception as e:
                logging.error("unable to create symlink from {} to {}: {}".format(
                    fullstoragedir, lnname, str(e)))
                report_exception()
                return "internal error (review logs)", 404

        # TODO we need to lock the alert here...
        file_observable.add_tag("malicious")
        alert.sync()

        # who gets these alerts?
        malicious_alert_recipients = get_config().malicious_files.malicious_alert_recipients

        msg = MIMEText('{} has identified a malicious file in alert {}.\r\n\r\nACE Direct Link: {}\r\n\r\nRemote Storage: {}'.format(
            current_user.username,
            alert.description,
            '{}/analysis?direct={}'.format(get_config().gui.base_uri, alert.uuid),
            lnname))

        msg['Subject'] = "malicious file detected - {}".format(os.path.basename(file_observable.value))
        msg['From'] = get_config().smtp.mail_from
        msg['To'] = ', '.join(malicious_alert_recipients)

        with smtplib.SMTP(get_config().smtp.server) as mail:
            mail.send_message(msg, 
                from_addr=get_config().smtp.mail_from, 
                to_addrs=malicious_alert_recipients)

        return "analysis?direct=" + alert.uuid, 200

    return "", 404

@analysis.route('/get_alert_meta', methods=['GET'])
@require_permission('alert', 'read')
def get_alert_metadata():
    alert = get_current_alert()
    if alert is None:
        result = {}
    else:
        result = alert.get_metadata_json()

    response = make_response(json.dumps(result))
    response.mimetype = 'application/json'
    return response

@analysis.route('/email_file', methods=["POST"])
@require_permission('alert', 'read')
def email_file():
    toemails = request.form.get('toemail', "").split(";")
    compress = request.form.get('compress', 'off')
    encrypt = request.form.get('encrypt', 'off')
    file_uuid = request.form.get('file_uuid', "")
    emailmessage = request.form.get("emailmessage", "")

    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    subject = request.form.get("subject", "ACE file attached from {}".format(alert.description))

    # find the observable with this uuid
    try:
        file_observable = alert.root_analysis.get_observable(file_uuid)
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
                file_uuid, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)

    # get the full path to the file to expose
    full_path = os.path.join(get_base_dir(), alert.root_analysis.storage_dir, file_observable.value)
    if not os.path.exists(full_path):
        logging.error("file path {0} does not exist for alert {1} user {2}".format(full_path, alert, current_user))
        flash("internal error")
        return redirect("/analysis?direct=" + alert.uuid)
    if compress == "on":
        if not os.path.exists(full_path + ".zip"):
            try:
                zf = zipfile.ZipFile(full_path + ".zip",
                                     mode='w',
                                     compression=zipfile.ZIP_DEFLATED,
                                     )
                with open(full_path, "rb") as fp:
                    msg = fp.read()
                try:
                    zf.writestr(os.path.basename(full_path), msg)
                finally:
                    zf.close()
            except Exception as e:
                logging.error("Could not compress " + full_path + ': ' + str(e))
                report_exception()
                flash("internal error compressing " + full_path)
                return redirect("/analysis?direct=" + alert.uuid)

        full_path += ".zip"

    if encrypt == "on":
        raise NotImplementedError("encryption is not implemented")

    try:
        smtphost = get_config().smtp.server
        smtpfrom = get_config().smtp.mail_from
        msg = MIMEMultipart()
        msg['From'] = smtpfrom
        msg['To'] = COMMASPACE.join(toemails)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        msg.attach(MIMEText(emailmessage))
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(full_path, "rb").read())
        encode_base64(part)
        #part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(full_path))
        part.add_header('Content-Disposition', os.path.basename(full_path))
        msg.attach(part)
        smtp = smtplib.SMTP(smtphost)
        smtp.sendmail(smtpfrom, toemails, msg.as_string())
        smtp.close()
    except Exception as e:
        logging.error("unable to send email: {}".format(str(e)))
        report_exception()

    return redirect("/analysis?direct=" + alert.uuid)

@analysis.route('/html_details', methods=['GET'])
@require_permission('alert', 'read')
def html_details():
    alert = load_current_alert()
    if alert is None:
        response = make_response("alert not found")
        response.mimtype = 'text/plain'
        return response

    if 'field' not in request.args:
        response = make_response("missing required parameter: field")
        response.mimtype = 'text/plain'
        return response

    response = make_response(alert.root_analysis.details[request.args['field']])
    response.mimtype = 'text/html'
    return response