from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import logging
import os
import smtplib
from subprocess import PIPE, Popen
from uuid import uuid4
import zipfile
from flask import flash, make_response, redirect, request, url_for
from flask_login import current_user
from app.analysis.views.session.alert import get_current_alert
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_temp_dir
from saq.error.reporting import report_exception

@analysis.route('/download_file', methods=['GET'])
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

    file_uuid = request.args.get('file_uuid', None)

    if file_uuid is None:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

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

    if mode == 'hex':
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
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response
    return "", 404

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
    file_observable = alert.root_analysis.get_observable(file_uuid)
    if file_observable is None:
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
