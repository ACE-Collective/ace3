import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user, login_required
from app.analysis.views.session.alert import get_current_alert
from app.analysis.views.session.filters import reset_checked_alerts
from app.blueprints import analysis

@analysis.route('/redirect_to', methods=['GET', "POST"])
@login_required
def redirect_to():

    # endpoint for redirecting to external security analysis tools (Falcon Sandbox, VirusTotal, VxStream)
    # called from observable action templates when users click external tool buttons

    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.root_analysis.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    file_uuid = request.values.get('file_uuid')
    if not file_uuid:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    target = request.values.get('target')
    if not target:
        logging.error("missing target")
        return "missing target", 500

    # find the observable with this id
    file_observable = alert.root_analysis.find_observable(lambda o: o.uuid == file_uuid)
    if not file_observable:
        flash("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        return redirect(url_for('analysis.index'))

    # the only supported target right now is VirusTotal
    if target == "vt":
        return redirect('https://www.virustotal.com/gui/file/{}'.format(file_observable.value)) # the value is the sha256 hash

    flash("invalid target {}".format(target))
    return redirect(url_for('analysis.index'))

@analysis.route('/set_page_offset', methods=['GET', 'POST'])
@login_required
def set_page_offset():
    # reset page options
    reset_checked_alerts()

    # set page offset
    session['page_offset'] = int(request.args['offset']) if request.method == 'GET' else int(request.form['offset'])

    # return empy page
    return ('', 204)

@analysis.route('/set_page_size', methods=['GET', 'POST'])
@login_required
def set_page_size():
    # reset page options
    reset_checked_alerts()

    # set page size
    session['page_size'] = int(request.args['size']) if request.method == 'GET' else int(request.form['size'])

    # return empy page
    return ('', 204)