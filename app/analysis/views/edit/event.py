from datetime import datetime
import os
from uuid import uuid4
from flask import flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT, VALID_DISPOSITIONS
from saq.database.model import Event, EventPreventionTool, EventRemediation, EventRiskLevel, EventStatus, EventType, EventVector
from saq.database.pool import get_db, get_db_connection
from saq.database.util.alert import set_dispositions

@analysis.route('/add_to_event', methods=['POST'])
@require_permission('event', 'write')
def add_to_event():
    analysis_page = False
    disposition = request.form.get('disposition', None)
    #if disposition not in VALID_DISPOSITIONS:
        #flash("invalid alert disposition: {0}".format(disposition))
        #return redirect(url_for('analysis.index'))

    disposition_comment = request.form.get('disposition_comment', None)
    event_id = request.form.get('event', None)
    event_name = request.form.get('event_name', None).strip()
    event_comment = request.form.get('event_comment', None)
    alert_time = request.form.get('alert_time', None)
    event_time = request.form.get('event_time', None)
    ownership_time = request.form.get('ownership_time', None)
    disposition_time = request.form.get('disposition_time', None)
    contain_time = request.form.get('contain_time', None)
    remediation_time = request.form.get('remediation_time', None)
    event_time = None if event_time in ['', 'None', None] else datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')
    alert_time = None if alert_time in ['', 'None', None] else datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
    ownership_time = None if ownership_time in ['', 'None', None] else datetime.strptime(ownership_time, '%Y-%m-%d %H:%M:%S')
    disposition_time = None if disposition_time in ['', 'None', None] else datetime.strptime(disposition_time, '%Y-%m-%d %H:%M:%S')
    contain_time = None if contain_time in ['', 'None', None] else datetime.strptime(contain_time, '%Y-%m-%d %H:%M:%S')
    remediation_time = None if remediation_time in ['', 'None', None] else datetime.strptime(remediation_time, '%Y-%m-%d %H:%M:%S')
    default_event_status_id = get_db().query(EventStatus).order_by(EventStatus.id).first().id
    default_event_remediation_id = get_db().query(EventRemediation).order_by(EventRemediation.id).first().id
    default_event_type_id = get_db().query(EventType).order_by(EventType.id).first().id
    default_event_vector_id = get_db().query(EventVector).order_by(EventVector.id).first().id
    default_event_risk_level_id = get_db().query(EventRiskLevel).order_by(EventRiskLevel.value).first().id
    default_event_prevention_id = get_db().query(EventPreventionTool).order_by(EventPreventionTool.id).first().id

    # Enforce logical chronology
    dates = [d for d in [event_time, alert_time, ownership_time, disposition_time, contain_time, remediation_time] if d is not None]
    sorted_dates = sorted(dates)
    if not dates == sorted_dates:
        flash("One or more of your dates has been entered out of valid order. "
              "Please ensure entered dates follow the scheme: "
              "Event Time < Alert Time <= Ownership Time < Disposition Time <= Contain Time <= Remediation Time")
        if analysis_page:
            return redirect(url_for('analysis.index'))
        else:
            return redirect(url_for('analysis.manage'))

    alert_uuids = []
    if "alert_uuids" in request.form:
        alert_uuids = request.form['alert_uuids'].split(',')

    if event_id == "NEW":
        new_event = True
    else:
        new_event = False

    with get_db_connection() as dbm:
        cursor = dbm.cursor()

        if new_event:

            creation_date = datetime.now().strftime("%Y-%m-%d")
            if len(alert_uuids) > 0:
                sql = 'SELECT insert_date FROM alerts WHERE uuid IN (%s) order by insert_date'
                in_p = ', '.join(list(map(lambda x: '%s', alert_uuids)))
                sql %= in_p
                cursor.execute(sql, alert_uuids)
                result = cursor.fetchone()
                creation_date = result[0].strftime("%Y-%m-%d")

            cursor.execute("""SELECT id FROM events WHERE creation_date = %s AND name = %s""", (creation_date, event_name))
            if cursor.rowcount > 0:
                result = cursor.fetchone()
                event_id = result[0]
            else:
                cursor.execute("""INSERT INTO events (uuid, creation_date, name, status_id, remediation_id, type_id, vector_id, risk_level_id, 
                prevention_tool_id, comment, event_time, alert_time, ownership_time, disposition_time, 
                contain_time, remediation_time, owner_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (str(uuid4()), creation_date, event_name, default_event_status_id, default_event_remediation_id, default_event_type_id, default_event_vector_id, default_event_risk_level_id,
                 default_event_prevention_id, event_comment, event_time, alert_time, ownership_time, disposition_time, contain_time,
                 remediation_time, current_user.id))

                dbm.commit()
                cursor.execute("""SELECT LAST_INSERT_ID()""")
                result = cursor.fetchone()
                event_id = result[0]

                cursor.execute("""SELECT uuid FROM events WHERE id=%s""", event_id)
                result = cursor.fetchone()
                event_uuid = result[0]

        for uuid in alert_uuids:
            cursor.execute("""SELECT id, company_id FROM alerts WHERE uuid = %s""", uuid)
            result = cursor.fetchone()
            alert_id = result[0]
            company_id = result[1]
            cursor.execute("""INSERT IGNORE INTO event_mapping (event_id, alert_id) VALUES (%s, %s)""", (event_id, alert_id))
            cursor.execute("""INSERT IGNORE INTO company_mapping (event_id, company_id) VALUES (%s, %s)""", (event_id, company_id))

        dbm.commit()

        # After the alerts are associated with the event, set the alert disposition based on what was chosen on the
        # Set Disposition modal and injected into this form.
        #if alert_uuids and disposition:
            #set_dispositions(alert_uuids, disposition, current_user.id, disposition_comment)

        # generate wiki
        cursor.execute("""SELECT creation_date, name FROM events WHERE id = %s""", event_id)
        result = cursor.fetchone()
        creation_date = result[0]
        event_name = result[1]
        cursor.execute("""SELECT uuid, storage_dir FROM alerts JOIN event_mapping ON alerts.id = event_mapping.alert_id WHERE 
        event_mapping.event_id = %s""", event_id)
        rows = cursor.fetchall()

        alert_uuids = []
        alert_paths = []
        for row in rows:
            alert_uuids.append(row[0])
            alert_paths.append(row[1])

        wiki_name = "{} {}".format(creation_date.strftime("%Y%m%d"), event_name)
        data = {"name": wiki_name, "alerts": alert_paths, "id": event_id }

    if analysis_page:
        return redirect(url_for('analysis.index'))

    # clear out the list of currently selected alerts
    if 'checked' in session:
        del session['checked']

    return redirect(url_for('analysis.manage'))

@analysis.route('/load_more_events', methods=['POST', 'GET'])
@require_permission('event', 'read')
def load_more_events():
    cur_closed_event_count = int(request.args['count'])
    events = get_db().query(Event).filter(Event.status.has(value='CLOSED')).order_by(Event.creation_date.desc()).all()
    total_closed_events = len(events)

    new_cur_closed_event_count = cur_closed_event_count + CLOSED_EVENT_LIMIT
    at_end_of_list = new_cur_closed_event_count >= total_closed_events
    if at_end_of_list:
        added_events = events[cur_closed_event_count:]
    else:
        added_events = events[cur_closed_event_count:new_cur_closed_event_count]

    return render_template('analysis/load_more_events.html', events=added_events, end_of_list=at_end_of_list)

@analysis.route('/<uuid>/event_name_candidate', methods=['GET'])
@require_permission('event', 'read')
def get_analysis_event_name_candidate(uuid):
    from saq.util import storage_dir_from_uuid, workload_storage_dir

    storage_dir = storage_dir_from_uuid(uuid)
    if get_config()['service_engine']['work_dir'] and not os.path.isdir(storage_dir):
        storage_dir = workload_storage_dir(uuid)

    if not os.path.exists(storage_dir):
        return ''

    root = RootAnalysis(storage_dir=storage_dir)
    root.load()
    return "Event"