from operator import attrgetter
from flask import flash, redirect, render_template, request, url_for
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.database.model import Observable, ObservableMapping
from saq.database.pool import get_db, get_db_connection
from saq.gui.alert import GUIAlert

@analysis.route('/observables', methods=['GET'])
@require_permission('alert', 'read')
def observables():
    # get the alert we're currently looking at
    alert_uuid = request.args.get('alert_uuid')
    if not alert_uuid:
        flash("alert_uuid missing")
        return redirect(url_for('analysis.index'))

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one_or_none()
    if not alert:
        flash("alert not found")
        return redirect(url_for('analysis.index'))

    # get all the observable IDs for the alerts we currently have to display
    observables = get_db().query(Observable).join(ObservableMapping,
                                                    Observable.id == ObservableMapping.observable_id).filter(
                                                    ObservableMapping.alert_id == alert.id).all()

    # key = Observable.id, value = count
    observable_count = {}

    # for each observable, get a count of the # of times we've seen this observable (ever)
    if len(observables) > 0:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = """
                SELECT 
                    o.id,
                    count(*)
                FROM 
                    observables o JOIN observable_mapping om ON om.observable_id = o.id 
                WHERE 
                    om.observable_id IN ( {0} )
                GROUP BY 
                    o.id""".format(",".join([str(o.id) for o in observables]))

            cursor.execute(sql)

            for row in cursor:
                # we record in a dictionary that matches the observable "id" to the count
                observable_count[row[0]] = row[1]
                #logging.debug("recorded observable count of {0} for {1}".format(row[1], row[0]))

    data = {}  # key = observable_type
    for observable in observables:
        if observable.type not in data:
            data[observable.type] = []
        data[observable.type].append(observable)
        observable.count = observable_count[observable.id]

    # sort the types
    types = [key for key in data.keys()]
    types.sort()
    # and then sort the observables per type
    for _type in types:
        data[_type].sort(key=attrgetter('value'))

    return render_template(
        'analysis/load_observables.html',
        data=data,
        types=types)