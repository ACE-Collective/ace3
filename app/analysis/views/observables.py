from operator import attrgetter
from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import func
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import ANALYSIS_TYPE_FAQUEUE, QUEUE_DEFAULT
from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db
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

    # key = Observable.id, value = the number of alerts this observable has been seen in. Only
    # alerts in the default queue count, and faqueue alerts never do, the same rule as the
    # observable disposition history and the v2 observable lookup: "seen before" means real alerts
    observable_count = {}
    if observables:
        rows = (
            get_db().query(ObservableMapping.observable_id, func.count())
            .join(Alert, Alert.id == ObservableMapping.alert_id)
            .filter(
                ObservableMapping.observable_id.in_([o.id for o in observables]),
                Alert.queue == QUEUE_DEFAULT,
                Alert.alert_type != ANALYSIS_TYPE_FAQUEUE,
            )
            .group_by(ObservableMapping.observable_id)
        )
        observable_count = dict(rows.all())

    data = {}  # key = observable_type
    for observable in observables:
        if observable.type not in data:
            data[observable.type] = []
        data[observable.type].append(observable)
        observable.count = observable_count.get(observable.id, 0)

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