import json
from flask import redirect, render_template, request, session, url_for
from flask_login import login_required
from app.analysis.views.session.filters import _reset_filters, _reset_filters_special, get_existing_filter, getFilters, reset_checked_alerts, reset_pagination, reset_sort_filter
from app.blueprints import analysis


@analysis.route('/set_sort_filter', methods=['GET', 'POST'])
@login_required
def set_sort_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # flip direction if same as current, otherwise start asc
    name = request.args['name'] if request.method == 'GET' else request.form['name']
    if 'sort_filter' in session and 'sort_filter_desc' in session and session['sort_filter'] == name:
        session['sort_filter_desc'] = not session['sort_filter_desc']
    else:
        session['sort_filter'] = name
        session['sort_filter_desc'] = False

    # return empy page
    return ('', 204)

@analysis.route('/reset_filters', methods=['GET'])
@login_required
def reset_filters():
    # reset page options
    _reset_filters()
    reset_pagination()
    reset_sort_filter()
    reset_checked_alerts()

    # return empy page
    return ('', 204)

@analysis.route('/reset_filters_special', methods=['GET'])
@login_required
def reset_filters_special():
    hours = request.args['hours'] if request.method == 'GET' else request.form['hours']
    # reset page options
    _reset_filters_special(int(hours))
    reset_pagination()
    reset_sort_filter()
    reset_checked_alerts()

    # return empy page
    return ('', 204)

@analysis.route('/set_filters', methods=['GET', 'POST'])
@login_required
def set_filters():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # get filters
    filters_json = request.args['filters'] if request.method == 'GET' else request.form['filters']
    session['filters'] = json.loads(filters_json)

    if request.method == 'GET' and request.args.get("redirect"):
        return redirect(url_for('analysis.manage'))

    # return empy page
    return ('', 204)

@analysis.route('/add_filter', methods=['GET', 'POST'])
@login_required
def add_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()
    if 'filters' not in session:
        session['filters'] = []

    # add filter to session
    new_filter_json = request.args['filter'] if request.method == 'GET' else request.form['filter']
    new_filter = json.loads(new_filter_json)
    name = new_filter['name']
    inverted = new_filter.get('inverted', False)
    values = new_filter['values']
    existing_filter = get_existing_filter(name, inverted)
    if existing_filter:
        existing_filter['values'].extend(values)
    else:
        session['filters'].append({ "name": name, "inverted": inverted, "values": values })

    # return empy page
    return ('', 204)

@analysis.route('/remove_filter', methods=['GET'])
@login_required
def remove_filter():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # remove filter from session
    name = request.args['name']
    index = int(request.args['index'])
    target = []
    for _filter in session['filters']:
        if _filter["name"] == name:
            del _filter["values"][index]

        if _filter["values"]:
            target.append(_filter)

    session['filters'] = target

    # return empy page
    return ('', 204)

@analysis.route('/remove_filter_category', methods=['GET'])
@login_required
def remove_filter_category():
    # reset page options
    reset_pagination()
    reset_checked_alerts()

    # remove filter from session
    name = request.args['name']
    target = []
    for _filter in session['filters']:
        if _filter["name"] != name:
            target.append(_filter)

    session['filters'] = target

    # return empy page
    return ('', 204)

@analysis.route('/new_filter_option', methods=['POST', 'GET'])
@login_required
def new_filter_option():
    return render_template('analysis/alert_filter_input.html', filters=getFilters(), session_filters=[{"name": "Description", "inverted": False, "values": [ "" ]}])