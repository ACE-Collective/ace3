import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import events
from saq.database.util.tag_mapping import add_event_tag_mapping

# used to determine where to redirect to after doing something
REDIRECT_MAP = {
    'analysis': 'events.index',
    'management': 'events.manage'
}

@events.route('/add_tag', methods=['POST'])
@require_permission('event', 'write')
def add_tag():
    # Make sure all required form fields are present
    for expected_form_item in ['tag', 'ids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error(f"missing expected form item {expected_form_item} for user {current_user}")
            flash("Something went wrong - Please contact administrator!")
            return redirect(url_for('events.manage'))

    # Grab and validate redirect field
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning(f"invalid redirection value {request.form['redirect']} for user {current_user}")
        redirect_to = 'events.manage'

    # If redirecting to a specific event, set the correct event ID to redirect to
    redirection_params = {}
    if redirect_to == 'events.index':
        redirection_params['direct'] = request.form['ids']
    redirection = redirect(url_for(redirect_to, **redirection_params))

    # Add tags to given events
    failed_count = 0
    tags = request.form['tag'].split()
    ids = request.form['ids'].split(',')
    for event_id in ids:
        try:
            for tag in tags:
                add_event_tag_mapping(event_id, tag)

        except Exception as e:
            logging.error(f"unable to add tag to event {event_id}: {e}")
            failed_count += 1

    if failed_count:
        flash("Some events were unable to be tagged; Please contact administrator!")

    if redirect_to == "events.manage":
        session['checked'] = ids

    return redirection