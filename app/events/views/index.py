from flask import redirect, render_template, url_for
from app.auth.permissions import require_permission
from app.blueprints import events
from app.events.views.session import get_current_event
from saq.configuration.config import get_config
from saq.database.pool import get_db
from saq.database.model import Comment
from saq.remediation.coverage import get_remediation_coverage

@events.route('/analysis', methods=['GET'])
@require_permission('event', 'read')
def index():
    # the "direct" parameter is used to specify a specific event to load
    event = get_current_event()
    if event is None:
        return redirect(url_for('events.manage'))
    event_tags = event.tags

    alerts = event.alert_objects
    alert_tags = event.showable_tags

    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    remediation_coverage = get_remediation_coverage(alerts)

    return render_template(
        'events/index.html',
        event=event,
        event_tags=event_tags,
        alerts=alerts,
        alert_tags=alert_tags,
        closed_status=get_config().events.closed_status,
        comments=comments,
        remediation_coverage=remediation_coverage,
    )
