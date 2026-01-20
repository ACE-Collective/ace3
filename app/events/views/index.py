from flask import redirect, render_template, url_for
from app.auth.permissions import require_permission
from app.blueprints import events
from app.events.views.session import get_current_event
from saq.configuration.config import get_config
from saq.database.pool import get_db
from saq.database.model import Comment
from saq.util.ui import create_histogram_string

@events.route('/analysis', methods=['GET', 'POST'])
@require_permission('event', 'read')
def index():
    # the "direct" parameter is used to specify a specific event to load
    event = get_current_event()
    if event is None:
        return redirect(url_for('events.manage'))
    event_tags = event.tags

    alerts = event.alert_objects
    alert_tags = event.showable_tags

    emails = event.all_emails

    email_to_display = None
    screenshots = None
    if event.alert_with_email_and_screenshot:
        email_to_display = event.alert_with_email_and_screenshot.all_email_analysis[0]
        screenshots = event.alert_with_email_and_screenshot.screenshots
    elif emails:
        email_to_display = next(iter(emails))

    phish_headers = None
    phish_body = None
    if email_to_display:
        phish_headers = email_to_display.headers_formatted
        phish_body_text = email_to_display.body_text
        phish_body_html = email_to_display.body_html
        phish_body = phish_body_text if phish_body_text else phish_body_html

    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    return render_template(
        'events/index.html',
        event=event,
        event_tags=event_tags,
        alerts=alerts,
        alert_tags=alert_tags,
        emails=emails,
        phish_headers=phish_headers,
        phish_body=phish_body,
        screenshots=screenshots,
        user_analysis=event.all_user_analysis,
        url_histogram=create_histogram_string(event.all_url_domain_counts),
        urls='\n'.join(sorted(list(event.all_urls))),
        observables=event.all_observables_sorted,
        closed_status=get_config().events.closed_status,
        comments=comments
    )