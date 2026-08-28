import logging

from flask import flash, redirect, request, session, url_for
from flask_login import current_user

from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.constants import REDIRECT_MAP
from saq.database.model import Comment
from saq.database.pool import get_db
from saq.database.util.alert import touch_alerts


@analysis.route('/add_comment', methods=['POST'])
@require_permission('alert', 'write')
def add_comment():
    user_comment = None
    uuids = None
    redirect_to = None

    for expected_form_item in ['comment', 'uuids', 'redirect']:
        if expected_form_item not in request.form:
            logging.error(f"missing expected form item {expected_form_item} for user {current_user}")
            flash("internal error")
            return redirect(url_for('analysis.index'))

    uuids = request.form['uuids'].split(',')
    try:
        redirect_to = REDIRECT_MAP[request.form['redirect']]
    except KeyError:
        logging.warning("invalid redirection value {0} for user {1}".format(request.form['redirect'], current_user))
        redirect_to = 'analysis.index'

    # the analysis page will require the direct uuid to get back to the alert the user just commented on
    redirection_params = {}
    if redirect_to == 'analysis.index':
        redirection_params['direct'] = request.form['uuids']

    redirection = redirect(url_for(redirect_to, **redirection_params))

    user_comment = request.form['comment']
    if len(user_comment.strip()) < 1:
        flash("comment cannot be empty")
        return redirection

    logging.info(f"AUDIT: user {current_user} added comment {user_comment} to alerts {','.join(uuids)}")

    for uuid in uuids:
        comment = Comment(
            user=current_user,
            uuid=uuid,
            comment=user_comment)

        get_db().add(comment)

    touch_alerts(uuids)
    get_db().commit()

    from saq.llm.embedding.service import submit_embedding_task
    for uuid in uuids:
        submit_embedding_task(uuid)

    flash("added comment to {0} item{1}".format(len(uuids), "s" if len(uuids) != 1 else ''))

    if redirect_to == "analysis.manage":
        session['checked'] = uuids

    return redirection

@analysis.route('/delete_comment', methods=['POST'])
@require_permission('alert', 'write')
def delete_comment():
    comment_id = request.form.get('comment_id', None)
    if comment_id is None:
        flash("missing comment_id")
        return redirect(url_for('analysis.index'))

    # XXX use delete() instead of select then delete
    comment = get_db().query(Comment).filter(Comment.comment_id == comment_id).one_or_none()
    if comment is None:
        flash("comment not found")
        return redirect(url_for('analysis.index'))

    if comment.user.id != current_user.id:
        flash("invalid user for this comment")
        return redirect(url_for('analysis.index'))

    logging.info(f"AUDIT: user {current_user} deleted comment {comment.comment} from alert {comment.uuid}")

    alert_uuid = comment.uuid

    get_db().delete(comment)
    touch_alerts([alert_uuid])
    get_db().commit()

    from saq.llm.embedding.service import submit_embedding_task
    submit_embedding_task(alert_uuid)

    return redirect(url_for('analysis.index', direct=request.form['direct']))