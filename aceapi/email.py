from aceapi.auth import api_auth_check
from aceapi.blueprints import email_bp

import logging
import socket

from urllib.parse import urlencode, quote_plus

from saq.constants import G_ENCRYPTION_KEY
from saq.email_archive import get_archived_email_path, iter_decrypt_email, get_archived_email_server
from saq.environment import g
from saq.util import fully_qualified

from flask import request, Response, abort, redirect


KEY_MESSAGE_ID = "message_id"

@email_bp.route('/get_archived_email', methods=['GET'])
@api_auth_check("email", "read")
def get_archived_email():
    if not g(G_ENCRYPTION_KEY):
        logging.critical("missing saq.ENCRYPTION_PASSWORD in api call to get_archived_email")
        abort(500)

    if KEY_MESSAGE_ID not in request.values:
        logging.warning("missing get parameter %s in api call to get_archived_email", KEY_MESSAGE_ID)
        abort(400)

    target_server = get_archived_email_server(request.values[KEY_MESSAGE_ID])
    if not target_server:
        logging.info("unknown message id %s in called to get_archived_email", request.values[KEY_MESSAGE_ID])
        abort(404)

    # is this email stored on a different server?
    if target_server != fully_qualified(socket.gethostname().lower()):
        params = { "message_id": request.values[KEY_MESSAGE_ID] }
        # XXX kind of a sloppy way to do this
        target_url = f"https://{target_server}/api/email/get_archived_email?{urlencode(params, quote_via=quote_plus)}"
        logging.info("redirecting request for %s to %s", request.values[KEY_MESSAGE_ID], target_url)
        return redirect(target_url, 302)

    target_path = get_archived_email_path(request.values[KEY_MESSAGE_ID])
    if not target_path:
        logging.info("unknown message id %s in called to get_archived_email", request.values[KEY_MESSAGE_ID])
        abort(404)

    return Response(iter_decrypt_email(target_path), mimetype="message/rfc822")
