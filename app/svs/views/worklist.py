from flask import abort, render_template, url_for
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import svs
from saq.gui.filter_screens import SVS_WORKLIST_SCREEN
from saq.gui.filter_url import encode_filter_query
from saq.util.uuid import UUID_REGEX


def _urls() -> dict:
    # the scripts put the ids in place of __SIGNATURE__ / __TECHNIQUE__ / __TEST__
    return {
        "signature_url": url_for("svs.worklist_signature", signature_uuid="__SIGNATURE__"),
        "technique_url": url_for("svs.coverage_detail", technique="__TECHNIQUE__"),
        "test_url": url_for("svs.test_detail", guid="__TEST__"),
    }


@svs.route("/worklist", methods=["GET"])
def worklist():
    # the declared-vs-measured worklist (docs/SVS_COVERAGE.md, *In the GUI*): a shell over
    # /api/v2/svs/worklist, whose filters and saved filters are the svs_worklist screen's, grouped per
    # signature. Like the other tabs, a user new to the screen gets its default saved filters, and only
    # this real page render writes them. Resolving follows svs:run_manage in the template, and the API
    # enforces it regardless.
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_WORKLIST_SCREEN.name)
    return render_template("svs/worklist.html", worklist_screen=SVS_WORKLIST_SCREEN.name, **_urls())


@svs.route("/worklist/<signature_uuid>", methods=["GET"])
def worklist_signature(signature_uuid: str):
    # one signature's worklist rows, retired ones included, and what it is measured on now: a shell over
    # /api/v2/svs/worklist/{signature_uuid}. A signature no test measures is the script's 404, from the
    # API. The uuid is kept as written: signature uuids are stored as their sources write them.
    if not UUID_REGEX.fullmatch(signature_uuid):
        abort(404)
    # the Worklist tab filtered on this signature
    worklist_f = encode_filter_query([{"name": "Signature", "inverted": False, "values": [signature_uuid]}],
                                     screen=SVS_WORKLIST_SCREEN)
    return render_template("svs/worklist_signature.html", signature_uuid=signature_uuid, worklist_f=worklist_f,
                           **_urls())
