from flask import render_template
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import signatures
from saq.gui.filter_screens import SVS_VALIDATIONS_SCREEN


def _page_context() -> dict:
    return {"validations_screen": SVS_VALIDATIONS_SCREEN.name}


@signatures.route("/validations", methods=["GET"])
def validations():
    # the page is a shell: its scripts load everything from /api/v2/svs/yara/validations, and its
    # filters and saved filters from /api/v2/filter-screens and /api/v2/saved-filters (screen
    # svs_validations). The signature:read gate is the blueprint's; the download controls follow
    # has_permission('signature', 'download') in the template, and the API enforces it regardless.
    #
    # A user new to the screen gets its default saved filters. This writes, which is why only
    # this real page render calls it (as the alert manage page does).
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_VALIDATIONS_SCREEN.name)
    return render_template("signatures/validations.html", **_page_context())


@signatures.route("/validations/<validation_uuid>", methods=["GET"])
def validation_detail(validation_uuid: str):
    # the report CI links to (aceapi_v2/svs/yara/validations/service.py, report_path); the API
    # validates the uuid and answers 400 or 404, which the page shows
    return render_template("signatures/validation_detail.html", validation_uuid=validation_uuid, **_page_context())
