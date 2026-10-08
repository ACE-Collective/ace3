from flask import render_template
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import signatures
from saq.configuration.config import get_config
from saq.gui.filter_screens import SVS_SAMPLES_SCREEN


def _page_context() -> dict:
    return {
        "samples_screen": SVS_SAMPLES_SCREEN.name,
        "max_bulk_download_files": get_config().svs.samples.max_bulk_download_files,
    }


@signatures.route("/samples", methods=["GET"])
def samples():
    # the page is a shell: its scripts load everything from /api/v2/svs/samples, and its filters
    # and saved filters from /api/v2/filter-screens and /api/v2/saved-filters (screen
    # svs_samples). The signature:read gate is the blueprint's; the download controls follow
    # has_permission('signature', 'download') in the template, and the API enforces it regardless.
    #
    # A user new to the screen gets its default saved filters. This writes, which is why only
    # this real page render calls it (as the alert manage page does).
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_SAMPLES_SCREEN.name)
    return render_template("signatures/samples.html", **_page_context())


@signatures.route("/samples/<sha256>/<rule_uuid>", methods=["GET"])
def sample_detail(sha256: str, rule_uuid: str):
    # the API validates the key and answers 400 or 404, which the page shows
    return render_template("signatures/sample_detail.html", sha256=sha256, rule_uuid=rule_uuid, **_page_context())
