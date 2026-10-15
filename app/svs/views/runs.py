from flask import current_app, redirect, render_template, url_for
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import svs
from saq.gui.filter_screens import SVS_RUNS_SCREEN

# the run page's endpoint; the rows link to it once it is registered
RUN_DETAIL_ENDPOINT = "svs.run_detail"


def _page_context(view: str) -> dict:
    run_url = ""
    if RUN_DETAIL_ENDPOINT in current_app.view_functions:
        run_url = url_for(RUN_DETAIL_ENDPOINT, run_id="__RUN__")
    return {"view": view, "runs_screen": SVS_RUNS_SCREEN.name, "run_url": run_url}


def _render(view: str):
    # the page is a shell: its scripts load everything from /api/v2/svs/runs, and its filters and
    # saved filters from /api/v2/filter-screens and /api/v2/saved-filters (screen svs_runs). The
    # svs:run_read gate is the blueprint's; the bulk actions follow has_permission('svs',
    # 'run_manage') in the template, and the API enforces it regardless.
    #
    # A user new to the screen gets its default saved filters. This writes, which is why only
    # these real page renders call it (as the alert manage page does).
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_RUNS_SCREEN.name)
    return render_template("svs/runs.html", **_page_context(view))


@svs.route("/", methods=["GET"])
def svs_home():
    return redirect(url_for("svs.runs"))


@svs.route("/runs", methods=["GET"])
def runs():
    return _render("runs")


@svs.route("/runs/batches", methods=["GET"])
def batches():
    # the same runs, one row per batch_id; the filters carry over between the two views
    return _render("batches")
