from flask import abort, redirect, render_template, url_for
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import svs
from saq.gui.filter_screens import SVS_RUNS_SCREEN
from saq.util.uuid import UUID_REGEX

def _page_context(view: str) -> dict:
    # each row links to its run page; the script puts the run id in place of __RUN__
    return {"view": view, "runs_screen": SVS_RUNS_SCREEN.name,
            "run_url": url_for("svs.run_detail", run_id="__RUN__")}


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


@svs.route("/runs/<run_id>", methods=["GET"])
def run_detail(run_id: str):
    # the run page (docs/SVS.md, Part 5, *The run page*): a shell over /api/v2/svs/runs/{run_id} and
    # what hangs off it. Each action follows its permission in the template, and the API enforces
    # them regardless. A run that doesn't exist is the script's 404, from the API.
    if not UUID_REGEX.fullmatch(run_id):
        abort(404)
    return render_template("svs/run.html", run_id=run_id.lower(), runs_screen=SVS_RUNS_SCREEN.name)
