from flask import abort, render_template, url_for
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import svs
from saq.gui.filter_screens import SVS_RUNS_SCREEN, SVS_TESTS_SCREEN
from saq.gui.filter_url import encode_filter_query
from saq.util.uuid import UUID_REGEX


@svs.route("/tests", methods=["GET"])
def tests():
    # the Atomic Red Team catalog, one row per test with its state (docs/SVS.md, Part 5, *Tests*): a
    # shell over /api/v2/svs/tests, whose filters and saved filters are the svs_tests screen's. Like
    # the Runs tab, a user new to the screen gets its default saved filters, and only this real page
    # render writes them.
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_TESTS_SCREEN.name)
    # each row links to its test page and its runs; the script puts the id in place of __TEST__ / __RUN__
    return render_template("svs/tests.html", tests_screen=SVS_TESTS_SCREEN.name,
                           test_url=url_for("svs.test_detail", guid="__TEST__"),
                           run_url=url_for("svs.run_detail", run_id="__RUN__"))


@svs.route("/tests/<guid>", methods=["GET"])
def test_detail(guid: str):
    # one test: its catalog entry, its observation window, expectations and ignores, and its runs. A
    # shell over /api/v2/svs/tests/{guid} and the listings filtered on it; a test the catalog doesn't
    # have is the script's 404, from the API. Each action follows its permission in the template, and
    # the API enforces them regardless.
    if not UUID_REGEX.fullmatch(guid):
        abort(404)
    guid = guid.lower()
    # the runs screen's filter on this test: the page lists its latest runs with it, and links the
    # Runs tab filtered on it
    runs_f = encode_filter_query([{"name": "Test", "inverted": False, "values": [guid]}], screen=SVS_RUNS_SCREEN)
    return render_template("svs/test.html", guid=guid, runs_f=runs_f,
                           run_url=url_for("svs.run_detail", run_id="__RUN__"))
