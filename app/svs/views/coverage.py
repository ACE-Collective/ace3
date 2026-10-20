from flask import abort, render_template, url_for
from flask_login import current_user

from aceapi_v2.saved_filters.service import ensure_default_saved_filters
from aceapi_v2.sync import run_async_with_session
from app.blueprints import svs
from saq.gui.filter_screens import (
    SVS_COVERAGE_HISTORY_SCREEN,
    SVS_COVERAGE_SCREEN,
    SVS_RUNS_SCREEN,
    SVS_TESTS_SCREEN,
)
from saq.gui.filter_url import encode_filter_query
from saq.svs.attack import AttackCatalog, get_attack_catalog, normalize_technique_id

# the drill-down's History section reads this much of the daily snapshots
HISTORY_RANGE = "-365d"


def _attack_names(catalog: AttackCatalog) -> dict:
    # coverage rows carry platform slugs and tactic ids; the pages show ATT&CK's names for them, from
    # the pinned release the rows were computed against
    return {
        "release": catalog.release,
        "platforms": catalog.platforms,
        "tactics": {tactic.id: tactic.name for tactic in catalog.tactics},
    }


@svs.route("/coverage", methods=["GET"])
def coverage():
    # ATT&CK coverage per technique and platform (docs/SVS_COVERAGE.md, *In the GUI*): a shell over
    # /api/v2/svs/coverage, whose filters and saved filters are the svs_coverage screen's. Like the
    # Runs and Tests tabs, a user new to the screen gets its default saved filters, and only this real
    # page render writes them.
    run_async_with_session(ensure_default_saved_filters, current_user.id, screen=SVS_COVERAGE_SCREEN.name)
    # each row links to its technique's drill-down; the script puts the id in place of __TECHNIQUE__
    return render_template("svs/coverage.html", coverage_screen=SVS_COVERAGE_SCREEN.name,
                           technique_url=url_for("svs.coverage_detail", technique="__TECHNIQUE__"),
                           attack=_attack_names(get_attack_catalog()))


@svs.route("/coverage/<technique>", methods=["GET"])
def coverage_detail(technique: str):
    # one technique's coverage: its rows and its sub-techniques', the tests and signatures that count
    # toward them, and its history. A shell over /api/v2/svs/coverage/{technique} and the snapshots;
    # a technique nothing covers and the release doesn't have is the script's 404, from the API.
    normalized = normalize_technique_id(technique)
    if normalized is None:
        abort(404)
    catalog = get_attack_catalog()
    # the API answers a revoked id for its successor, and the rows, tests, runs and snapshots are all
    # kept under the successor, so the links are built on it
    resolved = catalog.resolve(normalized).technique
    level = "sub-technique" if "." in resolved else "technique"
    technique_filter = {"name": "Technique", "inverted": False, "values": [resolved]}
    tests_f = encode_filter_query([technique_filter], screen=SVS_TESTS_SCREEN)
    runs_f = encode_filter_query([technique_filter], screen=SVS_RUNS_SCREEN)
    # the Technique filter finds a parent's sub-techniques too; Level keeps them out of its history
    history_f = encode_filter_query([technique_filter,
                                     {"name": "Level", "inverted": False, "values": [level]},
                                     {"name": "Date", "inverted": False, "values": [HISTORY_RANGE]}],
                                    screen=SVS_COVERAGE_HISTORY_SCREEN)
    return render_template("svs/coverage_detail.html", technique=normalized, tests_f=tests_f, runs_f=runs_f,
                           history_f=history_f, attack=_attack_names(catalog),
                           technique_url=url_for("svs.coverage_detail", technique="__TECHNIQUE__"),
                           test_url=url_for("svs.test_detail", guid="__TEST__"),
                           run_url=url_for("svs.run_detail", run_id="__RUN__"),
                           signature_url=url_for("svs.worklist_signature", signature_uuid="__SIGNATURE__"))
