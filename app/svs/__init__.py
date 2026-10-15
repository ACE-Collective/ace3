"""The /svs GUI area: the test half of the Signature Validation System (docs/SVS.md, Part 5).

One area with a tab per screen (app/svs/views/tabs.py). Only page views live here: every page gets
its data from aceapi_v2, called directly from the browser; Flask renders the page shell and nothing
else. The YARA half of SVS (Samples, Validations) lives in the Signatures area.
"""

# Imported first so its before_request guard is registered on the blueprint: `svs:run_read` gates
# the whole area, and a page can layer its own permission on top.
from app.svs.views import access  # noqa: F401
from app.svs.views.runs import batches, runs, svs_home
from app.svs.views.tabs import svs_tab_context
from app.svs.views.test_hosts import test_hosts

__all__ = [
    'batches',
    'runs',
    'svs_home',
    'svs_tab_context',
    'test_hosts',
]
