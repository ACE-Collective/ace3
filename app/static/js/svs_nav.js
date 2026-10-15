// The SVS entry of the navigation bar: how many test runs need attention (docs/SVS_RUNS.md,
// *Following runs*), read once per page from GET /api/v2/svs/runs/count. Nothing is shown when no
// run does, or when the count can't be read.

(function() {
    "use strict";

    const target = document.getElementById("svs_nav_count");
    if (!target || !target.dataset.countUrl) {
        return;
    }

    fetch(target.dataset.countUrl, {credentials: "same-origin", headers: {"Accept": "application/json"}})
        .then(function(response) { return response.ok ? response.json() : null; })
        .then(function(result) {
            if (result && result.count > 0) {
                target.textContent = "(" + result.count + ")";
            }
        })
        .catch(function() {});
})();
