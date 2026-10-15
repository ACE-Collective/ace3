// The SVS banner of the alert page (app/templates/analysis/_svs_alert_banner.html; docs/SVS_RUNS.md,
// *Test alerts in the alert list and on the alert page*): with alert:write, an analyst gives a test
// alert back to analysts. Disassociate from run removes its attributions to every run that holds
// it; Not a test does the same for a TEST? alert, one held by context alone. Both ask for a reason,
// call /api/v2/alerts/{uuid}/svs/{action} and reload the page, which then shows where the alert
// went. Values are placed as text, never markup.

(function() {
    "use strict";

    const ACTIONS = {
        "disassociate": {
            title: "Disassociate from its test run?",
            title_many: "Disassociate from its test runs?",
            submit: "Disassociate",
            text: "The alert is given back to analysts. Its attributions to the run are removed, and the run never " +
                  "attributes it again. A SIMULATED alert is set back to OPEN, and an open alert nobody else has " +
                  "taken goes back to the queue SVS took it from. The run's result is recomputed.",
            text_many: "The alert is given back to analysts. Its attributions to each of its runs are removed, and none " +
                       "of them attributes it again. A SIMULATED alert is set back to OPEN, and an open alert nobody " +
                       "else has taken goes back to the queue SVS took it from. The runs' results are recomputed.",
        },
        "not-a-test": {
            title: "Not a test?",
            submit: "Not a test",
            text: "The run holds this alert by context alone (its host and time), without a marker. Marked not a test, " +
                  "it is given back to analysts like a disassociated alert, and the run never attributes it again.",
        },
    };

    function start(banner) {
        const modal = document.getElementById("svs_alert_modal");
        if (!modal) {
            return;
        }
        const form = document.getElementById("svs_alert_form");
        const reason = document.getElementById("svs_alert_reason");
        const error = document.getElementById("svs_alert_modal_error");
        const submit = document.getElementById("svs_alert_submit");
        const path = "/alerts/" + encodeURIComponent(banner.dataset.alertUuid) + "/svs/";
        let action = null;

        function show_error(text) {
            error.textContent = text || "";
            error.classList.toggle("d-none", !text);
        }

        banner.querySelectorAll("[data-svs-action]").forEach(function(button) {
            button.addEventListener("click", function() {
                action = button.dataset.svsAction;
                const info = ACTIONS[action];
                const many = Number(banner.dataset.runCount) > 1 && info.title_many;
                document.getElementById("svs_alert_modal_title").textContent = many ? info.title_many : info.title;
                document.getElementById("svs_alert_modal_text").textContent = many ? info.text_many : info.text;
                submit.textContent = info.submit;
                reason.value = "";
                show_error("");
                bootstrap.Modal.getOrCreateInstance(modal).show();
            });
        });

        form.addEventListener("submit", function(event) {
            event.preventDefault();
            submit.disabled = true;
            show_error("");
            aceApi.post(path + action, {reason: reason.value.trim() || null})
                .then(function() { window.location.reload(); })
                .catch(function(err) {
                    submit.disabled = false;
                    show_error(err.message);
                });
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const banner = document.getElementById("svs_alert_banner");
        if (banner) {
            start(banner);
        }
    });
})();
