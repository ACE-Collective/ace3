// Detection verdicts on the alert page (docs/SVS.md, Part 1).
//
// Every detection in the analysis tree and in the Detection Chains card has an empty
// <span class="detection-verdict" data-content-hash="..."> next to it. This fills each one with a
// chip showing the detection's effective verdict (TP/FP) and where it comes from: explicit (an
// analyst said so), inherited (from the alert), or unconfirmed (an inherited TP on an alert where
// several signatures fired). The data comes from GET /api/v2/alerts/{uuid}/detection-points.
//
// On a TP alert an analyst with alert:write can change a chip: mark the detection as noise (FP),
// confirm it as TP, or let it inherit from the alert again. On an FP alert every detection is FP
// and the chip only says how to correct the alert. On an alert whose disposition only ACE sets
// (SIMULATED) the chips are read-only.
//
// It also drives the detection verdict section of the disposition dialog: shown only while a tp
// disposition is selected, with its inputs enabled only once it is opened, so a dialog saved
// without opening it changes no verdict.
//
// The page sets detection_verdicts_alert_uuid (saq_analysis.js owns current_alert_uuid and only
// fills it in once the document is ready), current_alert_disposition_class,
// current_alert_disposition_selectable, selectable_disposition_classes,
// current_user_can_write_alerts and current_user_can_review_alerts. The chips themselves look the
// way verdicts.js draws them, which the page loads first.

(function() {
    "use strict";

    function api_url(content_hash) {
        let url = "/api/v2/alerts/" + encodeURIComponent(detection_verdicts_alert_uuid) + "/detection-points";
        if (content_hash) {
            url += "/" + content_hash + "/verdict";
        }
        return url;
    }

    function request(method, url, body) {
        const options = {method: method, credentials: "same-origin", headers: {}};
        if (body !== undefined) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(body);
        }
        return fetch(url, options).then(function(response) {
            return response.json().then(function(data) {
                if (!response.ok) {
                    throw new Error(data.detail || ("request failed: " + response.status));
                }
                return data;
            });
        });
    }

    function editable() {
        return current_user_can_write_alerts
            && current_alert_disposition_class === "tp"
            && current_alert_disposition_selectable;
    }

    function verdict_badge(row) {
        return aceVerdicts.badge(row.verdict, row.verdict_source);
    }

    // an FP alert: every detection is FP, and a wrong one is fixed by correcting the alert
    function fp_alert_chip() {
        const element = aceVerdicts.chip("FP (from alert)", aceVerdicts.css("fp"),
                              "If the alert was wrong, correct its disposition");
        element.setAttribute("role", "button");
        element.addEventListener("click", function() {
            const target = current_user_can_review_alerts ? "review_modal" : "disposition_modal";
            bootstrap.Modal.getOrCreateInstance(document.getElementById(target)).show();
        });
        return element;
    }

    function menu_item(text, action) {
        const item = document.createElement("li");
        const link = document.createElement("a");
        link.className = "dropdown-item";
        link.href = "#";
        link.textContent = text;
        link.addEventListener("click", function(event) {
            event.preventDefault();
            action();
        });
        item.appendChild(link);
        return item;
    }

    function editable_chip(row) {
        const wrapper = document.createElement("span");
        wrapper.className = "dropdown d-inline-block";

        const toggle = verdict_badge(row);
        toggle.setAttribute("role", "button");
        toggle.setAttribute("data-bs-toggle", "dropdown");
        toggle.setAttribute("aria-expanded", "false");
        toggle.title += " (click to change)";
        wrapper.appendChild(toggle);

        const menu = document.createElement("ul");
        menu.className = "dropdown-menu";
        const set = function(verdict) {
            return function() { change(row.content_hash, "PUT", {verdict: verdict}); };
        };
        if (!(row.verdict === "fp" && row.verdict_source === "explicit")) {
            menu.appendChild(menu_item("Mark as noise (FP)", set("fp")));
        }
        if (!(row.verdict === "tp" && row.verdict_source === "explicit")) {
            menu.appendChild(menu_item("Confirm as TP", set("tp")));
        }
        if (row.override) {
            menu.appendChild(menu_item("Inherit from the alert", function() {
                change(row.content_hash, "DELETE");
            }));
        }
        wrapper.appendChild(menu);
        return wrapper;
    }

    function chip(row) {
        if (!row || !row.verdict) {
            return null;
        }
        if (current_alert_disposition_class === "fp") {
            return fp_alert_chip();
        }
        if (editable()) {
            return editable_chip(row);
        }
        const element = verdict_badge(row);
        if (!current_alert_disposition_selectable) {
            element.title += "; set by ACE, not by analysts";
        }
        return element;
    }

    function render(row, content_hash) {
        document.querySelectorAll('.detection-verdict[data-content-hash="' + content_hash + '"]').forEach(function(slot) {
            const element = chip(row);
            slot.replaceChildren(...(element ? [element] : []));
        });
    }

    function change(content_hash, method, body) {
        request(method, api_url(content_hash), body)
            .then(function(row) { render(row, content_hash); })
            .catch(function(error) { alert("unable to change the verdict: " + error.message); });
    }

    function load() {
        if (!document.querySelector(".detection-verdict")) {
            return;
        }
        request("GET", api_url())
            .then(function(rows) {
                const by_hash = {};
                rows.forEach(function(row) { by_hash[row.content_hash] = row; });
                document.querySelectorAll(".detection-verdict").forEach(function(slot) {
                    const content_hash = slot.dataset.contentHash;
                    render(by_hash[content_hash], content_hash);
                });
            })
            .catch(function(error) { console.error("unable to load detection verdicts", error); });
    }

    // the disposition dialog's detection verdict section
    function bind_disposition_dialog() {
        const section = document.getElementById("detection_verdicts_section");
        if (!section) {
            return;
        }
        const list = document.getElementById("detection_verdicts_list");
        const inputs = section.querySelectorAll("input");
        const set_enabled = function(enabled) {
            inputs.forEach(function(input) { input.disabled = !enabled; });
        };

        document.querySelectorAll('#disposition-form input[name="disposition"]').forEach(function(radio) {
            radio.addEventListener("change", function() {
                const tp = selectable_disposition_classes[radio.value] === "tp";
                section.classList.toggle("d-none", !tp);
                set_enabled(tp && list.classList.contains("show"));
            });
        });

        list.addEventListener("show.bs.collapse", function() { set_enabled(true); });
        list.addEventListener("hide.bs.collapse", function() { set_enabled(false); });
    }

    document.addEventListener("DOMContentLoaded", function() {
        load();
        bind_disposition_dialog();
    });
})();
