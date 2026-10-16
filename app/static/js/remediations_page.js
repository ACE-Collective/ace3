// Remediations: what the remediation service has been asked to remove or restore, and the
// analyst's actions on it.
//
// The page is a shell over /api/v2/remediation, called from the browser with the Flask session
// cookie. The list is a FilterListPage (filter_list_page.js) on the remediations filter screen,
// with a checkbox per row. Restore, Retry, Cancel and Delete act on the selected remediations
// they apply to, one request each, and report what they did and any request the API refused.
// Add Remediation looks up the remediation targets of the observables it is given, shows them,
// and queues a removal of each. Every value shown came from the database or from analyzed data,
// so it is placed as text, never markup.

(function() {
    "use strict";

    const API = "/remediation/remediations";

    // how many refusals a report lists before it only counts the rest
    const MAX_REPORTED_FAILURES = 5;

    function el(tag, css, text) {
        const element = document.createElement(tag);
        if (css) {
            element.className = css;
        }
        if (text !== undefined && text !== null) {
            element.textContent = String(text);
        }
        return element;
    }

    function date(value) {
        if (!value) {
            return "";
        }
        return value.replace("T", " ").replace(/\.\d+$/, "").replace(/(Z|\+00:00)$/, "");
    }

    function plural(count, word) {
        return count + " " + word + (count === 1 ? "" : "s");
    }

    function result_node(result) {
        const css = result === "SUCCESS" ? "text-success" : (result === "ERROR" || result === "FAILED") ? "text-danger" : null;
        return el("span", css, result || "");
    }

    // what each selection action does, and to which remediations it applies (the API decides
    // again, and refuses the others)
    const ACTIONS = {
        restore: {
            applies: function(row) { return row.action === "remove" && row.status === "COMPLETED" && row.result === "SUCCESS"; },
            request: function(row) { return aceApi.post(API + "/" + row.id + "/restore"); },
            done: "queued a restore of",
            skipped: "not a removal that succeeded",
        },
        retry: {
            applies: function(row) { return row.status === "COMPLETED"; },
            request: function(row) { return aceApi.post(API + "/" + row.id + "/retry"); },
            done: "retried",
            skipped: "not completed",
        },
        cancel: {
            applies: function(row) { return row.status !== "COMPLETED"; },
            request: function(row) { return aceApi.post(API + "/" + row.id + "/cancel"); },
            done: "stopped",
            skipped: "already completed",
        },
        delete: {
            applies: function() { return true; },
            request: function(row) { return aceApi.del(API + "/" + row.id); },
            done: "deleted",
            confirm: function(count) {
                return "Delete the records of " + plural(count, "remediation") + ", with their history? " +
                       "This does not undo what they did.";
            },
        },
    };

    // runs an action on the selected remediations it applies to, one request each, then reports
    // and reloads the page that is shown
    function run(action, selected, list) {
        const rows = selected.filter(action.applies);
        if (rows.length === 0 || (action.confirm && !window.confirm(action.confirm(rows.length)))) {
            return;
        }

        Promise.allSettled(rows.map(action.request)).then(function(results) {
            const failures = results.filter(function(result) { return result.status === "rejected"; })
                .map(function(result) { return result.reason.message; });
            let message = action.done + " " + plural(rows.length - failures.length, "remediation");
            const skipped = selected.length - rows.length;
            if (skipped > 0) {
                message += "; left " + skipped + " alone (" + action.skipped + ")";
            }
            if (failures.length > 0) {
                message += "; refused: " + failures.slice(0, MAX_REPORTED_FAILURES).join("; ");
                if (failures.length > MAX_REPORTED_FAILURES) {
                    message += "; and " + (failures.length - MAX_REPORTED_FAILURES) + " more";
                }
            }
            show_flash_message(message);
            return list.refresh();
        });
    }

    function setup_actions(page, list_ref) {
        const buttons = page.querySelectorAll("button[data-action]");
        const counter = document.getElementById("remediations_selection");
        let selected = [];

        buttons.forEach(function(button) {
            button.addEventListener("click", function() {
                run(ACTIONS[button.dataset.action], selected, list_ref.list);
            });
        });

        // the list calls this after every change of the selection
        return function(rows) {
            selected = rows;
            buttons.forEach(function(button) {
                const count = rows.filter(ACTIONS[button.dataset.action].applies).length;
                button.disabled = count === 0;
            });
            counter.textContent = rows.length ? rows.length + " selected" : "";
        };
    }

    //
    // a remediation's history
    //

    function show_history(row) {
        const title = document.getElementById("remediation_history_title");
        const body = document.getElementById("remediation_history_body");
        title.textContent = "History of remediation " + row.id + ": " + row.action + " " + row.observable_type + " " +
                            row.observable_value;
        body.replaceChildren(el("div", "text-muted", "Loading…"));
        bootstrap.Modal.getOrCreateInstance(document.getElementById("remediation_history_modal")).show();

        aceApi.get(API + "/" + row.id + "/history")
            .then(function(result) {
                if (result.data.length === 0) {
                    body.replaceChildren(el("div", "text-muted", "No attempts yet."));
                    return;
                }
                const table = el("table", "table table-sm table-striped");
                const head = table.createTHead().insertRow();
                ["Time (UTC)", "Status", "Result", "Message"].forEach(function(label) {
                    head.appendChild(el("th", null, label));
                });
                const rows = table.createTBody();
                result.data.forEach(function(entry) {
                    const tr = rows.insertRow();
                    tr.appendChild(el("td", "text-nowrap", date(entry.insert_date)));
                    tr.appendChild(el("td", null, entry.status));
                    tr.appendChild(el("td")).appendChild(result_node(entry.result));
                    tr.appendChild(el("td", "text-break", entry.message));
                });
                body.replaceChildren(table);
            })
            .catch(function(err) {
                body.replaceChildren(el("div", "alert alert-danger", "Unable to load the history: " + err.message));
            });
    }

    //
    // Add Remediation
    //

    function setup_add_remediation(list_ref) {
        const open = document.getElementById("btn_add_remediation");
        if (!open) {
            return;
        }
        const modal_element = document.getElementById("add_remediation_modal");
        const type_input = document.getElementById("add_remediation_type");
        const values_input = document.getElementById("add_remediation_values");
        const error = document.getElementById("add_remediation_error");
        const targets_area = document.getElementById("add_remediation_targets");
        const lookup = document.getElementById("btn_lookup_remediation_targets");
        const queue = document.getElementById("btn_queue_remediations");
        let targets = [];

        function show_error(message) {
            error.textContent = message || "";
            error.classList.toggle("d-none", !message);
        }

        // the targets found are for what the inputs said when they were looked up
        function clear_targets() {
            targets = [];
            targets_area.replaceChildren();
            queue.disabled = true;
            queue.textContent = "Remediate";
        }

        function values() {
            const seen = new Set();
            return values_input.value.split(/\r\n|\r|\n/)
                .map(function(value) { return value.trim(); })
                .filter(function(value) {
                    if (!value || seen.has(value)) {
                        return false;
                    }
                    seen.add(value);
                    return true;
                });
        }

        function render_targets() {
            if (targets.length === 0) {
                targets_area.replaceChildren(el("div", "text-muted", "No remediator handles these values."));
                return;
            }
            const table = el("table", "table table-sm table-striped");
            const head = table.createTHead().insertRow();
            ["Remediator", "Type", "Value", "Latest remediation"].forEach(function(label) {
                head.appendChild(el("th", null, label));
            });
            const rows = table.createTBody();
            targets.forEach(function(target) {
                const tr = rows.insertRow();
                tr.appendChild(el("td", null, target.remediator_display_name || target.remediator));
                tr.appendChild(el("td", null, target.observable_type));
                tr.appendChild(el("td", "text-break", target.observable_value));
                const current = target.current;
                tr.appendChild(el("td", null, current ? [current.action, current.status, current.result].filter(Boolean).join(" ") : ""));
            });
            targets_area.replaceChildren(el("div", "mb-1", "A removal of each of these will be queued:"), table);
            queue.disabled = false;
            queue.textContent = "Remediate " + plural(targets.length, "target");
        }

        open.addEventListener("click", function() {
            type_input.value = "";
            values_input.value = "";
            show_error("");
            clear_targets();
            bootstrap.Modal.getOrCreateInstance(modal_element).show();
        });

        type_input.addEventListener("input", clear_targets);
        values_input.addEventListener("input", clear_targets);

        lookup.addEventListener("click", function() {
            const type = type_input.value.trim();
            const given = values();
            show_error("");
            clear_targets();
            if (!type || given.length === 0) {
                show_error("Enter a type and at least one value.");
                return;
            }

            lookup.disabled = true;
            aceApi.post("/remediation/targets/lookup", {
                observables: given.map(function(value) { return {type: type, value: value}; }),
            })
                .then(function(result) {
                    targets = result.data;
                    render_targets();
                })
                .catch(function(err) { show_error(err.message); })
                .finally(function() { lookup.disabled = false; });
        });

        queue.addEventListener("click", function() {
            queue.disabled = true;
            aceApi.post(API, {
                action: "remove",
                targets: targets.map(function(target) {
                    return {remediator: target.remediator, observable_type: target.observable_type,
                            observable_value: target.observable_value};
                }),
            })
                .then(function(result) {
                    bootstrap.Modal.getOrCreateInstance(modal_element).hide();
                    show_flash_message("queued " + plural(result.data.length, "removal"));
                    return list_ref.list.reload();
                })
                .catch(function(err) {
                    show_error(err.message);
                    queue.disabled = false;
                });
        });
    }

    //
    // the list
    //

    function start(page) {
        const can_write = page.dataset.canWrite === "true";
        // the actions reach the list through this, since the list is created after them
        const list_ref = {list: null};

        // the columns fit their content (fitColumns): only Value wraps
        const columns = [
            {label: "ID", css: "text-nowrap", render: function(row) { return row.id; }},
            {label: "Created", css: "text-nowrap", title: "UTC", render: function(row) { return date(row.insert_date); }},
            {label: "Remediator", css: "text-nowrap", render: function(row) { return row.remediator; }},
            {label: "Type", css: "text-nowrap", render: function(row) { return row.observable_type; }},
            {label: "Value", css: "text-break-all", render: function(row) { return row.observable_value; }},
            {label: "Analyst", css: "text-nowrap", render: function(row) { return row.analyst || ""; }},
            {label: "Action", css: "text-nowrap", render: function(row) { return row.action; }},
            {label: "Status", css: "text-nowrap", render: function(row) { return row.status; }},
            {label: "Result", css: "text-nowrap", render: function(row) { return result_node(row.result); }},
            {label: "", css: "text-nowrap", render: function(row) {
                const button = el("button", "btn btn-xs btn-outline-dark");
                button.type = "button";
                button.title = "history";
                button.setAttribute("aria-label", "history of remediation " + row.id);
                button.appendChild(el("span", "bi bi-clock-history"));
                button.addEventListener("click", function() { show_history(row); });
                return button;
            }},
        ];

        list_ref.list = FilterListPage.create({
            root: document.getElementById("remediations_list"),
            screen: page.dataset.screen,
            api: API,
            columns: columns,
            fitColumns: true,
            // the API has one order, newest first
            defaultSort: null,
            defaultDesc: true,
            pageSizes: [25, 50, 100, 250],
            defaultLimit: 50,
            tz: page.dataset.tz,
            exports: ["csv", "ndjson"],
            download: null,
            select: can_write ? {key: function(row) { return row.id; }, onChange: setup_actions(page, list_ref)} : null,
            emptyText: "No remediations match these filters.",
        });

        if (can_write) {
            setup_add_remediation(list_ref);
        }
    }

    document.addEventListener("DOMContentLoaded", function() {
        const page = document.getElementById("remediations_page");
        if (page) {
            start(page);
        }
    });
})();
