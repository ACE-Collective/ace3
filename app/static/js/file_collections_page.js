// File Collections: the files the file collectors have been asked to fetch from hosts, and the
// analyst's actions on the requests.
//
// The page is a shell over /api/v2/file-collections, called from the browser with the Flask
// session cookie. The list is a FilterListPage (filter_list_page.js) on the file_collections
// filter screen, with a checkbox per row. Retry, Cancel and Delete act on the selected requests
// they apply to, one request each, and report what they did and any request the API refused.
// Every value shown came from the database or from analyzed data, so it is placed as text, never
// markup.

(function() {
    "use strict";

    const API = "/file-collections";

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

    function result_node(result, message) {
        const css = result === "SUCCESS" ? "text-success" : (result === "ERROR" || result === "FAILED") ? "text-danger" : null;
        const node = el("span", css, result || "");
        if (message) {
            node.title = message;
        }
        return node;
    }

    // what each selection action does, and to which requests it applies (the API decides again,
    // and refuses the others)
    const ACTIONS = {
        retry: {
            applies: function() { return true; },
            request: function(row) { return aceApi.post(API + "/" + row.id + "/retry"); },
            done: "retried",
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
                return "Delete " + plural(count, "file collection request") + ", with their history?";
            },
        },
    };

    // runs an action on the selected requests it applies to, one request each, then reports and
    // reloads the page that is shown
    function run(action, selected, list) {
        const rows = selected.filter(action.applies);
        if (rows.length === 0 || (action.confirm && !window.confirm(action.confirm(rows.length)))) {
            return;
        }

        Promise.allSettled(rows.map(action.request)).then(function(results) {
            const failures = results.filter(function(result) { return result.status === "rejected"; })
                .map(function(result) { return result.reason.message; });
            let message = action.done + " " + plural(rows.length - failures.length, "file collection request");
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
        const counter = document.getElementById("file_collections_selection");
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
                button.disabled = rows.filter(ACTIONS[button.dataset.action].applies).length === 0;
            });
            counter.textContent = rows.length ? rows.length + " selected" : "";
        };
    }

    //
    // a request's history
    //

    function show_history(row) {
        const title = document.getElementById("file_collection_history_title");
        const body = document.getElementById("file_collection_history_body");
        title.textContent = "History of file collection " + row.id + ": " + row.observable_type + " " + row.observable_value;
        body.replaceChildren(el("div", "text-muted", "Loading…"));
        bootstrap.Modal.getOrCreateInstance(document.getElementById("file_collection_history_modal")).show();

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
    // the list
    //

    function start(page) {
        const can_write = page.dataset.canWrite === "true";
        const alert_url = page.dataset.alertUrl;
        // the actions reach the list through this, since the list is created after them
        const list_ref = {list: null};

        // the columns fit their content (fitColumns): only Value wraps
        const columns = [
            {label: "ID", css: "text-nowrap", render: function(row) { return row.id; }},
            {label: "Created", css: "text-nowrap", title: "UTC", render: function(row) { return date(row.insert_date); }},
            {label: "Collector", css: "text-nowrap", render: function(row) { return row.collector; }},
            {label: "Type", css: "text-nowrap", render: function(row) { return row.observable_type; }},
            {label: "Value", css: "text-break-all", render: function(row) { return row.observable_value; }},
            {label: "Alert", css: "text-nowrap", render: function(row) {
                if (!row.alert_uuid) {
                    return "";
                }
                const link = el("a");
                link.href = alert_url + "?direct=" + encodeURIComponent(row.alert_uuid);
                link.title = row.alert_uuid;
                link.setAttribute("aria-label", "the alert " + row.alert_uuid);
                link.appendChild(el("span", "bi bi-box-arrow-up-right"));
                return link;
            }},
            {label: "Status", css: "text-nowrap", render: function(row) { return row.status; }},
            {label: "Result", css: "text-nowrap", title: "hover for the collector's message", render: function(row) {
                return result_node(row.result, row.result_message);
            }},
            {label: "Attempts", css: "text-nowrap", render: function(row) { return row.retry_count + " / " + row.max_retries; }},
            {label: "", css: "text-nowrap", render: function(row) {
                const button = el("button", "btn btn-xs btn-outline-dark");
                button.type = "button";
                button.title = "history";
                button.setAttribute("aria-label", "history of file collection " + row.id);
                button.appendChild(el("span", "bi bi-clock-history"));
                button.addEventListener("click", function() { show_history(row); });
                return button;
            }},
        ];

        list_ref.list = FilterListPage.create({
            root: document.getElementById("file_collections_list"),
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
            emptyText: "No file collection requests match these filters.",
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const page = document.getElementById("file_collections_page");
        if (page) {
            start(page);
        }
    });
})();
