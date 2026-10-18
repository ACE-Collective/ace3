// SVS -> Test hosts (docs/SVS_RUNS.md, *Test hosts*): the hosts test runs may target, and adding,
// changing and deleting them. A shell over /api/v2/svs/test-hosts, which needs svs:admin for a
// change, as the tab does. Every value shown was typed by a person or sent by a launcher, so it is
// placed as text, never markup.

(function() {
    "use strict";

    const PAGE_SIZE = 50;

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

    function show(element, message) {
        element.textContent = message || "";
        element.classList.toggle("d-none", !message);
    }

    // the lines of a textarea, blank ones left out
    function lines(text) {
        return text.split(/[\r\n,]+/).map(function(line) { return line.trim(); }).filter(Boolean);
    }

    function start(page) {
        const path = page.dataset.api.substring(aceApi.BASE.length);
        const rows = document.getElementById("svs_test_hosts_rows");
        const error = document.getElementById("svs_test_hosts_error");
        const previous = document.getElementById("svs_test_hosts_previous");
        const next = document.getElementById("svs_test_hosts_next");

        const form = document.getElementById("svs_test_host_form");
        const modal = document.getElementById("svs_test_host_modal");
        const form_error = document.getElementById("svs_test_host_error");
        const delete_modal = document.getElementById("svs_test_host_delete_modal");
        const delete_error = document.getElementById("svs_test_host_delete_error");

        const state = {cursors: [null], page: 0, editing: null, deleting: null};

        function message_row(text) {
            const row = el("tr");
            const cell = el("td", "text-muted", text);
            cell.colSpan = 8;
            row.appendChild(cell);
            rows.replaceChildren(row);
        }

        function host_row(host) {
            const row = el("tr");
            row.appendChild(el("td", "fw-semibold", host.hostname));
            row.appendChild(el("td", "text-break-all", host.fqdn || ""));
            row.appendChild(el("td", null, host.platform || ""));
            const users = el("td", "text-break-all", host.usernames.length ? host.usernames.join(", ") : "any");
            if (!host.usernames.length) {
                users.classList.add("text-muted");
            }
            row.appendChild(users);
            row.appendChild(el("td", "text-break-all", host.ips.join(", ")));
            row.appendChild(el("td", "text-break-all", host.notes || ""));
            const updated = el("td", "text-nowrap", date(host.updated_at));
            updated.title = host.created_by ? "added by " + host.created_by : "";
            row.appendChild(updated);

            const actions = el("td", "text-nowrap text-end");
            const edit = el("button", "btn btn-xs btn-outline-dark me-1");
            edit.type = "button";
            edit.title = "Change this test host";
            edit.appendChild(el("span", "bi bi-pencil"));
            edit.addEventListener("click", function() { open_form(host); });
            const remove = el("button", "btn btn-xs btn-outline-danger");
            remove.type = "button";
            remove.title = "Delete this test host";
            remove.appendChild(el("span", "bi bi-trash3"));
            remove.addEventListener("click", function() { open_delete(host); });
            actions.append(edit, remove);
            row.appendChild(actions);
            return row;
        }

        function load() {
            show(error, "");
            message_row("Loading…");
            const params = {limit: PAGE_SIZE, cursor: state.cursors[state.page] || undefined};
            return aceApi.get(path + "/" + aceApi.query(params))
                .then(function(result) {
                    state.cursors = state.cursors.slice(0, state.page + 1);
                    if (result.next_cursor) {
                        state.cursors.push(result.next_cursor);
                    }
                    if (result.data.length === 0) {
                        message_row(state.page === 0 ? "There are no test hosts yet." : "No more test hosts.");
                    } else {
                        rows.replaceChildren.apply(rows, result.data.map(host_row));
                    }
                    previous.disabled = state.page === 0;
                    next.disabled = state.cursors.length <= state.page + 1;
                })
                .catch(function(err) {
                    message_row("");
                    show(error, "Unable to load the test hosts: " + err.message);
                });
        }

        function reload_first() {
            state.cursors = [null];
            state.page = 0;
            return load();
        }

        previous.addEventListener("click", function() {
            state.page -= 1;
            load();
        });
        next.addEventListener("click", function() {
            state.page += 1;
            load();
        });

        //
        // adding and changing
        //

        function field(name) {
            return form.elements.namedItem(name);
        }

        function open_form(host) {
            state.editing = host;
            show(form_error, "");
            document.getElementById("svs_test_host_title").textContent =
                host ? "Change test host " + host.hostname : "Add a test host";
            field("hostname").value = host ? host.hostname : "";
            field("fqdn").value = host ? host.fqdn || "" : "";
            field("platform").value = host ? host.platform || "" : "";
            field("usernames").value = host ? host.usernames.join("\n") : "";
            field("ips").value = host ? host.ips.join("\n") : "";
            field("notes").value = host ? host.notes || "" : "";
            bootstrap.Modal.getOrCreateInstance(modal).show();
        }

        document.getElementById("svs_test_host_add").addEventListener("click", function() { open_form(null); });

        form.addEventListener("submit", function(event) {
            event.preventDefault();
            show(form_error, "");
            const body = {
                hostname: field("hostname").value.trim(),
                fqdn: field("fqdn").value.trim() || null,
                platform: field("platform").value || null,
                usernames: lines(field("usernames").value),
                ips: lines(field("ips").value),
                notes: field("notes").value.trim() || null,
            };
            // a change applies only to the host as this form loaded it, not over someone else's change
            const request = state.editing
                ? aceApi.put(path + "/" + state.editing.id, body, {"If-Match": state.editing.updated_at})
                : aceApi.post(path + "/", body);
            request
                .then(function() {
                    bootstrap.Modal.getOrCreateInstance(modal).hide();
                    return state.editing ? load() : reload_first();
                })
                .catch(function(err) {
                    if (err.status === 412) {
                        show(form_error, err.message + ". Close this form and open the host again to see " +
                                         "the change; your edits were not saved.");
                        return load();
                    }
                    show(form_error, err.message);
                });
        });

        //
        // deleting
        //

        function open_delete(host) {
            state.deleting = host;
            show(delete_error, "");
            document.getElementById("svs_test_host_delete_text").textContent =
                "Delete " + host.hostname + "? A run registered against it from now on is refused, and its " +
                "addresses no longer attribute alerts to runs by context.";
            bootstrap.Modal.getOrCreateInstance(delete_modal).show();
        }

        document.getElementById("svs_test_host_delete_submit").addEventListener("click", function() {
            show(delete_error, "");
            aceApi.del(path + "/" + state.deleting.id)
                .then(function() {
                    bootstrap.Modal.getOrCreateInstance(delete_modal).hide();
                    return load();
                })
                .catch(function(err) { show(delete_error, err.message); });
        });

        load();
    }

    document.addEventListener("DOMContentLoaded", function() {
        const page = document.getElementById("svs_test_hosts_page");
        if (page) {
            start(page);
        }
    });
})();
