// SVS -> Tests (docs/SVS.md, Part 5, *Tests*; docs/SVS_RUNS.md, *In the GUI*): the Atomic Red Team
// catalog, one row per test with its state, and one test's page.
//
// The list is a FilterListPage (filter_list_page.js) over /api/v2/svs/tests on the svs_tests filter
// screen, and opens on the tests still in the catalog. It is read-only, in the API's one order,
// technique then name: ACE doesn't suggest what to run next. The test page is a shell over
// /api/v2/svs: the test's catalog entry (its commands, input arguments and dependencies), its
// observation window, the signatures decided for it and the ignores that apply to it, and its latest
// runs. With svs:run_manage the page sets the observation window and removes decisions and the
// test's ignores; removing a global ignore needs svs:admin. Every value shown came from a catalog, a
// launcher or a person, so it is placed as text, never markup.

(function() {
    "use strict";

    // a test's state on a platform, by its latest reviewed run there; a test's own state is the worst
    // of its platforms' (docs/SVS_RUNS.md, *Tests and their state*)
    const TEST_STATES = {
        never_run: {css: "text-muted", title: "no run was ever registered for it"},
        awaiting_review: {css: "text-warning-emphasis fw-semibold",
                          title: "no run of it is reviewed yet, or something was expected of it only after its latest review"},
        no_expectations: {css: "text-muted", title: "it has a reviewed run, and nothing is expected of it"},
        failing: {css: "text-danger fw-semibold", title: "its latest reviewed run missed an expected signature"},
        stale: {css: "text-warning-emphasis",
                title: "it would be validated, but the test or an expected signature's rule changed since that review"},
        validated: {css: "text-success", title: "its latest reviewed run hit every expected signature"},
    };
    // the worst first: a test's state is the first of these any of its platforms is in
    const WORST_FIRST = ["failing", "stale", "awaiting_review", "validated", "no_expectations"];

    const RUN_STATES = {
        created: {css: "text-muted", title: "registered; the launcher hasn't started it"},
        started: {css: "text-primary", title: "running: its observation window is open"},
        ended: {css: "text-warning-emphasis fw-semibold", title: "the observation window passed; it waits for a review"},
        reviewed: {css: "text-success", title: "signed off"},
        canceled: {css: "text-muted", title: "canceled; it still attributes alerts until its attribution window ends"},
        error: {css: "text-danger fw-semibold", title: "the launcher reported a failure, or never started it"},
        closed: {css: "text-muted", title: "discarded: nothing is learned from it"},
    };

    // the test page lists this many of the test's latest runs, and links the Runs tab for the rest
    const RECENT_RUNS = 25;
    const PAGE_SIZE = 500;
    const MAX_PAGES = 20;

    //
    // helpers
    //

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

    function link(href, text, css) {
        const element = el("a", css || null, text);
        element.href = href;
        return element;
    }

    function append(parent) {
        Array.prototype.slice.call(arguments, 1).forEach(function(child) {
            if (child === null || child === undefined || child === "") {
                return;
            }
            parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
        });
        return parent;
    }

    function button(label, css, title, onclick) {
        const element = el("button", "btn btn-sm " + (css || "btn-outline-dark"), label);
        element.type = "button";
        if (title) {
            element.title = title;
        }
        element.addEventListener("click", onclick);
        return element;
    }

    function date(value) {
        if (!value) {
            return "";
        }
        return value.replace("T", " ").replace(/\.\d+$/, "").replace(/(Z|\+00:00)$/, "");
    }

    function plural(count, noun) {
        return count + " " + noun + (count === 1 ? "" : "s");
    }

    function mono(text, css) {
        return el("span", "font-monospace text-break-all" + (css ? " " + css : ""), text);
    }

    function muted(text) {
        return el("span", "text-muted", text);
    }

    function test_state_node(test) {
        const info = TEST_STATES[test.test_state] || {css: "", title: ""};
        const node = el("div");
        const name = el("span", info.css, test.test_state.replace(/_/g, " "));
        name.title = info.title;
        node.appendChild(name);
        if (test.removed_at) {
            const removed = el("div", "small text-muted", "removed");
            removed.title = "gone from its repository since " + date(test.removed_at) + " UTC; it keeps its runs";
            node.appendChild(removed);
        }
        return node;
    }

    function run_state_node(row) {
        const info = RUN_STATES[row.state] || {css: "", title: ""};
        const node = el("span", info.css, row.state);
        node.title = info.title + (row.error_reason ? ": " + row.error_reason : "") +
            (row.close_reason ? ": " + row.close_reason : "");
        return node;
    }

    // the recent runs that missed an expected signature, of those looked at
    function missing_node(test) {
        if (!test.recent_runs) {
            return muted("–");
        }
        const node = el("span", test.recent_runs_missing ? "text-danger" : null,
                        test.recent_runs_missing + " of " + test.recent_runs);
        node.title = "of its latest " + plural(test.recent_runs, "ended or reviewed run") +
            ", those that missed an expected signature";
        return node;
    }

    function signature_node(row) {
        const node = el("div");
        append(node, row.signature_name || "", row.signature_name ? " " : "");
        const details = el("div", "small text-muted");
        append(details, row.signature_family ? row.signature_family + " · " : "", mono(row.signature_uuid));
        node.appendChild(details);
        return node;
    }

    function table(headers) {
        const element = el("table", "table table-sm align-middle small mb-1");
        const row = el("tr");
        headers.forEach(function(header) {
            row.appendChild(el("th", "fw-normal text-muted", header));
        });
        element.appendChild(append(el("thead"), row));
        element.appendChild(el("tbody"));
        return element;
    }

    function table_row(target, cells) {
        const row = el("tr");
        cells.forEach(function(cell) {
            row.appendChild(append(el("td"), cell));
        });
        target.tBodies[0].appendChild(row);
        return row;
    }

    //
    // the list
    //

    function start_list(page) {
        const data = page.dataset;
        let default_f = [];
        try {
            default_f = JSON.parse(data.defaultF || "[]");
        } catch (e) {
            default_f = [];
        }
        const settings = {
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            default_f: default_f,
            test_url: data.testUrl,
            run_url: data.runUrl,
            tz: data.tz,
        };

        function test_url(guid) {
            return settings.test_url.replace("__TEST__", encodeURIComponent(guid));
        }

        function run_link(run_id, at) {
            if (!run_id) {
                return muted("–");
            }
            return link(settings.run_url.replace("__RUN__", encodeURIComponent(run_id)), date(at) || run_id.substring(0, 8),
                        "small text-nowrap");
        }

        const columns = [
            {label: "Technique", width: "8rem", render: function(row) {
                const node = el("span", "text-nowrap", row.technique);
                if (row.technique_name) {
                    node.title = row.technique_name;
                }
                return node;
            }},
            {label: "Name", render: function(row) {
                const node = el("div");
                node.appendChild(link(test_url(row.guid), row.name));
                node.appendChild(append(el("div", "small"), mono(row.guid, "text-muted")));
                return node;
            }},
            {label: "Platforms", width: "9rem", render: function(row) { return el("span", "small", row.platforms.join(", ")); }},
            {label: "Repository", width: "9rem", render: function(row) { return el("span", "small text-break-all", row.repository); }},
            {label: "State", width: "9rem", title: "on its latest reviewed run", render: test_state_node},
            {label: "Last run", width: "10rem", render: function(row) {
                return run_link(row.last_run_id, row.last_run_at);
            }},
            {label: "Last reviewed", width: "10rem", title: "its latest reviewed run", render: function(row) {
                return run_link(row.last_reviewed_run_id, row.last_reviewed_at);
            }},
            {label: "Runs", width: "4rem", title: "every run registered for it", render: function(row) { return String(row.run_count); }},
            {label: "Expected", width: "5rem", title: "the signatures expected of it", render: function(row) {
                return String(row.expected_signatures);
            }},
            {label: "Missing", width: "5rem", title: "its latest ended or reviewed runs that missed an expected signature",
             render: missing_node},
        ];

        FilterListPage.create({
            root: document.getElementById("svs_tests_list"),
            screen: settings.screen,
            api: settings.path,
            columns: columns,
            // the API has one order, technique then name: there is no suggested order
            defaultSort: null,
            defaultDesc: false,
            pageSizes: [25, 50, 100, 250],
            defaultLimit: 100,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: null,
            emptyText: "No tests match these filters.",
            defaultF: settings.default_f,
        });
    }

    //
    // one test
    //

    function start_detail(page) {
        const data = page.dataset;
        let runs_f = [];
        try {
            runs_f = JSON.parse(data.runsF || "[]");
        } catch (e) {
            runs_f = [];
        }
        const settings = {
            path: data.api.substring(aceApi.BASE.length),
            guid: data.guid,
            runs_f: runs_f,
            runs_url: data.runsUrl,
            run_url: data.runUrl,
            username: data.username,
            can_manage: data.canManage === "true",
            is_admin: data.isAdmin === "true",
        };
        const test_path = settings.path + "/tests/" + encodeURIComponent(settings.guid);
        const state = {};

        function run_url(run_id) {
            return settings.run_url.replace("__RUN__", encodeURIComponent(run_id));
        }

        function show_error(text) {
            const node = document.getElementById("svs_test_error");
            node.textContent = text || "";
            node.classList.toggle("d-none", !text);
        }

        function message(text, css) {
            const node = document.getElementById("svs_test_message");
            node.className = "alert " + (css || "alert-info");
            node.textContent = text || "";
            node.classList.toggle("d-none", !text);
        }

        // every page of a listing
        function all_pages(path, params) {
            const rows = [];
            function next(cursor, count) {
                const query = Object.assign({limit: PAGE_SIZE}, params || {}, {cursor: cursor || undefined});
                return aceApi.get(path + aceApi.query(query)).then(function(result) {
                    Array.prototype.push.apply(rows, result.data);
                    if (result.next_cursor && count < MAX_PAGES) {
                        return next(result.next_cursor, count + 1);
                    }
                    return rows;
                });
            }
            return next(null, 1);
        }

        function load() {
            return Promise.all([
                aceApi.get(test_path),
                all_pages(settings.path + "/expectations/", {test: settings.guid}),
                all_pages(settings.path + "/ignores/", {test: settings.guid}),
                // a 404 is a test without settings: its runs get the computed window
                aceApi.get(test_path + "/settings").catch(function(err) {
                    if (err.status === 404) {
                        return null;
                    }
                    throw err;
                }),
                aceApi.get(settings.path + "/runs/" + aceApi.query({f: settings.runs_f, limit: RECENT_RUNS})),
            ]).then(function(parts) {
                state.test = parts[0];
                state.expectations = parts[1];
                state.ignores = parts[2];
                state.settings = parts[3];
                state.runs = parts[4];
                render();
            });
        }

        function reload() {
            return load().catch(function(err) { show_error("Unable to load the test: " + err.message); });
        }

        function render() {
            show_error("");
            document.title = state.test.name + " - SVS test";
            render_header();
            render_facts();
            render_description();
            render_commands();
            render_arguments();
            render_dependencies();
            render_window();
            render_expectations();
            render_ignores();
            render_runs();
            document.getElementById("svs_test_loading").classList.add("d-none");
            document.getElementById("svs_test_body").classList.remove("d-none");
        }

        // shows the ask modal; resolves to true once it was submitted
        function ask(title, text, submit_label) {
            const modal = document.getElementById("svs_test_ask_modal");
            const form = document.getElementById("svs_test_ask_form");
            document.getElementById("svs_test_ask_title").textContent = title;
            document.getElementById("svs_test_ask_text").textContent = text;
            document.getElementById("svs_test_ask_submit").textContent = submit_label;
            return new Promise(function(resolve) {
                const instance = bootstrap.Modal.getOrCreateInstance(modal);
                let answer = false;
                function submit(event) {
                    event.preventDefault();
                    answer = true;
                    instance.hide();
                }
                form.addEventListener("submit", submit);
                modal.addEventListener("hidden.bs.modal", function hidden() {
                    modal.removeEventListener("hidden.bs.modal", hidden);
                    form.removeEventListener("submit", submit);
                    resolve(answer);
                });
                instance.show();
            });
        }

        // runs an action, then shows what happened and reloads; failures are shown, not thrown
        function act(promise, done_text) {
            return promise
                .then(function(result) {
                    if (result === false) {
                        return;
                    }
                    message(done_text, "alert-success");
                    return reload();
                })
                .catch(function(err) { message(err.message, "alert-danger"); });
        }

        function remove(title, text, submit_label, path, done_text) {
            return act(ask(title, text, submit_label).then(function(confirmed) {
                return confirmed ? aceApi.del(path) : false;
            }), done_text);
        }

        //
        // the catalog entry
        //

        function render_header() {
            const test = state.test;
            document.getElementById("svs_test_title").textContent = test.name;
            document.getElementById("svs_test_subtitle").textContent =
                test.technique + (test.technique_name ? " · " + test.technique_name : "");
        }

        function render_facts() {
            const test = state.test;
            const executor = test.test.executor || {};
            const list = document.getElementById("svs_test_facts");
            list.replaceChildren();
            function fact(term, value) {
                if (value === null || value === undefined || value === "") {
                    return;
                }
                list.appendChild(el("dt", "col-sm-2 fw-normal text-muted", term));
                list.appendChild(append(el("dd", "col-sm-10 mb-1"), value));
            }
            fact("State", test_state_node(test));
            fact("By platform", platform_states_node(test));
            fact("GUID", mono(test.guid));
            fact("Platforms", test.platforms.join(", "));
            fact("Executor", append(el("span"), test.executor || "",
                                    executor.elevation_required ? muted(" (elevation required)") : ""));
            fact("Repository", append(el("span"), test.repository, " ", mono(test.path, "text-muted")));
            const commit = mono(test.commit.substring(0, 12));
            commit.title = "the commit this version of the test was first read from: " + test.commit;
            const content = mono(test.content_hash.substring(0, 12), "text-muted");
            content.title = "the test's content hash: " + test.content_hash;
            fact("Commit", append(el("span"), commit, " ", content));
            fact("First seen", date(test.first_seen_at) + " UTC");
            if (test.removed_at) {
                fact("Removed", append(el("span"), date(test.removed_at) + " UTC",
                                       muted(": gone from its repository; it keeps its runs")));
            }
            const runs = el("span", null, plural(test.run_count, "run"));
            if (test.last_run_id) {
                append(runs, ", latest ", link(run_url(test.last_run_id), date(test.last_run_at)));
            }
            if (test.last_reviewed_run_id) {
                append(runs, ", latest reviewed ", link(run_url(test.last_reviewed_run_id), date(test.last_reviewed_at)));
            }
            fact("Runs", runs);
            const expected = el("span", null, plural(test.expected_signatures, "signature") + " expected");
            if (test.recent_runs) {
                append(expected, muted(", "), missing_node(test), muted(" recent runs missed one"));
            }
            fact("Expectations", expected);
        }

        function platform_states_node(test) {
            // one line per platform, worst first, as plain text
            const states = test.platform_states || [];
            if (states.length < 2 && !(states.length === 1 && states[0].test_state !== test.test_state)) {
                return null;
            }
            function rank(row) {
                const index = WORST_FIRST.indexOf(row.test_state);
                return index < 0 ? WORST_FIRST.length : index;
            }
            const node = el("div");
            states.slice().sort(function(a, b) {
                return rank(a) - rank(b) || a.platform.localeCompare(b.platform);
            }).forEach(function(row) {
                const info = TEST_STATES[row.test_state] || {css: "", title: ""};
                const line = el("div");
                const name = el("span", info.css, row.test_state.replace(/_/g, " "));
                name.title = row.test_state === "never_run" ? "no run of it on " + row.platform + " yet" : info.title;
                append(line, el("span", "text-muted", row.platform + ": "), name);
                if (row.expected_signatures) {
                    line.appendChild(muted(", " + plural(row.expected_signatures, "signature") + " expected"));
                }
                if (row.last_reviewed_run_id) {
                    append(line, muted(", reviewed "), link(run_url(row.last_reviewed_run_id), date(row.last_reviewed_at)));
                }
                node.appendChild(line);
            });
            return node;
        }

        function pre(text) {
            // wrapped, keeping the command's own line breaks
            const node = el("pre", "small bg-body-tertiary border rounded p-2 mb-2 text-break", text);
            node.style.whiteSpace = "pre-wrap";
            return node;
        }

        function render_description() {
            const node = document.getElementById("svs_test_description");
            const text = state.test.description || state.test.test.description;
            node.replaceChildren(text ? el("div", "small", text) : muted("none"));
            if (text) {
                node.firstChild.style.whiteSpace = "pre-wrap";
            }
        }

        function render_commands() {
            const node = document.getElementById("svs_test_commands");
            const executor = state.test.test.executor || {};
            node.replaceChildren();
            [["command", "Command"], ["steps", "Steps"], ["cleanup_command", "Cleanup"]].forEach(function(item) {
                const value = executor[item[0]];
                if (value) {
                    node.appendChild(el("div", "small text-muted", item[1]));
                    node.appendChild(pre(String(value).trim()));
                }
            });
            if (!node.childNodes.length) {
                node.appendChild(muted("none"));
            }
        }

        function render_arguments() {
            const node = document.getElementById("svs_test_arguments");
            const args = state.test.test.input_arguments || {};
            const names = Object.keys(args).sort();
            node.replaceChildren();
            if (!names.length) {
                node.appendChild(muted("none"));
                return;
            }
            const target = table(["Name", "Type", "Default", "Description"]);
            names.forEach(function(name) {
                const arg = args[name] || {};
                const value = arg["default"];
                table_row(target, [
                    mono(name),
                    arg.type || "",
                    value === undefined || value === null ? "" : mono(String(value)),
                    arg.description || "",
                ]);
            });
            node.appendChild(append(el("div", "table-responsive"), target));
        }

        function render_dependencies() {
            const node = document.getElementById("svs_test_dependencies");
            const test = state.test.test;
            const dependencies = test.dependencies || [];
            node.replaceChildren();
            if (!dependencies.length) {
                node.appendChild(muted("none"));
                return;
            }
            if (test.dependency_executor_name) {
                node.appendChild(el("div", "small text-muted mb-1", "run with " + test.dependency_executor_name));
            }
            dependencies.forEach(function(dependency) {
                const item = el("div", "mb-2");
                item.appendChild(el("div", "small", dependency.description || ""));
                if (dependency.prereq_command) {
                    item.appendChild(el("div", "small text-muted", "Check"));
                    item.appendChild(pre(String(dependency.prereq_command).trim()));
                }
                if (dependency.get_prereq_command) {
                    item.appendChild(el("div", "small text-muted", "Get"));
                    item.appendChild(pre(String(dependency.get_prereq_command).trim()));
                }
                node.appendChild(item);
            });
        }

        //
        // what SVS keeps about the test
        //

        function render_window() {
            const node = document.getElementById("svs_test_window");
            const current = state.settings;
            node.replaceChildren();
            const text = el("div", "small");
            if (current && current.observation_minutes) {
                append(text, plural(current.observation_minutes, "minute"),
                       muted(", used as it is for its runs registered from now on; set by " + (current.set_by || "?") +
                             " at " + date(current.updated_at) + " UTC "));
                if (settings.can_manage) {
                    text.appendChild(button("Use the computed window", "btn-link p-0 align-baseline",
                                            "the window computed from the latency of the signatures expected of it, as for any test", function() {
                        remove("Use the computed window?",
                               "Runs of this test registered from now on get the window computed from the latency of the signatures expected of it.",
                               "Use it", test_path + "/settings", "The test's runs get the computed window again.");
                    }));
                }
            } else {
                append(text, "Computed for each run: the latency of the slowest signature expected of the test, plus slack, " +
                       "within a floor and a ceiling (svs.runs.observation_window).");
            }
            node.appendChild(text);
            const field = document.getElementById("svs_test_window_minutes");
            if (field && document.activeElement !== field) {
                field.value = current && current.observation_minutes ? String(current.observation_minutes) : "";
            }
        }

        function expectation_order(a, b) {
            if (a.platform !== b.platform) {
                return a.platform.localeCompare(b.platform);
            }
            if (a.state !== b.state) {
                return a.state === "expected" ? -1 : 1;
            }
            return (a.signature_name || a.signature_uuid).localeCompare(b.signature_name || b.signature_uuid);
        }

        function render_expectations() {
            const node = document.getElementById("svs_test_expectations");
            node.replaceChildren();
            if (!state.expectations.length) {
                node.appendChild(el("div", "small text-muted",
                                    "Nothing is decided for this test yet. A reviewed run's candidates are decided on its page."));
                return;
            }
            const headers = ["Platform", "Signature", "Decision", "By", "When (UTC)", "Reason", "From run"];
            if (settings.can_manage) {
                headers.push("");
            }
            const target = table(headers);
            state.expectations.slice().sort(expectation_order).forEach(function(row) {
                const decision = el("span", row.state === "expected" ? "text-success" : "text-muted", row.state);
                decision.title = row.state === "expected" ? "every run of the test on " + row.platform + " should fire it"
                    : "it fires on " + row.platform + ", but it isn't what the test is about; it isn't proposed again";
                const cells = [
                    row.platform,
                    signature_node(row),
                    decision,
                    row.decided_by || "",
                    el("span", "text-nowrap", date(row.decided_at)),
                    row.reason || "",
                    row.decided_from_run_id ? link(run_url(row.decided_from_run_id), row.decided_from_run_id.substring(0, 8),
                                                   "font-monospace") : "",
                ];
                if (settings.can_manage) {
                    const name = row.signature_name || row.signature_uuid;
                    cells.push(button("Remove", "btn-outline-dark", "undecide it: it is a candidate again", function() {
                        remove("Remove the decision on " + name + " on " + row.platform + "?",
                               "It is a candidate again the next time a run of this test on " + row.platform +
                               " fires it." + (row.state === "expected" ? " Until then, no run misses it." : ""),
                               "Remove", test_path + "/expectations/" + encodeURIComponent(row.platform) + "/" +
                                         encodeURIComponent(row.signature_uuid),
                               "Removed the decision on " + name + " on " + row.platform + ".");
                    }));
                }
                table_row(target, cells);
            });
            node.appendChild(append(el("div", "table-responsive"), target));
        }

        function render_ignores() {
            const node = document.getElementById("svs_test_ignores");
            node.replaceChildren();
            [
                {scope: "test", title: "For this test", can_remove: settings.can_manage,
                 empty: "Nothing is ignored for this test only.",
                 path: function(sig) { return test_path + "/ignores/" + sig; },
                 text: "It counts in this test's runs again, from their next result."},
                {scope: "global", title: "For every test", can_remove: settings.is_admin,
                 empty: "Nothing is ignored for every test.",
                 path: function(sig) { return settings.path + "/ignores/global/" + sig; },
                 text: "It counts in every test's runs again, from their next result."},
            ].forEach(function(scope) {
                const rows = state.ignores.filter(function(row) { return row.scope === scope.scope; });
                node.appendChild(el("h5", "fs-6 mt-2", scope.title));
                if (!rows.length) {
                    node.appendChild(el("div", "small text-muted mb-2", scope.empty));
                    return;
                }
                const headers = ["Signature", "By", "When (UTC)", "Reason"];
                if (scope.can_remove) {
                    headers.push("");
                }
                const target = table(headers);
                rows.forEach(function(row) {
                    const cells = [signature_node(row), row.created_by || "", el("span", "text-nowrap", date(row.created_at)),
                                   row.reason || ""];
                    if (scope.can_remove) {
                        const name = row.signature_name || row.signature_uuid;
                        cells.push(button("Remove", "btn-outline-dark", "stop ignoring it", function() {
                            remove("Stop ignoring " + name + " " + scope.title.toLowerCase() + "?", scope.text, "Stop ignoring it",
                                   scope.path(encodeURIComponent(row.signature_uuid)), "Stopped ignoring " + name + ".");
                        }));
                    }
                    table_row(target, cells);
                });
                node.appendChild(append(el("div", "table-responsive"), target));
            });
        }

        //
        // its runs
        //

        function result_node(row) {
            const node = el("div");
            if (row.result_expected) {
                node.appendChild(el("div", null, row.result_hit + "/" + row.result_expected + " expected"));
            }
            if (row.result_missing) {
                const missing = el("div", "text-danger", row.result_missing + " missing");
                if (row.result_possibly_suppressed) {
                    missing.appendChild(muted(" (" + row.result_possibly_suppressed + " possibly suppressed)"));
                }
                node.appendChild(missing);
            }
            if (row.result_candidate) {
                node.appendChild(el("div", "text-warning-emphasis", plural(row.result_candidate, "candidate")));
            }
            if (!node.childNodes.length) {
                node.appendChild(muted("–"));
            }
            return node;
        }

        function times_node(row) {
            const node = el("div", "text-nowrap");
            [["created", row.created_at], ["started", row.started_at], ["ended", row.ended_at]].forEach(function(item) {
                if (item[1]) {
                    node.appendChild(append(el("div"), muted(item[0] + " "), date(item[1])));
                }
            });
            return node;
        }

        function render_runs() {
            const node = document.getElementById("svs_test_runs");
            const rows = state.runs.data;
            node.replaceChildren();
            const all = link(settings.runs_url + aceApi.query({f: settings.runs_f}), "all runs of this test on the Runs tab");
            if (!rows.length) {
                node.appendChild(el("div", "small text-muted", "No run of this test was registered yet."));
                return;
            }
            node.appendChild(append(el("div", "small mb-1"),
                                    state.runs.next_cursor ? "The latest " + rows.length + " of " +
                                        plural(state.test.run_count, "run") + ", newest first; "
                                        : plural(rows.length, "run") + ", newest first; ",
                                    all));
            const target = table(["Run", "State", "Times (UTC)", "Result", "Alerts", "Batch", "Owner", "Reviewer"]);
            rows.forEach(function(row) {
                const changed = row.changed_since_review ? el("div", "text-warning-emphasis", "changed since review") : "";
                table_row(target, [
                    link(run_url(row.run_id), row.run_id.substring(0, 8), "font-monospace"),
                    append(el("div"), run_state_node(row), changed),
                    times_node(row),
                    result_node(row),
                    row.alerts ? plural(row.alerts, "alert") : muted("0"),
                    row.batch_id || "",
                    row.owner || "",
                    row.reviewer || "",
                ]);
            });
            node.appendChild(append(el("div", "table-responsive"), target));
        }

        //
        // the observation window form
        //

        const form = document.getElementById("svs_test_window_form");
        if (form) {
            form.addEventListener("submit", function(event) {
                event.preventDefault();
                const minutes = Number(document.getElementById("svs_test_window_minutes").value);
                act(aceApi.put(test_path + "/settings", {observation_minutes: minutes}),
                    "Runs of this test registered from now on observe for " + plural(minutes, "minute") + ".");
            });
        }

        load().catch(function(err) {
            document.getElementById("svs_test_loading").classList.add("d-none");
            show_error(err.status === 404 ? "There is no test " + settings.guid + " in the catalog."
                : "Unable to load the test: " + err.message);
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const list = document.getElementById("svs_tests_page");
        if (list) {
            start_list(list);
        }
        const detail = document.getElementById("svs_test_page");
        if (detail) {
            start_detail(detail);
        }
    });
})();
