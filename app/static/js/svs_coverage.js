// SVS -> Coverage (docs/SVS_COVERAGE.md, *In the GUI*): ATT&CK coverage, one row per technique and
// platform, and one technique's drill-down.
//
// The list is a FilterListPage (filter_list_page.js) over /api/v2/svs/coverage on the svs_coverage
// filter screen, and opens on the endpoint platforms. Above it, a summary of the rows the filters
// match, counted per platform and state from /api/v2/svs/coverage/summary; each count applies its
// platform and state as filters. The drill-down is a shell over /api/v2/svs/coverage/{technique}: the
// technique's rows and its sub-techniques', the tests and signatures that count toward them, the tests
// removed from the catalog, and the days its state changed in the daily snapshots. Both are read-only.
// The rows carry platform slugs and tactic ids; the page names them from the pinned ATT&CK release
// (data-attack). Every value shown came from a catalog, a signature or a person, so it is placed as
// text, never markup. A state is plain text, not a badge.

(function() {
    "use strict";

    // a row's state: the worst of what counts toward the technique (and its sub-techniques) on the
    // platform (docs/SVS_COVERAGE.md, *States*), worst first
    const COVERAGE_STATES = {
        failing: {css: "text-danger fw-semibold", title: "the latest reviewed run of a test for it missed an expected signature"},
        stale: {css: "text-warning-emphasis",
                title: "it was validated, but a test or an expected signature changed since, or something is expected that no review has judged"},
        validated: {css: "text-success", title: "the latest reviewed runs of its tests hit every expected signature"},
        manual: {css: "text-primary", title: "covered only by signatures whose technique tags claim it; no test measures it"},
        untested: {css: "", title: "it has tests, but none has a reviewed run with expectations"},
        none: {css: "text-muted", title: "no test and no signature tag"},
    };
    const STATE_ORDER = Object.keys(COVERAGE_STATES);

    // a test's state on a platform, as the Tests tab shows it (svs_tests.js)
    const TEST_STATES = {
        never_run: {css: "text-muted", title: "no run or decision on the platform yet"},
        awaiting_review: {css: "text-warning-emphasis fw-semibold",
                          title: "no run of it is reviewed yet, or something was expected of it only after its latest review"},
        no_expectations: {css: "text-muted", title: "it has a reviewed run, and nothing is expected of it"},
        failing: {css: "text-danger fw-semibold", title: "its latest reviewed run missed an expected signature"},
        stale: {css: "text-warning-emphasis",
                title: "it would be validated, but the test or an expected signature's rule changed since that review"},
        validated: {css: "text-success", title: "its latest reviewed run hit every expected signature"},
    };

    const MANUAL_REASONS = {
        not_counting: "it doesn't count: the signature is disabled, or a YARA rule in QA mode",
        unknown_technique: "it doesn't count: the release has no such technique",
    };

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

    function table_row(target, cells, css) {
        const row = el("tr", css || null);
        cells.forEach(function(cell) {
            row.appendChild(append(el("td"), cell));
        });
        target.tBodies[0].appendChild(row);
        return row;
    }

    function responsive(target) {
        return append(el("div", "table-responsive"), target);
    }

    function parse_json(value, fallback) {
        try {
            return JSON.parse(value || "");
        } catch (e) {
            return fallback;
        }
    }

    // the pinned release's names for platform slugs and tactic ids
    function namer(attack) {
        const platforms = (attack && attack.platforms) || {};
        const tactics = (attack && attack.tactics) || {};
        return {
            release: (attack && attack.release) || "",
            platform: function(slug) { return platforms[slug] || slug; },
            tactics: function(ids) {
                return (ids || []).map(function(id) { return tactics[id] || id; }).join(", ");
            },
        };
    }

    function state_node(state) {
        const info = COVERAGE_STATES[state] || {css: "", title: ""};
        const node = el("span", info.css, state);
        node.title = info.title;
        return node;
    }

    // the row's state, and its own state when the sub-techniques made it differ
    function states_node(row) {
        const node = append(el("div"), state_node(row.state));
        if (row.own_state !== row.state) {
            const own = el("div", "small text-muted", "own: " + row.own_state);
            own.title = "leaving its sub-techniques out";
            node.appendChild(own);
        }
        return node;
    }

    function tests_node(row) {
        if (!row.tests_total) {
            return muted("0");
        }
        const node = el("div", null, String(row.tests_total));
        const parts = [];
        if (row.tests_validated) {
            parts.push(row.tests_validated + " validated");
        }
        if (row.tests_failing) {
            parts.push(row.tests_failing + " failing");
        }
        if (row.tests_stale) {
            parts.push(row.tests_stale + " stale");
        }
        if (parts.length) {
            node.appendChild(el("div", "small text-muted", parts.join(", ")));
        }
        return node;
    }

    function signatures_node(row) {
        const node = el("span", "text-nowrap");
        const measured = el("span", row.measured_signatures ? null : "text-muted", row.measured_signatures + " measured");
        measured.title = "signatures expected of the counted tests on the platform";
        const manual = el("span", row.manual_signatures ? null : "text-muted", row.manual_signatures + " manual");
        manual.title = "signatures whose technique tag counts toward the row";
        return append(node, measured, muted(" · "), manual);
    }

    function catalog_status_node(row) {
        if (row.retired_at) {
            const node = el("div", "small text-muted", "retired");
            node.title = "nothing has produced this row since " + date(row.retired_at) + " UTC; it is kept";
            return node;
        }
        if (row.catalog_status === "deprecated") {
            const node = el("div", "small text-muted", "deprecated");
            node.title = "ATT&CK deprecated it; it keeps its rows while a test or a tag names it";
            return node;
        }
        if (row.catalog_status === "unknown") {
            const node = el("div", "small text-muted", "unknown");
            node.title = "not in the pinned ATT&CK release; a test names it";
            return node;
        }
        return null;
    }

    function platform_node(names, row) {
        const node = el("div", null, names.platform(row.platform));
        if (!row.attack_platform) {
            const note = el("div", "small text-muted", "not listed by ATT&CK");
            note.title = "ATT&CK doesn't list this platform for the technique; a test runs it there";
            node.appendChild(note);
        }
        return node;
    }

    //
    // the list
    //

    function start_list(page) {
        const data = page.dataset;
        const settings = {
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            default_f: parse_json(data.defaultF, []),
            technique_url: data.techniqueUrl,
            tz: data.tz,
        };
        const names = namer(parse_json(data.attack, {}));
        let list = null;

        function technique_url(technique) {
            return settings.technique_url.replace("__TECHNIQUE__", encodeURIComponent(technique));
        }

        //
        // the summary of what the filters match
        //

        const summary = {key: null, generation: 0};

        // the filters shown, with these replacing the ones of the same names
        function narrow(replacements) {
            const replaced = replacements.map(function(entry) { return entry.name; });
            const filters = list.filters().filter(function(entry) { return replaced.indexOf(entry.name) < 0; });
            return list.setFilters(filters.concat(replacements));
        }

        function count_node(count, filters, title) {
            if (!count) {
                return muted("0");
            }
            const node = link("#", String(count));
            node.title = title;
            node.addEventListener("click", function(event) {
                event.preventDefault();
                narrow(filters);
            });
            return node;
        }

        function render_summary(result) {
            const target = document.getElementById("svs_coverage_summary");
            target.replaceChildren();
            if (result.platforms.length) {
                const counts = table(["Platform", "Rows"].concat(STATE_ORDER));
                counts.classList.add("w-auto");
                STATE_ORDER.forEach(function(state, index) {
                    const header = counts.tHead.rows[0].cells[index + 2];
                    header.replaceChildren(state_node(state));
                });
                function line(label, rows, states, platform, css) {
                    const cells = [label, String(rows)];
                    STATE_ORDER.forEach(function(state) {
                        const filters = [{name: "State", inverted: false, values: [state]}];
                        let title = "show the " + state + " rows";
                        if (platform) {
                            filters.push({name: "Platform", inverted: false, values: [platform]});
                            title += " on " + names.platform(platform);
                        }
                        cells.push(count_node(states[state] || 0, filters, title));
                    });
                    table_row(counts, cells, css);
                }
                result.platforms.forEach(function(item) {
                    line(names.platform(item.platform), item.rows, item.states, item.platform);
                });
                if (result.platforms.length > 1) {
                    line("All", result.rows, result.states, null, "fw-semibold");
                }
                target.appendChild(responsive(counts));
            } else {
                target.appendChild(el("div", "small text-muted mb-1", "No rows match these filters."));
            }

            const status = el("div", "small text-muted");
            if (result.refreshed_at) {
                append(status, "Computed " + date(result.refreshed_at) + " UTC against ATT&CK " + result.attack_release + ".");
            } else {
                append(status, "Coverage hasn't been computed yet: service_svs computes it on the primary node " +
                               "(or run ace svs coverage refresh).");
            }
            if (result.unknown_tags) {
                const unknown = el("span", null, " " + plural(result.unknown_tags, "signature tag") +
                                               " name a technique the release doesn't have.");
                unknown.title = "they don't count; the worklist lists them";
                status.appendChild(unknown);
            }
            if (result.ignored_tags) {
                const ignored = el("span", null, " " + plural(result.ignored_tags, "mitre: tag") + " aren't technique ids.");
                ignored.title = "templated tags and tactics; they don't count";
                status.appendChild(ignored);
            }
            target.appendChild(status);
            if (result.error) {
                target.appendChild(el("div", "small text-danger", "The latest refresh failed: " + result.error));
            }
        }

        function load_summary(params) {
            const key = JSON.stringify([params.f, params.tz]);
            if (key === summary.key) {
                return;
            }
            summary.key = key;
            const generation = ++summary.generation;
            aceApi.get(settings.path + "/summary" + aceApi.query({f: params.f, tz: params.tz}))
                .then(function(result) {
                    if (generation === summary.generation) {
                        render_summary(result);
                    }
                })
                .catch(function(err) {
                    if (generation !== summary.generation) {
                        return;
                    }
                    summary.key = null;
                    document.getElementById("svs_coverage_summary").replaceChildren(
                        el("div", "small text-danger", "Unable to count the rows: " + err.message));
                });
        }

        const columns = [
            {label: "Technique", width: "8rem", css: "text-nowrap", render: function(row) {
                const node = el("div", row.is_subtechnique ? "ps-3" : null);
                const anchor = link(technique_url(row.technique), row.technique);
                if (row.technique_name) {
                    anchor.title = row.technique_name;
                }
                return append(node, anchor, catalog_status_node(row));
            }},
            {label: "Name", render: function(row) {
                return el("span", row.is_subtechnique ? null : "fw-semibold", row.technique_name || "");
            }},
            {label: "Tactics", width: "10rem", render: function(row) { return el("span", "small", names.tactics(row.tactics)); }},
            {label: "Platform", width: "8rem", render: function(row) { return platform_node(names, row); }},
            {label: "State", width: "7rem",
             title: "the worst of what counts toward the technique and its sub-techniques on the platform", render: states_node},
            {label: "Tests", width: "8rem", title: "the tests that count toward the row, the sub-techniques' included",
             render: tests_node},
            {label: "Signatures", width: "10rem", render: signatures_node},
            {label: "Last reviewed", width: "9rem", title: "the latest review of a run that counts", css: "text-nowrap",
             render: function(row) { return row.last_reviewed_at ? date(row.last_reviewed_at) : muted("–"); }},
            {label: "State changed", width: "9rem", css: "text-nowrap",
             render: function(row) { return date(row.state_changed_at); }},
        ];

        list = FilterListPage.create({
            root: document.getElementById("svs_coverage_list"),
            screen: settings.screen,
            api: settings.path,
            columns: columns,
            fitColumns: true,
            // the API has one order, technique then platform
            defaultSort: null,
            defaultDesc: false,
            pageSizes: [50, 100, 250, 500],
            defaultLimit: 100,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: null,
            emptyText: "No coverage rows match these filters.",
            defaultF: settings.default_f,
            onLoad: load_summary,
        });
    }

    //
    // one technique
    //

    function start_detail(page) {
        const data = page.dataset;
        const settings = {
            path: data.api.substring(aceApi.BASE.length),
            technique: data.technique,
            tests_f: parse_json(data.testsF, []),
            runs_f: parse_json(data.runsF, []),
            history_f: parse_json(data.historyF, []),
            tests_url: data.testsUrl,
            runs_url: data.runsUrl,
            technique_url: data.techniqueUrl,
            test_url: data.testUrl,
            run_url: data.runUrl,
        };
        const names = namer(parse_json(data.attack, {}));
        const state = {};

        function technique_url(technique) {
            return settings.technique_url.replace("__TECHNIQUE__", encodeURIComponent(technique));
        }

        function test_url(guid) {
            return settings.test_url.replace("__TEST__", encodeURIComponent(guid));
        }

        function run_url(run_id) {
            return settings.run_url.replace("__RUN__", encodeURIComponent(run_id));
        }

        function show_error(text) {
            const node = document.getElementById("svs_technique_error");
            node.textContent = text || "";
            node.classList.toggle("d-none", !text);
        }

        // every page of a listing, up to MAX_PAGES of them
        function all_pages(path, params) {
            const rows = [];
            function next(cursor, count) {
                const query = Object.assign({limit: PAGE_SIZE}, params || {}, {cursor: cursor || undefined});
                return aceApi.get(path + aceApi.query(query)).then(function(result) {
                    Array.prototype.push.apply(rows, result.data);
                    if (result.next_cursor && count < MAX_PAGES) {
                        return next(result.next_cursor, count + 1);
                    }
                    return {rows: rows, complete: !result.next_cursor};
                });
            }
            return next(null, 1);
        }

        function load() {
            const coverage_path = settings.path + "/coverage/" + encodeURIComponent(settings.technique);
            return Promise.all([
                aceApi.get(coverage_path),
                // the history is one section of the page; without it the rest still shows
                all_pages(settings.path + "/coverage/history", {f: settings.history_f}).catch(function(err) {
                    return {error: err.message};
                }),
            ]).then(function(parts) {
                state.detail = parts[0];
                state.history = parts[1];
                render();
            });
        }

        function render() {
            show_error("");
            const detail = state.detail;
            document.title = detail.technique + (detail.name ? " " + detail.name : "") + " - SVS coverage";
            document.getElementById("svs_technique_title").textContent =
                detail.technique + (detail.name ? " · " + detail.name : "");
            document.getElementById("svs_technique_subtitle").textContent =
                (detail.is_subtechnique ? "Sub-technique" : "Technique") +
                (detail.tactics.length ? " · " + names.tactics(detail.tactics) : "");
            render_facts();
            render_rows();
            render_subs();
            render_tests();
            render_measured();
            render_manual();
            render_removed();
            render_history();
            document.getElementById("svs_technique_loading").classList.add("d-none");
            document.getElementById("svs_technique_body").classList.remove("d-none");
        }

        function render_facts() {
            const detail = state.detail;
            const list = document.getElementById("svs_technique_facts");
            list.replaceChildren();
            function fact(term, value) {
                if (value === null || value === undefined || value === "") {
                    return;
                }
                list.appendChild(el("dt", "col-sm-2 fw-normal text-muted", term));
                list.appendChild(append(el("dd", "col-sm-10 mb-1"), value));
            }
            if (detail.requested.toUpperCase() !== detail.technique) {
                fact("Revoked", append(el("span"), mono(detail.requested.toUpperCase()),
                                       " is revoked in ATT&CK " + detail.attack_release + "; this is its successor."));
            }
            if (detail.parent) {
                fact("Parent", link(technique_url(detail.parent), detail.parent));
            }
            fact("Tactics", names.tactics(detail.tactics));
            if (detail.catalog_status === "deprecated") {
                fact("Status", append(el("span"), "deprecated", muted(": it keeps its rows while a test or a tag names it")));
            } else if (detail.catalog_status === "unknown") {
                fact("Status", append(el("span"), "unknown", muted(": not in ATT&CK " + detail.attack_release + "; a test names it")));
            }
            fact("ATT&CK", detail.attack_release);
            fact("Computed", detail.refreshed_at
                ? append(el("span"), date(detail.refreshed_at) + " UTC",
                         muted(": the rows are as of then; the tests and signatures below are read now"))
                : muted("not yet"));
            fact("Elsewhere", append(el("span"),
                                     link(settings.tests_url + aceApi.query({f: settings.tests_f}), "its tests on the Tests tab"),
                                     " · ",
                                     link(settings.runs_url + aceApi.query({f: settings.runs_f}), "its runs on the Runs tab")));
        }

        function row_cells(row) {
            const retired = row.retired_at ? el("div", "small text-muted", "retired " + date(row.retired_at)) : "";
            return [
                append(el("div"), platform_node(names, row), retired),
                states_node(row),
                tests_node(row),
                signatures_node(row),
                row.last_reviewed_at ? el("span", "text-nowrap", date(row.last_reviewed_at)) : muted("–"),
                el("span", "text-nowrap", date(row.state_changed_at)),
            ];
        }

        const ROW_HEADERS = ["Platform", "State", "Tests", "Signatures", "Last reviewed (UTC)", "State changed (UTC)"];

        function render_rows() {
            const node = document.getElementById("svs_technique_rows");
            const rows = state.detail.rows;
            node.replaceChildren();
            if (!rows.length) {
                node.appendChild(el("div", "small text-muted", "No rows yet: the next refresh computes them."));
                return;
            }
            const target = table(ROW_HEADERS);
            rows.forEach(function(row) {
                table_row(target, row_cells(row), row.retired_at ? "text-muted" : null);
            });
            node.appendChild(responsive(target));
        }

        function render_subs() {
            const node = document.getElementById("svs_technique_subs");
            const rows = state.detail.sub_technique_rows;
            node.replaceChildren();
            if (!rows.length) {
                node.appendChild(el("div", "small text-muted", state.detail.is_subtechnique
                    ? "A sub-technique has none." : "It has no sub-techniques with coverage rows."));
                return;
            }
            const target = table(["Sub-technique"].concat(ROW_HEADERS));
            rows.forEach(function(row) {
                const technique = append(el("div", "text-nowrap"), link(technique_url(row.technique), row.technique));
                if (row.technique_name) {
                    technique.appendChild(el("div", "small", row.technique_name));
                }
                table_row(target, [technique].concat(row_cells(row)), row.retired_at ? "text-muted" : null);
            });
            node.appendChild(responsive(target));
        }

        function test_state_node(value) {
            const info = TEST_STATES[value] || {css: "", title: ""};
            const node = el("span", info.css, value.replace(/_/g, " "));
            node.title = info.title;
            return node;
        }

        function render_tests() {
            const node = document.getElementById("svs_technique_tests");
            const tests = state.detail.tests;
            node.replaceChildren();
            if (!tests.length) {
                node.appendChild(el("div", "small text-muted", "No test in the catalog is for this technique or its sub-techniques."));
                return;
            }
            const target = table(["Test", "Technique", "Platform", "Test state", "Counts as", "Last reviewed (UTC)", "Expected"]);
            tests.forEach(function(test) {
                const technique = el("div", "text-nowrap", test.technique);
                if (test.test_technique !== test.technique) {
                    const named = el("div", "small text-muted", "as " + test.test_technique);
                    named.title = "the id its atomic names was revoked; it counts toward its successor";
                    technique.appendChild(named);
                }
                table_row(target, [
                    append(el("div"), link(test_url(test.guid), test.name), append(el("div", "small"), mono(test.guid, "text-muted"))),
                    technique,
                    names.platform(test.platform),
                    test_state_node(test.test_state),
                    state_node(test.contribution),
                    test.last_reviewed_run_id
                        ? link(run_url(test.last_reviewed_run_id), date(test.last_reviewed_at), "text-nowrap")
                        : muted("–"),
                    test.expected_signatures.length ? String(test.expected_signatures.length) : muted("0"),
                ]);
            });
            node.appendChild(responsive(target));
        }

        function signature_node(row) {
            const node = el("div");
            append(node, row.name || "");
            const details = el("div", "small text-muted");
            append(details, row.family ? row.family + " · " : "", mono(row.signature_uuid));
            node.appendChild(details);
            return node;
        }

        function render_measured() {
            const node = document.getElementById("svs_technique_measured");
            const signatures = state.detail.measured_signatures;
            node.replaceChildren();
            if (!signatures.length) {
                node.appendChild(el("div", "small text-muted",
                                    "No signature is expected of these tests yet. A reviewed run's candidates are decided on its page."));
                return;
            }
            const test_names = {};
            state.detail.tests.forEach(function(test) { test_names[test.guid] = test.name; });
            const target = table(["Signature", "Expected by"]);
            signatures.forEach(function(signature) {
                const by = el("div");
                signature.tests.forEach(function(pair) {
                    append(by, append(el("div"), link(test_url(pair.guid), test_names[pair.guid] || pair.guid),
                                      muted(" on " + names.platform(pair.platform))));
                });
                table_row(target, [signature_node(signature), by]);
            });
            node.appendChild(responsive(target));
        }

        function render_manual() {
            const node = document.getElementById("svs_technique_manual");
            const detail = state.detail;
            node.replaceChildren();
            if (detail.manual_signatures_error) {
                node.appendChild(el("div", "small text-danger mb-1",
                                    "The signatures' tags couldn't be read: " + detail.manual_signatures_error));
            }
            if (!detail.manual_signatures.length) {
                if (!detail.manual_signatures_error) {
                    node.appendChild(el("div", "small text-muted", "No signature's technique tag names this technique or its sub-techniques."));
                }
                return;
            }
            const target = table(["Signature", "Tag", "Counts"]);
            detail.manual_signatures.forEach(function(signature) {
                const tag = el("div", "text-nowrap", signature.declared);
                if (signature.declared !== signature.technique) {
                    tag.appendChild(muted(" → " + signature.technique));
                }
                const counts = signature.counts
                    ? el("span", null, "yes")
                    : el("span", "text-muted", MANUAL_REASONS[signature.reason] || "it doesn't count");
                table_row(target, [signature_node(signature), tag, counts]);
            });
            node.appendChild(responsive(target));
        }

        function render_removed() {
            const node = document.getElementById("svs_technique_removed");
            const removed = state.detail.removed_tests;
            node.replaceChildren();
            if (!removed.length) {
                node.appendChild(el("div", "small text-muted", "None."));
                return;
            }
            node.appendChild(el("div", "small text-muted mb-1", "Gone from their repositories; they don't count, and keep their runs."));
            const target = table(["Test", "Technique", "Removed (UTC)"]);
            removed.forEach(function(test) {
                table_row(target, [link(test_url(test.guid), test.name), test.technique,
                                   el("span", "text-nowrap", date(test.removed_at))]);
            });
            node.appendChild(responsive(target));
        }

        // per platform, the days the state changed, from the snapshots (oldest first)
        function state_changes(rows) {
            const platforms = {};
            rows.forEach(function(row) {
                (platforms[row.platform] = platforms[row.platform] || []).push(row);
            });
            const changes = [];
            Object.keys(platforms).sort().forEach(function(platform) {
                let previous = null;
                platforms[platform].forEach(function(row) {
                    if (previous === null || row.state !== previous.state) {
                        changes.push({platform: platform, day: row.snapshot_date, from: previous ? previous.state : null,
                                      to: row.state});
                    }
                    previous = row;
                });
            });
            return changes;
        }

        function render_history() {
            const node = document.getElementById("svs_technique_history");
            const history = state.history;
            node.replaceChildren();
            if (history.error) {
                node.appendChild(el("div", "small text-danger", "Unable to read the snapshots: " + history.error));
                return;
            }
            const exports = append(el("div", "small mb-1"), "Export the snapshots shown: ");
            ["csv", "ndjson"].forEach(function(format, index) {
                append(exports, index ? " · " : "",
                       link(aceApi.BASE + settings.path + "/coverage/history/export/" + format +
                            aceApi.query({f: settings.history_f}), format.toUpperCase()));
            });
            if (!history.rows.length) {
                node.appendChild(el("div", "small text-muted", "No snapshot of it in the last year. One is filed each day."));
                return;
            }
            const first = history.rows[0].snapshot_date;
            const last = history.rows[history.rows.length - 1].snapshot_date;
            node.appendChild(el("div", "small mb-1", "From the daily snapshots of the last year (" + first + " to " + last +
                                ", UTC days): the first state on each platform, then each day it changed." +
                                (history.complete ? "" : " Only the oldest " + history.rows.length + " snapshot rows are read.")));
            node.appendChild(exports);
            const target = table(["Platform", "Day", "State"]);
            state_changes(history.rows).forEach(function(change) {
                const cell = el("span");
                if (change.from === null) {
                    append(cell, state_node(change.to), muted(" (first snapshot)"));
                } else {
                    append(cell, state_node(change.from), muted(" → "), state_node(change.to));
                }
                table_row(target, [names.platform(change.platform), el("span", "text-nowrap", change.day), cell]);
            });
            node.appendChild(responsive(target));
        }

        load().catch(function(err) {
            document.getElementById("svs_technique_loading").classList.add("d-none");
            show_error(err.status === 404
                ? "ATT&CK " + names.release + " has no technique " + settings.technique + ", and nothing covers it."
                : "Unable to load the technique: " + err.message);
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const list = document.getElementById("svs_coverage_page");
        if (list) {
            start_list(list);
        }
        const detail = document.getElementById("svs_technique_page");
        if (detail) {
            start_detail(detail);
        }
    });
})();
