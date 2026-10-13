// Signatures -> Validations (docs/SVS_VALIDATION.md, In the GUI): the list of YARA validations and
// a validation's report.
//
// Both pages are shells over /api/v2/svs/yara/validations, called from the browser with the Flask
// session cookie. The list is a FilterListPage (filter_list_page.js) on the svs_validations filter
// screen. The report reads GET /{uuid} for its header and its counts, and each band pages its own
// rows from GET /{uuid}/results. Files are plain links to the API: the browser saves the zip,
// which is encrypted with the password "infected". Every value shown came from rule files, a
// repository or analyzed data, so it is placed as text, never markup.

(function() {
    "use strict";

    const STATES = {
        queued: {icon: "bi-hourglass", css: "text-muted", title: "waiting for a worker of the svs service"},
        running: {icon: "bi-arrow-repeat", css: "text-primary", title: "a worker of the svs service is scanning"},
        completed: {icon: "bi-check-circle", css: "text-success", title: "the report is ready"},
        failed: {icon: "bi-x-octagon", css: "text-danger", title: "the validation could not run"},
    };

    // the listed categories (aceapi_v2/svs/yara/validations/service.py, LISTED_CATEGORIES); own:
    // every row is a sample of its own rule, so it links to that sample's page
    const CATEGORIES = {
        regression: {
            heading: "Regressions", attention: true, own: true,
            hint: "Real hits for the rule that it no longer matches."},
        regression_unconfirmed: {
            heading: "Regressions on unconfirmed labels", attention: true, own: true,
            hint: "Check that each sample was ever a real hit for the rule: its label is only inherited from alerts where several signatures fired."},
        new_fp: {
            heading: "New false positives", attention: true, own: true,
            hint: "False positives for the rule that it now matches."},
        new_fp_other_rule: {
            heading: "New false positives on another rule's sample", attention: true, own: false,
            hint: "The rule now matches files that are graded false positives for other rules."},
        scan_error: {
            heading: "Scan errors", attention: true, own: false,
            hint: "The scan of the rule's namespace failed or timed out on these files, under base or head. They are not misses."},
        rule_removed: {
            heading: "Samples of rules this change removes", attention: true, own: true,
            hint: "Head no longer has the rule. Retire its samples if it is gone on purpose."},
        recovered: {
            heading: "Recovered", attention: false, own: true,
            hint: "Real hits the rule missed on base and matches in head."},
        improvement: {
            heading: "Improvements", attention: false, own: true,
            hint: "False positives the rule no longer matches."},
        already_broken: {
            heading: "Already broken on base", attention: false, own: true,
            hint: "Real hits the rule misses on both commits. Retire or relabel the sample if that is intended."},
        new_match_real_hit: {
            heading: "New matches on files that are a real hit for another rule", attention: false, own: false,
            hint: "For information: the rule now matches files graded real hits for other rules."},
        unlabeled_change: {
            heading: "Unlabeled changes", attention: false, own: false,
            hint: "The match changed on a file that has no label for the rule, or a conflicted one."},
    };

    // the categories that are counted and never listed
    const COUNTED = [
        ["known_fp", "known FP still matching"],
        ["retired", "retired"],
        ["not_testable", "not testable"],
        ["unchanged", "unchanged"],
    ];

    const RESULTS_PAGE_SIZE = 50;
    const REFRESH_SECONDS = 15;

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

    function icon(name, title, css) {
        const element = el("span", "bi " + name + (css ? " " + css : ""));
        element.title = title;
        element.setAttribute("aria-label", title);
        return element;
    }

    function append(parent) {
        Array.prototype.slice.call(arguments, 1).forEach(function(child) {
            if (child === null || child === undefined) {
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

    function size(bytes) {
        if (bytes === null || bytes === undefined) {
            return "";
        }
        if (bytes < 1024) {
            return bytes + " B";
        }
        const units = ["KB", "MB", "GB"];
        let value = bytes;
        let unit = -1;
        do {
            value /= 1024;
            unit++;
        } while (value >= 1024 && unit < units.length - 1);
        return value.toFixed(1) + " " + units[unit];
    }

    function seconds(value) {
        return value === null || value === undefined ? "" : value.toFixed(2) + " s";
    }

    function copy_button(value, title) {
        const button = el("button", "btn btn-xs btn-outline-secondary ms-1");
        button.type = "button";
        button.title = title;
        button.appendChild(el("span", "bi bi-clipboard"));
        button.addEventListener("click", function(event) {
            event.preventDefault();
            event.stopPropagation();
            copy_to_clipboard(value);
        });
        return button;
    }

    function short_sha(sha) {
        const code = el("code", null, sha ? sha.substring(0, 10) : "");
        code.title = sha || "";
        return code;
    }

    function state_node(row) {
        const state = STATES[row.state] || {icon: "bi-question-circle", css: "text-muted", title: row.state};
        const node = el("span", "text-nowrap " + state.css);
        node.title = row.state === "failed" && row.error ? row.error : state.title;
        return append(node, el("span", "bi " + state.icon + " me-1"), row.state);
    }

    // a sample's label for the rule: tp and fp are verdicts and look like one
    function label_node(row) {
        if (!row.label) {
            const none = el("span", "text-muted", "–");
            none.title = "no label for this rule: the file is not its sample, or no contributing detection has a verdict";
            return none;
        }
        if (row.label === "conflicted") {
            const conflicted = el("span", "text-danger text-nowrap");
            conflicted.title = "votes of the strongest strength (" + aceVerdicts.SOURCE_LABELS[row.label_source] +
                ") disagree: someone has to relabel this sample";
            return append(conflicted, icon("bi-exclamation-octagon", "conflicted"), " conflicted");
        }
        return aceVerdicts.badge(row.label, row.label_source);
    }

    function page_settings(page) {
        const data = page.dataset;
        return {
            api: data.api,
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            list_url: data.listUrl,
            samples_url: data.samplesUrl,
            tz: data.tz,
            can_download: data.canDownload === "true",
        };
    }

    function report_url(settings, uuid) {
        return settings.list_url + "/" + encodeURIComponent(uuid);
    }

    // the branch, linked to its pull request when CI sent one (the API takes only http(s) URLs)
    function branch_node(row) {
        const cell = el("span", "text-break-all", row.branch);
        if (row.pr_url && /^https?:\/\//.test(row.pr_url)) {
            const pr = link(row.pr_url, null, "ms-1");
            pr.target = "_blank";
            pr.rel = "noopener noreferrer";
            pr.appendChild(icon("bi-box-arrow-up-right", "the pull request"));
            cell.appendChild(pr);
        }
        return cell;
    }

    // a count that needs attention when it is not zero; "–" until the validation has completed
    function count_node(value, title) {
        if (value === null || value === undefined) {
            const none = el("span", "text-muted", "–");
            none.title = "not completed";
            return none;
        }
        const node = el("span", value ? "text-danger fw-semibold" : "text-muted", value);
        node.title = title;
        return node;
    }

    //
    // the list
    //

    function start_list(page) {
        const settings = page_settings(page);

        const columns = [
            {label: "Created", width: "10rem", title: "UTC", render: function(row) {
                return link(report_url(settings, row.uuid), date(row.created_at));
            }},
            {label: "State", width: "8rem", render: state_node},
            {label: "Repository", width: "12%", css: "text-break-all", render: function(row) { return row.repository; }},
            {label: "Branch", width: "18%", render: branch_node},
            {label: "Commits", width: "13rem", title: "base..head", render: function(row) {
                return append(el("span", "text-nowrap"), short_sha(row.base_sha), "..", short_sha(row.head_sha));
            }},
            {label: "Requested by", width: "9rem", css: "text-break-all", render: function(row) { return row.requested_by || ""; }},
            {label: "Regressions", width: "7rem", title: "regressions, including those on unconfirmed labels", render: function(row) {
                return count_node(row.regressions, "regressions, including those on unconfirmed labels");
            }},
            {label: "New FP", width: "6rem", title: "new false positives, including those on another rule's sample", render: function(row) {
                return count_node(row.new_fps, "new false positives, including those on another rule's sample");
            }},
            {label: "Compile errors", width: "7rem", title: "head files that do not compile, plus one if its ruleset would not load", render: function(row) {
                return count_node(row.compile_errors, "head files that do not compile, plus one if its ruleset would not load");
            }},
        ];

        FilterListPage.create({
            root: document.getElementById("validations_list"),
            screen: settings.screen,
            api: settings.path,
            columns: columns,
            // the API has one order, newest first
            defaultSort: null,
            defaultDesc: true,
            pageSizes: [25, 50, 100, 250],
            defaultLimit: 50,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: null,
            emptyText: "No validations match these filters.",
        });
    }

    //
    // one validation
    //

    function start_detail(page) {
        const settings = page_settings(page);
        const uuid = page.dataset.validationUuid;
        const error = document.getElementById("validation_error");
        const target = document.getElementById("validation_detail");
        const context = {
            settings: settings,
            uuid: uuid,
            path: settings.path + "/" + encodeURIComponent(uuid),
        };

        function load() {
            return aceApi.get(context.path)
                .then(function(validation) {
                    error.classList.add("d-none");
                    render_detail(context, target, validation);
                    // a queued or running validation is followed until it ends
                    if (validation.state === "queued" || validation.state === "running") {
                        window.setTimeout(load, REFRESH_SECONDS * 1000);
                    }
                })
                .catch(function(err) {
                    target.replaceChildren();
                    error.textContent = "Unable to load the validation: " + err.message;
                    error.classList.remove("d-none");
                });
        }

        load();
    }

    function definition_list(items) {
        const list = el("dl", "row mb-0");
        items.forEach(function(item) {
            if (item[1] === null || item[1] === undefined || item[1] === "") {
                return;
            }
            list.appendChild(el("dt", "col-sm-3", item[0]));
            const value = el("dd", "col-sm-9 text-break");
            append(value, item[1]);
            list.appendChild(value);
        });
        return list;
    }

    function export_links(context, category) {
        const settings = context.settings;
        const params = category ? {category: category} : {};
        const links = el("span", "small text-nowrap");
        append(links, "Export ",
               link(settings.api + "/" + encodeURIComponent(context.uuid) + "/results/export/csv" + aceApi.query(params), "CSV"),
               " · ",
               link(settings.api + "/" + encodeURIComponent(context.uuid) + "/results/export/ndjson" + aceApi.query(params), "NDJSON"));
        if (settings.can_download) {
            const download = link(settings.api + "/" + encodeURIComponent(context.uuid) + "/download" + aceApi.query(params), "Download files");
            download.title = "the files of these rows that are stored on this node, in a zip protected with the password infected";
            append(links, " · ", download);
        }
        return links;
    }

    function render_detail(context, target, validation) {
        const report = validation.report;
        const nodes = [render_header(context, validation)];
        if (validation.state === "completed" && report) {
            if (!validation.diffed) {
                nodes.push(not_compared_banner(report));
            }
            nodes.push(render_bands(context, validation));
        }
        if (report) {
            nodes.push(render_diagnostics(validation, report));
        }
        target.replaceChildren.apply(target, nodes);
    }

    function render_header(context, validation) {
        const header = el("div", "mb-3");
        append(header, el("h2", "mb-1 text-break", validation.repository + " · " + validation.branch));

        const commit = function(sha, name) {
            return append(el("span"), el("code", null, sha), copy_button(sha, "copy the " + name + " commit"));
        };
        const report = validation.report;
        const items = [
            ["State", state_node(validation)],
            ["Error", validation.error ? el("span", "text-danger", validation.error) : null],
            ["Repository", validation.repository],
            ["Branch", branch_node(validation)],
            ["Base", commit(validation.base_sha, "base")],
            ["Head", commit(validation.head_sha, "head")],
            ["Requested by", validation.requested_by],
            ["Created", date(validation.created_at) + " UTC"],
            ["Ran", validation.started_at ? date(validation.started_at) + " – " + (date(validation.finished_at) || "…") + " UTC" : null],
        ];
        if (report) {
            items.push(["Rules", report.added_rules.length + " added, " + report.removed_rules.length + " removed, " +
                        report.changed_rules.length + " changed in head"]);
        }
        append(header, definition_list(items));

        if (validation.state === "queued" || validation.state === "running") {
            append(header, el("div", "text-muted small mt-2", "This page refreshes every " + REFRESH_SECONDS +
                              " seconds until the validation ends."));
        }
        if (validation.state === "completed" && validation.diffed) {
            const all = el("div", "mt-2");
            append(all, el("span", "small text-muted me-1", "Every listed row:"), export_links(context, null));
            header.appendChild(all);
        }
        return header;
    }

    // a side whose ruleset would not load stops the comparison (production keeps its previous
    // generation of rules)
    function not_compared_banner(report) {
        const banner = el("div", "alert alert-danger");
        append(banner, el("div", "fw-semibold", "Nothing was compared: a ruleset would not load."));
        [["head", report.head], ["base", report.base]].forEach(function(side) {
            if (side[1].loads) {
                return;
            }
            const line = el("div", "small mt-1");
            append(line, "The " + side[0] + " commit's ruleset would not load" +
                   (side[0] === "head" ? " (the yara service would keep its previous rules): " : ": "),
                   el("code", null, side[1].ruleset_error));
            banner.appendChild(line);
        });
        return banner;
    }

    //
    // the bands
    //

    function render_bands(context, validation) {
        const counts = validation.counts || {};
        const section = el("div");
        const band = function(category) {
            if (counts[category]) {
                section.appendChild(category_band(context, category, counts[category]));
            }
        };

        ["regression", "regression_unconfirmed", "new_fp", "new_fp_other_rule"].forEach(band);
        const compile = compile_problems(validation.report);
        if (compile) {
            section.appendChild(compile);
        }
        ["scan_error", "rule_removed", "recovered", "improvement", "already_broken", "new_match_real_hit",
         "unlabeled_change"].forEach(band);

        const counted = el("div", "small text-muted mb-3");
        const parts = COUNTED.filter(function(item) { return counts[item[0]]; })
            .map(function(item) { return counts[item[0]] + " " + item[1]; });
        counted.textContent = parts.length ? "Counted, not listed: " + parts.join(" · ") + "." : "";
        section.appendChild(counted);

        const listed = Object.keys(CATEGORIES).some(function(category) { return counts[category]; });
        if (validation.diffed && !listed) {
            section.insertBefore(el("p", "text-success", "This change makes no difference to any sample."), section.firstChild);
        }
        return section;
    }

    function band_summary(heading, count, attention) {
        const summary = el("summary", "fs-5 mb-1");
        append(summary, el("span", attention ? "fw-semibold" : null, heading), " ",
               el("span", attention ? "text-danger" : "text-muted", "(" + count + ")"));
        return summary;
    }

    function category_band(context, category, count) {
        const definition = CATEGORIES[category];
        const details = el("details", "mb-3");
        details.open = definition.attention;
        details.dataset.category = category;
        details.appendChild(band_summary(definition.heading, count, definition.attention));

        const top = el("div", "d-flex flex-wrap justify-content-between gap-2 mb-1");
        append(top, el("span", "text-muted small", definition.hint), export_links(context, category));
        details.appendChild(top);

        const table = el("table", "table table-sm table-bordered filter-list-table small");
        const head = table.createTHead().insertRow();
        [["Rule", "24%"], ["Namespace", "10rem"], ["SHA256", "13rem"], ["Label", "9rem"], ["Base → head", "10rem"],
         ["Note", null]].forEach(function(column) {
            const th = el("th", null, column[0]);
            if (column[1]) {
                th.style.width = column[1];
            }
            head.appendChild(th);
        });
        const body = table.createTBody();
        details.appendChild(table);

        const more = el("button", "btn btn-sm btn-outline-dark d-none", "Show more");
        more.type = "button";
        details.appendChild(more);

        let cursor = null;
        let started = false;
        function load_page() {
            more.disabled = true;
            const params = {category: category, limit: RESULTS_PAGE_SIZE, cursor: cursor};
            aceApi.get(context.path + "/results" + aceApi.query(params))
                .then(function(page) {
                    page.data.forEach(function(row) { body.appendChild(result_row(context, category, row)); });
                    cursor = page.next_cursor;
                    more.classList.toggle("d-none", !cursor);
                })
                .catch(function(err) {
                    const row = body.insertRow();
                    const cell = el("td", "text-danger", "Unable to load the rows: " + err.message);
                    cell.colSpan = 6;
                    row.appendChild(cell);
                })
                .finally(function() { more.disabled = false; });
        }
        more.addEventListener("click", load_page);

        // a band's rows load the first time it is opened
        function start() {
            if (details.open && !started) {
                started = true;
                load_page();
            }
        }
        details.addEventListener("toggle", start);
        start();
        return details;
    }

    function outcome_node(outcome, raw) {
        const node = el("span", outcome === "error" ? "text-danger" : (outcome === "match" ? "fw-semibold" : null), outcome);
        if (raw && outcome !== "match") {
            append(node, icon("bi-info-circle", "the rule matched, but its meta makes no detection (see the note)", "ms-1 text-muted"));
        }
        return node;
    }

    function result_row(context, category, row) {
        const settings = context.settings;
        const tr = el("tr");

        // a sample of the row's own rule has its page; any other file is found in the Samples list
        // by its sha256, under whichever rules captured it
        const target = CATEGORIES[category].own ?
            settings.samples_url + "/" + encodeURIComponent(row.sha256) + "/" + encodeURIComponent(row.rule_uuid) :
            settings.samples_url + aceApi.query({f: "sha256:" + row.sha256});
        const rule = el("td", "text-break-all");
        const rule_link = link(target, row.rule_name || row.rule_uuid, "fw-semibold");
        rule_link.title = (CATEGORIES[category].own ? "the sample for this rule" : "the samples of this file") +
            "\nrule uuid " + row.rule_uuid;
        rule.appendChild(rule_link);
        tr.appendChild(rule);

        tr.appendChild(el("td", "text-break-all", row.namespace));
        tr.appendChild(append(el("td", "text-nowrap"), short_sha(row.sha256), copy_button(row.sha256, "copy the sha256")));
        tr.appendChild(append(el("td"), label_node(row)));
        tr.appendChild(append(el("td", "text-nowrap"), outcome_node(row.base, row.raw_base), " → ",
                              outcome_node(row.head, row.raw_head)));
        tr.appendChild(el("td", "text-break", row.note));
        return tr;
    }

    // files that do not compile, rulesets that would not load, and include problems, per commit
    function compile_problems(report) {
        const rows = [];
        [["head", report.head], ["base", report.base]].forEach(function(side) {
            side[1].file_errors.forEach(function(error) {
                rows.push([side[0], error.file, error.error, error.dropped.length ?
                           "drops " + error.dropped.map(function(rule) { return rule.name; }).join(", ") : ""]);
            });
            if (side[1].ruleset_error) {
                rows.push([side[0], "(the whole ruleset)", side[1].ruleset_error, "would not load: the yara service keeps its previous rules"]);
            }
            side[1].include_warnings.forEach(function(warning) {
                rows.push([side[0], warning.file, warning.error, "include " + warning.include + " is compiled as empty"]);
            });
        });
        if (rows.length === 0) {
            return null;
        }

        const head_count = rows.filter(function(row) { return row[0] === "head"; }).length;
        const details = el("details", "mb-3");
        details.open = head_count > 0;
        details.appendChild(band_summary("Compile problems", rows.length, head_count > 0));
        details.appendChild(el("div", "text-muted small mb-1",
            "A file that does not compile is dropped with its rules; the other files still load."));

        const table = el("table", "table table-sm table-bordered small");
        const head = table.createTHead().insertRow();
        [["Commit", "6rem"], ["File", "24%"], ["Error", null], ["Effect", "24%"]].forEach(function(column) {
            const th = el("th", null, column[0]);
            if (column[1]) {
                th.style.width = column[1];
            }
            head.appendChild(th);
        });
        const body = table.createTBody();
        rows.forEach(function(values) {
            const tr = body.insertRow();
            tr.appendChild(el("td", null, values[0]));
            tr.appendChild(el("td", "text-break-all", values[1]));
            tr.appendChild(append(el("td", "text-break"), el("code", null, values[2])));
            tr.appendChild(el("td", "text-break", values[3]));
        });
        details.appendChild(table);
        return details;
    }

    //
    // diagnostics
    //

    function small_table(columns, rows) {
        const table = el("table", "table table-sm table-bordered w-auto small mb-2");
        const head = table.createTHead().insertRow();
        columns.forEach(function(column) { head.appendChild(el("th", null, column)); });
        const body = table.createTBody();
        rows.forEach(function(values) {
            const tr = body.insertRow();
            values.forEach(function(value) {
                const cell = el("td", "text-break");
                append(cell, value);
                tr.appendChild(cell);
            });
        });
        return table;
    }

    function diagnostic(title, count, content) {
        const details = el("details", "mb-2");
        const summary = el("summary", null, title);
        if (count !== null) {
            append(summary, " ", el("span", "text-muted", "(" + count + ")"));
        }
        details.appendChild(summary);
        append.apply(null, [details].concat(content));
        return details;
    }

    function rule_rows(rules, extra) {
        return rules.map(function(rule) {
            const row = [rule.name, rule.uuid || "", rule.file];
            return extra ? row.concat([extra(rule)]) : row;
        });
    }

    function render_diagnostics(validation, report) {
        const section = el("div", "mt-4");
        append(section, el("h5", null, "Details"));

        const changes = [];
        [["added", report.added_rules], ["removed", report.removed_rules], ["changed", report.changed_rules]].forEach(function(kind) {
            kind[1].forEach(function(rule) { changes.push([kind[0], rule.name, rule.uuid || "", rule.file]); });
        });
        if (changes.length) {
            section.appendChild(diagnostic("Rules this change touches", changes.length,
                small_table(["", "Rule", "uuid", "File"], changes)));
        }
        if (report.not_testable.length) {
            section.appendChild(diagnostic("Rules that cannot be tested", report.not_testable.length, [
                el("div", "text-muted small mb-1", "A rule needs a uuid of its own: samples are labeled per rule uuid."),
                small_table(["Rule", "uuid", "File", "Why"], rule_rows(report.not_testable, function(rule) { return rule.reason; })),
            ]));
        }
        if (report.full_path_rules.length) {
            section.appendChild(diagnostic("Rules that filter on full_path", report.full_path_rules.length, [
                el("div", "text-muted small mb-1",
                   "The original path held the alert's storage directory, so a replay cannot reproduce this filter."),
                small_table(["Rule", "uuid", "File"], rule_rows(report.full_path_rules)),
            ]));
        }
        if (report.head.warnings.length) {
            section.appendChild(diagnostic("Compiler warnings in head", report.head.warnings.length,
                small_table(["Warning"], report.head.warnings.map(function(warning) { return [el("code", null, warning)]; }))));
        }

        const not_loaded = [];
        const refused = [];
        [["head", report.head], ["base", report.base]].forEach(function(side) {
            side[1].not_loaded.forEach(function(item) { not_loaded.push([side[0], item.path, item.reason]); });
            side[1].skipped_members.forEach(function(item) { refused.push([side[0], item[0], item[1]]); });
        });
        if (not_loaded.length) {
            section.appendChild(diagnostic("Rule files the yara service would not load", not_loaded.length,
                small_table(["Commit", "Path", "Why"], not_loaded)));
        }
        if (refused.length) {
            section.appendChild(diagnostic("Archive members refused", refused.length,
                small_table(["Commit", "Path", "Why"], refused)));
        }
        if (report.skipped.length || report.truncated_paths) {
            const content = [];
            if (report.truncated_paths) {
                content.push(el("div", "text-muted small mb-1", report.truncated_paths +
                    " sample path(s) were truncated when captured, so a rule filtering on the file name may differ."));
            }
            content.push(small_table(["SHA256", "File", "Why", "Detail"], report.skipped.map(function(item) {
                return [short_sha(item.sha256), item.file_path || "", item.reason, item.detail];
            })));
            section.appendChild(diagnostic("Samples not scanned", report.skipped.length, content));
        }

        section.appendChild(diagnostic("Scan time per namespace", timing_rows(report).length, timings_table(report)));

        section.appendChild(diagnostic("The run", null, definition_list([
            ["Scanned", report.units + " unit(s) of " + report.samples + " sample(s), " + report.files + " file(s), " + size(report.bytes)],
            ["Duration", seconds(report.duration_seconds)],
            ["Rules", "base " + report.base.rule_count + ", head " + report.head.rule_count],
            ["yara / yara_scanner", [report.yara_python_version, report.yara_scanner_version].filter(Boolean).join(" / ")],
            ["Attempts", validation.attempts],
            ["Worker", validation.claimed_by],
            ["Corpus version", el("code", null, validation.corpus_version)],
            ["Engine fingerprint", el("code", null, validation.engine_fingerprint)],
        ])));
        return section;
    }

    function timing_rows(report) {
        const names = {};
        Object.keys(report.base.timings).concat(Object.keys(report.head.timings)).forEach(function(name) { names[name] = true; });
        return Object.keys(names).sort().map(function(name) {
            return {name: name, base: report.base.timings[name] || {}, head: report.head.timings[name] || {}};
        });
    }

    function timings_table(report) {
        const rows = timing_rows(report).map(function(row) {
            const base = row.base.scan_seconds;
            const head = row.head.scan_seconds;
            let delta = "";
            if (base !== undefined && head !== undefined) {
                const change = head - base;
                // slower by a quarter and by more than noise
                delta = el("span", change > 0.1 && head > base * 1.25 ? "text-warning-emphasis fw-semibold" : null,
                           (change >= 0 ? "+" : "") + change.toFixed(2) + " s");
            }
            return [row.name, row.base.rules === undefined ? "" : row.base.rules, row.head.rules === undefined ? "" : row.head.rules,
                    seconds(row.base.compile_seconds), seconds(row.head.compile_seconds), seconds(base), seconds(head), delta];
        });
        return small_table(["Namespace", "Rules (base)", "Rules (head)", "Compile (base)", "Compile (head)",
                            "Scan (base)", "Scan (head)", "Scan change"], rows);
    }

    document.addEventListener("DOMContentLoaded", function() {
        const list = document.getElementById("validations_page");
        if (list) {
            start_list(list);
        }
        const detail = document.getElementById("validation_detail_page");
        if (detail) {
            start_detail(detail);
        }
    });
})();
