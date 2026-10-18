// Signatures -> Samples (docs/SVS_SAMPLES.md, GUI): the list of samples and a sample's page.
//
// Both pages are shells over /api/v2/svs/samples, called from the browser with the Flask session
// cookie. The list is a FilterListPage (filter_list_page.js) on the svs_samples filter screen.
// Files are plain links to the API: the browser saves the zip, which is encrypted with the
// password "infected". Every value shown came from analyzed data or rule files, so it is placed
// as text, never markup.
//
// A sample's page also offers the actions (docs/SVS_SAMPLES.md, Actions) its user may take:
// relabel, reset and confirm with alert:write, retire and delete with svs:admin. The API checks
// the permissions again; the page only leaves out what would be refused.

(function() {
    "use strict";

    const VOTE_STRENGTHS = [
        ["explicit", "explicit"],
        ["inherited_single", "inherited"],
        ["inherited_multi", "unconfirmed"],
    ];

    const MISSING_REASONS = {
        file: "the file was gone or had changed",
        storage: "the store refused the file",
        match_record: "the match record was gone",
    };

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

    function short_version(version) {
        return /^[0-9a-f]{40}$/.test(version) ? version.substring(0, 10) : version;
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

    // a sample's label: tp and fp are verdicts and look like one; conflicted asks for a person
    function label_node(row) {
        if (!row.label) {
            const none = el("span", "text-muted", "–");
            none.title = "no label: no contributing detection has a verdict (its alerts are unclassified, deleted, or from an unreviewed test run)";
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

    function vote_totals(votes) {
        let tp = 0;
        let fp = 0;
        VOTE_STRENGTHS.forEach(function(strength) {
            tp += votes["tp_" + strength[0]];
            fp += votes["fp_" + strength[0]];
        });
        return {tp: tp, fp: fp};
    }

    function votes_node(votes) {
        const totals = vote_totals(votes);
        const node = el("span", "text-nowrap", "TP " + totals.tp + " · FP " + totals.fp);
        node.title = VOTE_STRENGTHS.map(function(strength) {
            return strength[1] + ": TP " + votes["tp_" + strength[0]] + ", FP " + votes["fp_" + strength[0]];
        }).join("\n");
        return node;
    }

    function page_settings(page) {
        const data = page.dataset;
        return {
            api: data.api,
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            list_url: data.listUrl,
            alert_url: data.alertUrl,
            tz: data.tz,
            can_download: data.canDownload === "true",
            can_relabel: data.canRelabel === "true",
            can_admin: data.canAdmin === "true",
            max_bulk_files: data.maxBulkFiles,
        };
    }

    function retired_title(row) {
        return "retired for this rule by " + (row.retired_by || "a deleted user") + " on " + date(row.retired_at) +
            " UTC: " + row.retired_reason + ". YARA validations only count it.";
    }

    function detail_url(settings, sha256, rule_uuid) {
        return settings.list_url + "/" + encodeURIComponent(sha256) + "/" + encodeURIComponent(rule_uuid);
    }

    //
    // the list
    //

    function start_list(page) {
        const settings = page_settings(page);

        const columns = [
            {label: "Label", sort: "label", sortDesc: false, width: "9rem", render: label_node},
            {label: "Rule", sort: "rule", sortDesc: false, width: "20%", css: "text-break-all", render: function(row) {
                const cell = el("div");
                append(cell, link(detail_url(settings, row.sha256, row.rule_uuid), row.rule_name, "fw-semibold"));
                if (row.namespace) {
                    append(cell, el("div", "text-muted small", row.namespace));
                }
                return cell;
            }},
            {label: "File", width: "20%", css: "text-break-all", render: function(row) {
                const cell = el("div", null, row.file_path);
                if (row.file_size !== null && row.file_size !== undefined) {
                    append(cell, el("div", "text-muted small", size(row.file_size)));
                }
                return cell;
            }},
            {label: "SHA256", sort: "sha256", sortDesc: false, width: "12rem", render: function(row) {
                const code = el("code", null, row.sha256.substring(0, 16) + "…");
                code.title = row.sha256;
                return append(el("span", "text-nowrap"), code, copy_button(row.sha256, "copy the sha256"));
            }},
            {label: "Captures", sort: "capture_count", width: "7rem", title: "how many graded alerts it was captured from", render: function(row) {
                const cell = el("span", null, row.capture_count);
                if (row.missing) {
                    append(cell, el("div", "text-danger small", row.missing + " missing"));
                }
                return cell;
            }},
            {label: "Votes", width: "8rem", title: "the verdicts of its contributing detections; hover for each strength", render: function(row) {
                return votes_node(row.votes);
            }},
            {label: "First captured", sort: "first_captured", width: "10rem", title: "UTC", render: function(row) { return date(row.first_captured); }},
            {label: "Last captured", sort: "last_captured", width: "10rem", title: "UTC", render: function(row) { return date(row.last_captured); }},
            {label: "", width: "4.5rem", render: function(row) {
                const cell = el("span", "text-nowrap");
                if (row.retired) {
                    append(cell, icon("bi-archive", retired_title(row), "text-muted me-1"));
                }
                if (row.unknown_version) {
                    append(cell, icon("bi-exclamation-triangle", row.unknown_version +
                        " capture(s) with signature version unknown: the rule's repository is not in service_yara.git_repo_dirs",
                        "text-warning me-1"));
                }
                if (row.missing_data) {
                    append(cell, icon("bi-file-earmark-x", row.missing_data + " capture(s) missing their file or match record", "text-danger"));
                }
                return cell;
            }},
        ];

        const list = FilterListPage.create({
            root: document.getElementById("samples_list"),
            screen: settings.screen,
            api: settings.path,
            columns: columns,
            defaultSort: "last_captured",
            defaultDesc: true,
            pageSizes: [25, 50, 100, 250],
            defaultLimit: 50,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: settings.can_download ? {
                path: "/download",
                hint: "the files of every sample these filters match, in one zip (password: infected), up to " +
                      settings.max_bulk_files + " files",
            } : null,
            emptyText: "No samples match these filters.",
        });

        load_missing(settings, list);
    }

    // captures that lost their file or match record, per rule, linked to the filtered list
    function load_missing(settings, list) {
        const banner = document.getElementById("samples_missing");
        aceApi.get(settings.path + "/missing").then(function(rows) {
            if (rows.length === 0) {
                return;
            }

            const rules = {};
            let total = 0;
            rows.forEach(function(row) {
                total += row.count;
                if (!rules[row.rule_uuid]) {
                    rules[row.rule_uuid] = {rule_uuid: row.rule_uuid, rule_name: row.rule_name, count: 0};
                }
                rules[row.rule_uuid].count += row.count;
            });
            const by_count = Object.values(rules).sort(function(a, b) { return b.count - a.count; });

            function show(rule_uuid) {
                const filters = [{name: "Missing Data", inverted: false, values: ["true"]}];
                if (rule_uuid) {
                    filters.push({name: "Signature", inverted: false, values: [rule_uuid]});
                }
                return function(event) {
                    event.preventDefault();
                    list.setFilters(filters);
                };
            }

            const summary = el("div");
            append(summary, icon("bi-file-earmark-x", "missing data", "me-1"),
                   total + " capture(s) of " + by_count.length + " rule(s) are missing their file or match record. ");
            const all = link("#", "Show them");
            all.addEventListener("click", show(null));
            append(summary, all);

            const top = el("div", "small mt-1");
            by_count.slice(0, 5).forEach(function(rule, index) {
                if (index) {
                    append(top, " · ");
                }
                const item = link("#", rule.rule_name);
                item.title = rule.rule_uuid;
                item.addEventListener("click", show(rule.rule_uuid));
                append(top, item, " (" + rule.count + ")");
            });
            if (by_count.length > 5) {
                append(top, " · …");
            }

            banner.replaceChildren(summary, top);
            banner.classList.remove("d-none");
        }).catch(function(err) {
            console.error("unable to load the missing captures", err);
        });
    }

    //
    // one sample
    //

    function start_detail(page) {
        const settings = page_settings(page);
        const sha256 = page.dataset.sha256;
        const rule_uuid = page.dataset.ruleUuid;
        const error = document.getElementById("sample_error");
        const notice = document.getElementById("sample_notice");
        const target = document.getElementById("sample_detail");

        const context = {
            settings: settings,
            // the API paths of the sample, and of its file (deletion is per file, for every rule)
            path: settings.path + "/" + encodeURIComponent(sha256) + "/" + encodeURIComponent(rule_uuid),
            file_path: settings.path + "/" + encodeURIComponent(sha256),
            reload: load,
            // a message above the sample: kind "error" or "info", text or nodes
            notify: function(kind, content) {
                const box = kind === "error" ? error : notice;
                (kind === "error" ? notice : error).classList.add("d-none");
                box.replaceChildren();
                append.apply(null, [box].concat(content));
                box.classList.remove("d-none");
            },
        };

        function load() {
            return aceApi.get(context.path)
                .then(function(sample) { render_detail(context, target, sample); })
                .catch(function(err) {
                    target.replaceChildren();
                    context.notify("error", "Unable to load the sample: " + err.message);
                });
        }

        setup_reason_modal();
        load();
    }

    //
    // actions
    //

    // what the reason dialog does on submit: a function(reason) returning a promise
    let reason_action = null;

    function setup_reason_modal() {
        const form = document.getElementById("sample_reason_form");
        if (!form) {
            return;
        }
        form.addEventListener("submit", function(event) {
            event.preventDefault();
            const reason = document.getElementById("sample_reason").value.trim();
            const error = document.getElementById("sample_reason_error");
            if (!reason) {
                error.textContent = "A reason is required.";
                error.classList.remove("d-none");
                return;
            }
            const submit = document.getElementById("sample_reason_submit");
            submit.disabled = true;
            reason_action(reason)
                .then(function() {
                    bootstrap.Modal.getOrCreateInstance(document.getElementById("sample_reason_modal")).hide();
                })
                .catch(function(err) {
                    error.textContent = err.message;
                    error.classList.remove("d-none");
                })
                .finally(function() { submit.disabled = false; });
        });
    }

    // options: title, text (text or nodes), button, button_css, submit(reason) -> promise
    function open_reason(options) {
        document.getElementById("sample_reason_title").textContent = options.title;
        const text = document.getElementById("sample_reason_text");
        text.replaceChildren();
        append.apply(null, [text].concat(options.text));
        const submit = document.getElementById("sample_reason_submit");
        submit.textContent = options.button;
        submit.className = "btn " + options.button_css;
        document.getElementById("sample_reason").value = "";
        document.getElementById("sample_reason_error").classList.add("d-none");
        reason_action = options.submit;
        bootstrap.Modal.getOrCreateInstance(document.getElementById("sample_reason_modal")).show();
    }

    function action_button(text, css, title, onclick) {
        const button = el("button", "btn btn-sm " + css, text);
        button.type = "button";
        button.title = title;
        button.addEventListener("click", onclick);
        return button;
    }

    // what a relabel, reset or confirm did, and the detections it could not write
    function label_result(context, result) {
        const content = [result.changed + " detection(s) changed" +
            (result.unchanged ? ", " + result.unchanged + " already as asked" : "") + "."];
        if (result.skipped.length) {
            content.push(" " + result.skipped.length + " skipped:");
            const list = el("ul", "mb-0 small");
            result.skipped.forEach(function(skipped) {
                const item = el("li");
                const alert_link = link(context.settings.alert_url + "?direct=" + encodeURIComponent(skipped.alert_uuid), "alert");
                alert_link.title = skipped.alert_uuid;
                alert_link.target = "_blank";
                alert_link.rel = "noopener";
                append(item, alert_link, ": " + skipped.reason);
                list.appendChild(item);
            });
            content.push(list);
        }
        context.notify("info", content);
        return context.reload();
    }

    function label_action(context, question, request) {
        return function() {
            if (!window.confirm(question)) {
                return;
            }
            request()
                .then(function(result) { return label_result(context, result); })
                .catch(function(err) { context.notify("error", err.message); });
        };
    }

    function action_buttons(context, sample) {
        const settings = context.settings;
        const buttons = [];
        const votes = sample.votes;

        // relabel is offered only when it would write something (sample.relabel_refusal says why not)
        if (settings.can_relabel && !sample.relabel_refusal) {
            ["tp", "fp"].forEach(function(verdict) {
                const name = verdict.toUpperCase();
                buttons.push(action_button("Relabel " + name, "btn-outline-dark",
                    "store an explicit " + name + " on every detection of this rule on this file",
                    label_action(context,
                        "Relabel this sample " + name + "? This stores an explicit " + name + " verdict on every detection of " +
                        "this rule on this file, on every alert it was captured from that analysts can grade.",
                        function() { return aceApi.put(context.path + "/label", {verdict: verdict}); })));
            });
        }
        if (settings.can_relabel) {
            if (votes.tp_explicit + votes.fp_explicit > 0) {
                buttons.push(action_button("Reset to inherited", "btn-outline-dark",
                    "clear the explicit verdicts, so the label follows the alerts' dispositions again",
                    label_action(context,
                        "Reset this sample's label? This clears the explicit verdicts on its detections, so they inherit " +
                        "from their alerts' dispositions again.",
                        function() { return aceApi.del(context.path + "/label"); })));
            }
            if (votes.tp_inherited_multi > 0) {
                buttons.push(action_button("Confirm", "btn-outline-dark",
                    "confirm the unconfirmed TP detections, so they weigh as a person's verdict",
                    label_action(context,
                        "Confirm this sample's unconfirmed TP detections? They were inherited on alerts where several " +
                        "signatures fired; confirming stores an explicit TP on each.",
                        function() { return aceApi.post(context.path + "/confirm"); })));
            }
        }

        if (settings.can_admin) {
            if (sample.retired) {
                buttons.push(action_button("Unretire", "btn-outline-dark", "expect this file to match the rule again",
                    function() {
                        if (!window.confirm("Unretire this sample? YARA validations will expect it to match this rule again.")) {
                            return;
                        }
                        aceApi.del(context.path + "/retirement")
                            .then(function() { context.notify("info", "The sample is no longer retired."); return context.reload(); })
                            .catch(function(err) { context.notify("error", err.message); });
                    }));
            } else {
                buttons.push(action_button("Retire", "btn-outline-dark", "no longer expect this file to match the rule",
                    function() {
                        open_reason({
                            title: "Retire sample",
                            text: "Retire this sample for " + sample.rule_name + ": it is no longer expected to match this " +
                                  "rule, and YARA validations only count it. It can be unretired later.",
                            button: "Retire",
                            button_css: "btn-outline-primary",
                            submit: function(reason) {
                                return aceApi.put(context.path + "/retirement", {reason: reason}).then(function() {
                                    context.notify("info", "The sample is retired for this rule.");
                                    return context.reload();
                                });
                            },
                        });
                    }));
            }
            buttons.push(action_button("Delete sample", "btn-outline-danger",
                "delete the file from SVS, for every rule (legal or privacy requests)",
                function() { open_delete(context, sample); }));
        }

        return buttons;
    }

    function open_delete(context, sample) {
        const rules = el("p", "mb-2", "This file has samples for every rule it was captured for; all of them are deleted.");
        aceApi.get(context.settings.path + "/" + aceApi.query({f: "sha256:" + sample.sha256, limit: 1000}))
            .then(function(page) {
                rules.textContent = "This file has samples for " + page.data.length + " rule(s); all of them are deleted.";
            })
            .catch(function() { /* the generic sentence stays */ });

        const removes = el("ul", "small mb-2");
        ["its captures and retirements, for every rule",
         "its stored bytes (its match records are released and removed by storage cleanup)"].forEach(function(text) {
            removes.appendChild(el("li", null, text));
        });
        const keeps = el("ul", "small mb-2");
        ["the alerts' own copies of the file",
         "YARA QA results",
         "copies in other nodes' read caches, until they are evicted"].forEach(function(text) {
            keeps.appendChild(el("li", null, text));
        });

        open_reason({
            title: "Delete sample file",
            text: [rules, el("div", "fw-semibold small", "Removed:"), removes, el("div", "fw-semibold small", "Not removed:"), keeps,
                   el("p", "small mb-0", "An audit record of who deleted it and why is kept, and the file is never captured again.")],
            button: "Delete",
            button_css: "btn-danger",
            submit: function(reason) {
                return aceApi.request("DELETE", context.file_path, {reason: reason}).then(function(deletion) {
                    if (!deletion.purged_at) {
                        window.alert("The sample is deleted, but its file could not be purged yet (a legal hold or a storage " +
                                     "failure). Delete it again later to retry.");
                    }
                    window.location = context.settings.list_url + aceApi.query({f: "sha256:" + sample.sha256});
                });
            },
        });
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

    function render_detail(context, target, sample) {
        const settings = context.settings;
        const header = el("div", "mb-3");
        append(header, el("h2", "mb-1 text-break", sample.rule_name));

        const rule = append(el("span"), el("code", null, sample.rule_uuid), copy_button(sample.rule_uuid, "copy the rule uuid"));
        const sha = append(el("span"), el("code", null, sample.sha256), copy_button(sample.sha256, "copy the sha256"));
        append(header, definition_list([
            ["Rule uuid", rule],
            ["Namespace", sample.namespace],
            ["SHA256", sha],
            ["File", sample.file_path + (sample.file_size !== null && sample.file_size !== undefined ? " (" + size(sample.file_size) + ")" : "")],
            ["Captured", date(sample.first_captured) + " – " + date(sample.last_captured) + " UTC"],
        ]));

        // the label, its votes, and what can be done with the sample
        const label = el("div", "card mb-3");
        const body = el("div", "card-body");
        const heading = el("div", "d-flex flex-wrap align-items-center gap-2 mb-2");
        append(heading, el("span", "fw-semibold", "Label"), label_node(sample));
        if (!sample.label) {
            append(heading, el("span", "text-muted small", "no contributing detection has a verdict"));
        } else if (sample.label === "conflicted") {
            append(heading, el("span", "text-muted small",
                "votes of the strongest strength (" + aceVerdicts.SOURCE_LABELS[sample.label_source] + ") disagree"));
        }
        body.appendChild(heading);
        if (sample.retired) {
            const retired = el("div", "small mb-2");
            append(retired, icon("bi-archive", "retired", "me-1"), "R" + retired_title(sample).substring(1));
            body.appendChild(retired);
        }

        const votes = el("table", "table table-sm table-bordered w-auto small mb-2");
        const head = votes.createTHead().insertRow();
        ["", "TP", "FP"].forEach(function(text) { head.appendChild(el("th", null, text)); });
        const rows = votes.createTBody();
        VOTE_STRENGTHS.forEach(function(strength) {
            const row = rows.insertRow();
            const name = el("th", "fw-normal", strength[1]);
            name.title = aceVerdicts.SOURCE_TITLES[strength[0]];
            row.appendChild(name);
            row.appendChild(el("td", null, sample.votes["tp_" + strength[0]]));
            row.appendChild(el("td", null, sample.votes["fp_" + strength[0]]));
        });
        body.appendChild(votes);
        body.appendChild(el("div", "text-muted small mb-2",
            "The strongest strength that has a vote decides: explicit, then inherited, then unconfirmed."));

        const actions = el("div", "d-flex flex-wrap align-items-center gap-2");
        const rule_samples = link("#", "All samples of this rule", "btn btn-sm btn-outline-dark");
        aceApi.post("/filter-screens/" + encodeURIComponent(settings.screen) + "/encode",
                    {filters: [{name: "Signature", inverted: false, values: [sample.rule_uuid]}]})
            .then(function(result) { rule_samples.href = settings.list_url + aceApi.query({f: result.f}); })
            .catch(function() { rule_samples.classList.add("disabled"); });
        actions.appendChild(rule_samples);
        if (settings.can_download) {
            if (sample.local) {
                const download = link(settings.api + "/" + encodeURIComponent(sample.sha256) + "/" + encodeURIComponent(sample.rule_uuid) + "/download",
                                      "Download sample", "btn btn-sm btn-outline-dark");
                download.title = "the file and its match records, in a zip protected with the password infected";
                actions.appendChild(download);
            } else {
                actions.appendChild(el("span", "text-muted small", "The file is stored on another node; download it there."));
            }
        }
        action_buttons(context, sample).forEach(function(button) { actions.appendChild(button); });
        if (context.settings.can_relabel && sample.relabel_refusal) {
            actions.appendChild(el("span", "small text-muted", "Can't be relabeled: " + sample.relabel_refusal + "."));
        }
        body.appendChild(actions);
        label.appendChild(body);

        target.replaceChildren(header, label, captures_table(settings, sample));
    }

    function captures_table(settings, sample) {
        const section = el("div");
        append(section, el("h5", null, "Captures (" + sample.captures.length + ")"));

        const table = el("table", "table table-sm table-bordered filter-list-table small");
        const head = table.createTHead().insertRow();
        [["Captured", "9rem"], ["Alert", "5rem"], ["File", "22%"], ["Version", "8rem"], ["State", "9rem"],
         ["Verdicts", "11rem"], ["Node", "7rem"], ["", "9rem"]].forEach(function(column) {
            const th = el("th", null, column[0]);
            th.style.width = column[1];
            head.appendChild(th);
        });

        const body = table.createTBody();
        sample.captures.forEach(function(capture) {
            const row = body.insertRow();
            row.appendChild(el("td", null, date(capture.created_at)));

            const alert = el("td");
            const alert_link = link(settings.alert_url + "?direct=" + encodeURIComponent(capture.alert_uuid), "Alert");
            alert_link.title = capture.alert_uuid;
            alert_link.target = "_blank";
            alert_link.rel = "noopener";
            alert.appendChild(alert_link);
            row.appendChild(alert);

            const file = el("td", "text-break-all", capture.file_path);
            if (capture.yara_meta_tags.length) {
                file.appendChild(el("div", "text-muted", capture.yara_meta_tags.join(", ")));
            }
            row.appendChild(file);

            const version = el("td");
            const code = el("code", null, short_version(capture.signature_version));
            code.title = capture.signature_version;
            version.appendChild(code);
            if (capture.signature_version === "unknown") {
                version.appendChild(icon("bi-exclamation-triangle",
                    "the rule's repository is not in service_yara.git_repo_dirs, so the version it was graded under is lost",
                    "text-warning ms-1"));
            }
            row.appendChild(version);

            const state = el("td", capture.state === "missing" ? "text-danger" : null, capture.state);
            if (capture.missing_reason) {
                state.appendChild(el("div", capture.state === "missing" ? null : "text-danger",
                                     MISSING_REASONS[capture.missing_reason] || capture.missing_reason));
            }
            row.appendChild(state);

            const verdicts = el("td");
            if (capture.detections.length === 0) {
                const none = el("span", "text-muted", "alert deleted");
                none.title = "the alert is gone, so this capture casts no vote";
                verdicts.appendChild(none);
            }
            capture.detections.forEach(function(detection) {
                if (detection.verdict) {
                    verdicts.appendChild(aceVerdicts.badge(detection.verdict, detection.verdict_source));
                } else {
                    verdicts.appendChild(el("span", "text-muted ms-1", "no verdict"));
                }
            });
            row.appendChild(verdicts);

            row.appendChild(el("td", "text-break-all", capture.node));

            const actions = el("td", "text-nowrap");
            const match = el("button", "btn btn-xs btn-outline-secondary", "Match");
            match.type = "button";
            match.title = "what the rule matched";
            actions.appendChild(match);
            if (capture.has_record) {
                if (capture.local) {
                    const record = link(settings.api + "/captures/" + capture.id + "/record", "Record", "btn btn-xs btn-outline-secondary ms-1");
                    record.target = "_blank";
                    record.rel = "noopener";
                    record.title = "the full match record (JSON)";
                    actions.appendChild(record);
                } else {
                    actions.appendChild(el("span", "text-muted ms-1", "record on " + capture.node));
                }
            }
            row.appendChild(actions);

            const detail = body.insertRow();
            detail.className = "d-none";
            const detail_cell = el("td");
            detail_cell.colSpan = 8;
            detail_cell.appendChild(match_summary(capture));
            detail.appendChild(detail_cell);
            match.addEventListener("click", function() { detail.classList.toggle("d-none"); });
        });

        if (sample.captures.length === 0) {
            const row = body.insertRow();
            const cell = el("td", "text-muted", "No captures.");
            cell.colSpan = 8;
            row.appendChild(cell);
        }

        section.appendChild(table);
        return section;
    }

    function match_summary(capture) {
        const summary = capture.match_summary || {};
        const container = el("div", "bg-light p-2");
        if (!capture.has_record && Object.keys(summary).length === 0) {
            container.appendChild(el("span", "text-muted", "No match record was kept for this capture."));
            return container;
        }

        container.appendChild(definition_list([
            ["Rule", summary.rule],
            ["Namespace", summary.namespace],
            ["Tags", (summary.tags || []).join(", ")],
            ["String matches", summary.string_match_count],
            ["Rule content hash", capture.rule_content_hash],
            ["yara / yara_scanner", [capture.yara_python_version, capture.yara_scanner_version].filter(Boolean).join(" / ")],
        ]));

        if ((summary.strings || []).length) {
            const strings = el("table", "table table-sm table-bordered w-auto mt-2 mb-2");
            const head = strings.createTHead().insertRow();
            ["String", "Matches", "First offset"].forEach(function(text) { head.appendChild(el("th", null, text)); });
            const rows = strings.createTBody();
            summary.strings.forEach(function(s) {
                const row = rows.insertRow();
                row.appendChild(append(el("td"), el("code", null, s.identifier)));
                row.appendChild(el("td", null, s.count));
                row.appendChild(el("td", null, s.first_offset === null ? "" : "0x" + s.first_offset.toString(16)));
            });
            container.appendChild(strings);
        }

        const meta = el("pre", "small mb-0", JSON.stringify(summary.meta || {}, null, 2));
        meta.style.maxHeight = "16rem";
        meta.style.overflow = "auto";
        container.appendChild(meta);
        return container;
    }

    document.addEventListener("DOMContentLoaded", function() {
        const list = document.getElementById("samples_page");
        if (list) {
            start_list(list);
        }
        const detail = document.getElementById("sample_detail_page");
        if (detail) {
            start_detail(detail);
        }
    });
})();
