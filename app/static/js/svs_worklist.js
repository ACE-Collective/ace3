// SVS -> Worklist (docs/SVS_COVERAGE.md, *In the GUI*): the declared-vs-measured worklist, grouped per
// signature, and one signature's page.
//
// The list is a FilterListPage (filter_list_page.js) over /api/v2/svs/worklist on the svs_worklist
// filter screen, and opens on the tags that need a decision. The API orders it by signature, then
// technique, and each signature's rows sit under one header (the list's group option). The signature
// page is a shell over /api/v2/svs/worklist/{signature_uuid}: every row of the signature, retired ones
// included, and the techniques it is measured on with the tests that measure it.
//
// With svs:run_manage a tag no test confirms is kept or removed (a reason, and for a removal the pull
// request), one row at a time or the selected rows in bulk, and a resolution can be cleared (Reopen).
// Every value shown came from a signature, a catalog or a person, so it is placed as text, never
// markup. A status is plain text, not a badge.

(function() {
    "use strict";

    // docs/SVS_COVERAGE.md, *The worklist*
    const WORKLIST_STATUSES = {
        confirmed: {css: "text-success", title: "a test measures the signature on the technique, or on one of its sub-techniques"},
        open: {css: "fw-semibold", title: "no test confirms the tag, and nobody resolved it"},
        kept: {css: "text-primary", title: "resolved keep: the tag covers something no test reaches"},
        remove_pending: {css: "text-warning-emphasis",
                         title: "resolved remove, and the signature still has the tag: it doesn't count toward coverage"},
        removed: {css: "text-muted", title: "resolved remove, and the tag is gone"},
        undeclared: {css: "text-muted", title: "information only: the signature is measured on it, and no tag names it"},
        unknown: {css: "text-muted", title: "information only: a tag names an id the pinned ATT&CK release doesn't have"},
        retired: {css: "text-muted",
                  title: "the signature isn't measured any more, or the tag went away without a remove; a resolution is kept"},
    };

    const KINDS = {
        declared: "a tag of the signature",
        undeclared: "a technique the signature is measured on that no tag names",
        unknown: "a tag naming an id the pinned ATT&CK release doesn't have",
    };

    // what can be done to a row, by its status (the API answers 409 to anything else)
    const ROW_ACTIONS = {
        open: ["keep", "remove"],
        kept: ["remove", "reopen"],
        remove_pending: ["keep", "reopen"],
    };

    const RESOLUTIONS = {
        keep: {
            label: "Keep…",
            title: "the tag covers something no test reaches: it keeps counting",
            text: "The tag covers something no test reaches, so it keeps counting toward coverage as a manual mapping.",
            submit: "Keep",
            done: "Kept",
            hint: "optional: a link that explains it",
        },
        remove: {
            label: "Remove…",
            title: "the signature repository will drop the tag: it stops counting",
            text: "The signature repository will drop the tag. It stops counting toward coverage from the next " +
                  "refresh, while the signature still has it.",
            submit: "Remove",
            done: "Resolved remove on",
            hint: "the pull request removing the tag",
        },
    };

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

    function button(text, title, onclick) {
        const result = el("button", "btn btn-xs btn-outline-dark", text);
        result.type = "button";
        result.title = title;
        result.addEventListener("click", onclick);
        return result;
    }

    function parse_json(value, fallback) {
        try {
            return JSON.parse(value || "");
        } catch (e) {
            return fallback;
        }
    }

    function page_settings(page) {
        const data = page.dataset;
        return {
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            default_f: parse_json(data.defaultF, []),
            signature: data.signature,
            worklist_f: parse_json(data.worklistF, []),
            worklist_url: data.worklistUrl,
            signature_url: data.signatureUrl,
            technique_url: data.techniqueUrl,
            test_url: data.testUrl,
            can_manage: data.canManage === "true",
            tz: data.tz,
        };
    }

    function url(template, placeholder, value) {
        return template.replace(placeholder, encodeURIComponent(value));
    }

    function message(content, css) {
        const node = document.getElementById("svs_worklist_message");
        node.replaceChildren();
        if (!content) {
            node.className = "alert d-none";
            return;
        }
        append(node, content);
        node.className = "alert " + (css || "alert-info");
    }

    function signature_label(row) {
        return row.signature_name || row.signature_uuid;
    }

    function row_label(row) {
        return signature_label(row) + ": " + row.technique + (row.technique_name ? " " + row.technique_name : "");
    }

    function row_path(settings, row) {
        return settings.path + "/" + encodeURIComponent(row.signature_uuid) + "/" + encodeURIComponent(row.technique) +
               "/resolution";
    }

    //
    // the row's cells
    //

    function technique_node(settings, row) {
        const node = el("div");
        // an unknown id has no coverage drill-down: the release doesn't have it and it doesn't count
        append(node, row.kind === "unknown"
            ? mono(row.technique)
            : link(url(settings.technique_url, "__TECHNIQUE__", row.technique), row.technique, "text-nowrap"));
        if (row.technique_name) {
            node.appendChild(el("div", "small", row.technique_name));
        }
        const tagged = row.declared_as.filter(function(id) { return id !== row.technique; });
        if (tagged.length) {
            const note = el("div", "small text-muted", "tagged " + row.declared_as.join(", "));
            note.title = "the tag ids, as the signature writes them, that count as " + row.technique;
            node.appendChild(note);
        }
        return node;
    }

    function kind_node(row) {
        const node = el("span", row.kind === "declared" ? null : "text-muted", row.kind);
        node.title = KINDS[row.kind] || "";
        return node;
    }

    function status_node(row) {
        const info = WORKLIST_STATUSES[row.status] || {css: "", title: ""};
        const node = el("div");
        const status = el("span", info.css, row.status.replace("_", " "));
        status.title = info.title;
        node.appendChild(status);
        node.appendChild(el("div", "small text-muted text-nowrap", "since " + date(row.status_changed_at)));
        return node;
    }

    function counts_node(row) {
        if (row.counts) {
            const node = el("span", null, "yes");
            node.title = "the tag counts toward coverage as a manual mapping";
            return node;
        }
        let why = "it doesn't count";
        if (row.kind !== "declared") {
            why = "no tag to count";
        } else if (!row.signature_counts) {
            why = "the signature is disabled, or a YARA rule in QA mode";
        } else if (row.resolution === "remove") {
            why = "resolved remove";
        } else if (!row.tag_present) {
            why = "the signature no longer has the tag";
        }
        const node = append(el("div"), muted("no"));
        node.appendChild(el("div", "small text-muted", why));
        return node;
    }

    function resolution_node(row) {
        if (!row.resolution) {
            return muted("–");
        }
        const node = el("div");
        node.appendChild(el("span", "fw-semibold", row.resolution));
        if (row.reason) {
            node.appendChild(el("div", "small text-break", row.reason));
        }
        if (row.reference) {
            const reference = el("div", "small text-break-all");
            // the API takes only http(s) links; anything else is shown, not linked
            append(reference, /^https?:\/\//i.test(row.reference) ? link(row.reference, row.reference) : row.reference);
            node.appendChild(reference);
        }
        const by = [row.resolved_by, date(row.resolved_at)].filter(Boolean).join(", ");
        if (by) {
            node.appendChild(el("div", "small text-muted", by));
        }
        if (!ROW_ACTIONS[row.status]) {
            node.title = "kept, but it has no effect while the row is " + row.status.replace("_", " ");
        }
        return node;
    }

    function actions_node(settings, row, changed) {
        const node = el("div", "d-flex flex-wrap gap-1");
        (ROW_ACTIONS[row.status] || []).forEach(function(action) {
            if (action === "reopen") {
                node.appendChild(button("Reopen", "clear the resolution: the row needs a decision again", function() {
                    reopen(settings, row).then(function(done) {
                        if (done) {
                            changed();
                        }
                    });
                }));
                return;
            }
            const resolution = RESOLUTIONS[action];
            node.appendChild(button(resolution.label, resolution.title, function() {
                resolve_one(settings, row, action).then(function(done) {
                    if (done) {
                        changed();
                    }
                });
            }));
        });
        return node;
    }

    function columns(settings, changed) {
        const result = [
            {label: "Technique", width: "16rem", render: function(row) { return technique_node(settings, row); }},
            {label: "Kind", width: "7rem", render: kind_node},
            {label: "Status", width: "10rem", title: "as of the last coverage refresh; a resolution changes it at once",
             render: status_node},
            {label: "Counts", width: "10rem", title: "whether the tag counts toward coverage as a manual mapping",
             render: counts_node},
            {label: "Resolution", render: resolution_node},
        ];
        if (settings.can_manage) {
            result.push({label: "", width: "10rem", render: function(row) { return actions_node(settings, row, changed); }});
        }
        return result;
    }

    //
    // resolving (svs:run_manage)
    //

    // shows a modal; bind_submit(done) wires the modal's submit to call done(value) and returns what
    // unwires it. Resolves to that value once the modal is hidden, or to null when the person closes it
    // without submitting.
    function modal_promise(modal, bind_submit) {
        return new Promise(function(resolve) {
            const instance = bootstrap.Modal.getOrCreateInstance(modal);
            let answer = null;
            const unbind = bind_submit(function(value) {
                answer = value;
                instance.hide();
            });
            modal.addEventListener("hidden.bs.modal", function hidden() {
                modal.removeEventListener("hidden.bs.modal", hidden);
                unbind();
                resolve(answer);
            });
            instance.show();
        });
    }

    // asks for a resolution's reason and reference (resolution = keep or remove), or only to confirm
    // (resolution = null, Reopen); resolves to {reason, reference} or null
    function ask(title, text, rows, submit_label, resolution) {
        const modal = document.getElementById("svs_worklist_resolve_modal");
        const form = document.getElementById("svs_worklist_resolve_form");
        const reason = document.getElementById("svs_worklist_resolve_reason");
        const reference = document.getElementById("svs_worklist_resolve_reference");
        const list = document.getElementById("svs_worklist_resolve_rows");
        document.getElementById("svs_worklist_resolve_title").textContent = title;
        document.getElementById("svs_worklist_resolve_text").textContent = text;
        list.replaceChildren.apply(list, rows.map(function(row) { return el("li", null, row_label(row)); }));
        document.getElementById("svs_worklist_resolve_submit").textContent = submit_label;
        document.getElementById("svs_worklist_resolve_fields").classList.toggle("d-none", !resolution);
        document.getElementById("svs_worklist_resolve_reference_hint").textContent =
            resolution ? RESOLUTIONS[resolution].hint : "";
        reason.value = "";
        reference.value = "";
        // a hidden field must not block the form's submit
        reason.required = !!resolution;
        reference.disabled = !resolution;

        return modal_promise(modal, function(done) {
            function submit(event) {
                event.preventDefault();
                if (resolution && !reason.value.trim()) {
                    reason.setCustomValidity("Say why");
                    reason.reportValidity();
                    return;
                }
                done({reason: reason.value.trim(), reference: reference.value.trim() || null});
            }
            function typed() {
                reason.setCustomValidity("");
            }
            form.addEventListener("submit", submit);
            reason.addEventListener("input", typed);
            return function() {
                form.removeEventListener("submit", submit);
                reason.removeEventListener("input", typed);
            };
        });
    }

    // resolves to true when the row changed
    function resolve_one(settings, row, resolution) {
        const info = RESOLUTIONS[resolution];
        message("");
        return ask(info.submit + " the tag", info.text, [row], info.submit, resolution)
            .then(function(answer) {
                if (!answer) {
                    return false;
                }
                return aceApi.put(row_path(settings, row), {resolution: resolution, reason: answer.reason,
                                                            reference: answer.reference})
                    .then(function() {
                        message(info.done + " " + row_label(row) + ".", "alert-success");
                        return true;
                    });
            })
            .catch(function(err) {
                message("Unable to resolve " + row_label(row) + ": " + err.message, "alert-danger");
                return true;
            });
    }

    function reopen(settings, row) {
        message("");
        return ask("Reopen the row",
                   "Clear the resolution: the row needs a decision again, and the tag counts toward coverage again " +
                   "from the next refresh.",
                   [row], "Reopen", null)
            .then(function(answer) {
                if (!answer) {
                    return false;
                }
                return aceApi.del(row_path(settings, row)).then(function() {
                    message("Reopened " + row_label(row) + ".", "alert-success");
                    return true;
                });
            })
            .catch(function(err) {
                message("Unable to reopen " + row_label(row) + ": " + err.message, "alert-danger");
                return true;
            });
    }

    function report(verb, rows_by_key, result) {
        function label(item) {
            const row = rows_by_key[item.signature_uuid + " " + item.technique];
            return row ? row_label(row) : item.signature_uuid + ": " + item.technique;
        }
        const node = el("div");
        node.appendChild(el("div", null, verb + " " + plural(result.done.length, "row") + "."));
        if (result.conflicts.length) {
            const list = el("ul", "mb-0");
            result.conflicts.forEach(function(item) {
                list.appendChild(el("li", null, label(item) + ": " + item.status.replace("_", " ")));
            });
            node.append(el("div", null, "Not resolved, their status can't be:"), list);
        }
        if (result.unknown.length) {
            node.appendChild(el("div", null, "No longer exist: " + result.unknown.map(label).join("; ") + "."));
        }
        const clean = !result.conflicts.length && !result.unknown.length;
        message(node, clean ? "alert-success" : "alert-warning");
    }

    function bulk_actions(settings) {
        return ["keep", "remove"].map(function(resolution) {
            const info = RESOLUTIONS[resolution];
            return {
                label: info.label,
                title: "Resolve the selected rows " + resolution + ": " + info.title,
                run: function(keys, rows) {
                    message("");
                    return ask(info.submit + " " + plural(rows.length, "tag"),
                               info.text + " Rows that are confirmed, information only, retired or removed are left alone.",
                               rows, info.submit, resolution)
                        .then(function(answer) {
                            if (!answer) {
                                return false;
                            }
                            const rows_by_key = {};
                            rows.forEach(function(row) { rows_by_key[row.signature_uuid + " " + row.technique] = row; });
                            return aceApi.post(settings.path + "/bulk/resolve", {
                                resolution: resolution, reason: answer.reason, reference: answer.reference,
                                rows: rows.map(function(row) { return {signature_uuid: row.signature_uuid, technique: row.technique}; }),
                            }).then(function(result) {
                                report(info.done, rows_by_key, result);
                                return true;
                            });
                        });
                },
            };
        });
    }

    //
    // the list
    //

    function group_node(settings, rows) {
        const first = rows[0];
        const node = el("div", "d-flex flex-wrap align-items-baseline column-gap-2");
        node.appendChild(link(url(settings.signature_url, "__SIGNATURE__", first.signature_uuid), signature_label(first),
                              "fw-semibold text-break"));
        if (first.signature_family) {
            node.appendChild(el("span", "small", first.signature_family));
        }
        if (first.signature_name) {
            node.appendChild(mono(first.signature_uuid, "small text-muted"));
        }
        const measured = el("span", "small");
        append(measured, muted("measured on "));
        if (first.measured_techniques.length) {
            first.measured_techniques.forEach(function(technique, index) {
                append(measured, index ? ", " : "", link(url(settings.technique_url, "__TECHNIQUE__", technique), technique));
            });
        } else {
            append(measured, muted("nothing now"));
        }
        node.appendChild(measured);
        // a signature without tags doesn't count either, but then there is nothing to say
        const tagged = rows.some(function(row) { return row.kind !== "undeclared"; });
        if (!first.signature_counts && tagged) {
            const note = el("span", "small text-muted", "disabled or in QA mode: its tags don't count");
            note.title = "the signature is disabled, or a YARA rule in QA mode";
            node.appendChild(note);
        }
        return node;
    }

    function start_list(page) {
        const settings = page_settings(page);
        let list = null;

        list = FilterListPage.create({
            root: document.getElementById("svs_worklist_list"),
            screen: settings.screen,
            api: settings.path,
            columns: columns(settings, function() { list.refresh(); }),
            fitColumns: true,
            // the API has one order, signature then technique, which keeps a signature's rows together
            defaultSort: null,
            defaultDesc: false,
            pageSizes: [50, 100, 250, 500],
            defaultLimit: 100,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: null,
            emptyText: "No worklist rows match these filters.",
            defaultF: settings.default_f,
            group: {
                key: function(row) { return row.signature_uuid; },
                render: function(rows) { return group_node(settings, rows); },
            },
            select: settings.can_manage ? {
                key: function(row) { return row.signature_uuid + " " + row.technique; },
                noun: "row",
                actions: bulk_actions(settings),
            } : null,
        });
    }

    //
    // one signature
    //

    function start_signature(page) {
        const settings = page_settings(page);

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

        function render_rows(detail) {
            const node = document.getElementById("svs_signature_rows");
            const cells = columns(settings, reload);
            const target = table(cells.map(function(column) { return column.label; }));
            detail.rows.forEach(function(row) {
                const tr = el("tr", row.status === "retired" ? "text-muted" : null);
                cells.forEach(function(column) {
                    tr.appendChild(append(el("td"), column.render(row)));
                });
                target.tBodies[0].appendChild(tr);
            });
            node.replaceChildren(append(el("div", "table-responsive"), target));
        }

        function render_measured(detail) {
            const node = document.getElementById("svs_signature_measured");
            node.replaceChildren();
            if (!detail.measured.length) {
                node.appendChild(el("div", "small text-muted",
                                    "No catalog test expects it now; its rows retire at the next coverage refresh."));
                return;
            }
            const target = table(["Technique", "Tests"]);
            detail.measured.forEach(function(item) {
                const technique = append(el("div"), link(url(settings.technique_url, "__TECHNIQUE__", item.technique),
                                                         item.technique, "text-nowrap"));
                if (item.technique_name) {
                    technique.appendChild(el("div", null, item.technique_name));
                }
                const tests = el("ul", "list-unstyled mb-0");
                item.tests.forEach(function(test) {
                    tests.appendChild(append(el("li"), link(url(settings.test_url, "__TEST__", test.guid), test.name || test.guid),
                                             muted(" on " + test.platform)));
                });
                const row = el("tr");
                row.append(append(el("td"), technique), append(el("td"), tests));
                target.tBodies[0].appendChild(row);
            });
            node.appendChild(append(el("div", "table-responsive"), target));
        }

        function render(detail) {
            const title = detail.signature_name || detail.signature_uuid;
            document.title = title + " - SVS worklist";
            document.getElementById("svs_signature_title").textContent = title;
            const subtitle = document.getElementById("svs_signature_subtitle");
            subtitle.replaceChildren();
            append(subtitle, detail.signature_family ? detail.signature_family + " · " : "", mono(detail.signature_uuid),
                   " · ", plural(detail.rows.length, "row"), " · ",
                   link(settings.worklist_url + aceApi.query({f: settings.worklist_f}), "its rows on the Worklist tab"));
            render_rows(detail);
            render_measured(detail);
            document.getElementById("svs_signature_loading").classList.add("d-none");
            document.getElementById("svs_signature_body").classList.remove("d-none");
        }

        function load() {
            return aceApi.get(settings.path + "/" + encodeURIComponent(settings.signature)).then(render);
        }

        function reload() {
            load().catch(function(err) {
                message("Unable to reload the signature: " + err.message, "alert-danger");
            });
        }

        load().catch(function(err) {
            document.getElementById("svs_signature_loading").classList.add("d-none");
            if (err.status === 404) {
                message("No test measures this signature, so it has no worklist rows: its technique tags count as " +
                        "manual mappings.", "alert-info");
            } else {
                message("Unable to load the signature: " + err.message, "alert-danger");
            }
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const list = document.getElementById("svs_worklist_page");
        if (list) {
            start_list(list);
        }
        const signature = document.getElementById("svs_worklist_signature_page");
        if (signature) {
            start_signature(signature);
        }
    });
})();
