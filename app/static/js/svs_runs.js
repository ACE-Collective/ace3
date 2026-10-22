// SVS -> Runs (docs/SVS_RUNS.md, *Following runs*): the test runs, and the same runs one row per
// batch.
//
// Both views are shells over /api/v2/svs/runs, called from the browser with the Flask session
// cookie, and FilterListPages (filter_list_page.js) on the svs_runs filter screen, so they share the
// saved filters and the filters carry over from one to the other. Runs opens on Needs attention.
// With svs:run_manage, runs can be taken, canceled and closed in bulk; a run someone else owns is
// only acted on once the person confirms taking it from them. Every value shown came from a
// launcher, a catalog or a person, so it is placed as text, never markup.

(function() {
    "use strict";

    const STATES = {
        created: {css: "text-muted", title: "registered; the launcher hasn't started it"},
        started: {css: "text-primary", title: "running: its observation window is open"},
        ended: {css: "text-warning-emphasis fw-semibold", title: "the observation window passed; it waits for a review"},
        reviewed: {css: "text-success", title: "signed off"},
        canceled: {css: "text-muted", title: "canceled; it still attributes alerts until its attribution window ends"},
        error: {css: "text-danger fw-semibold", title: "the launcher reported a failure, or never started it"},
        closed: {css: "text-muted", title: "discarded: nothing is learned from it"},
    };

    // how often the time left on started runs is brought up to date
    const TICK_SECONDS = 30;

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

    // the API's times are UTC without an offset
    function utc_ms(value) {
        return Date.parse(/(Z|[+-]\d\d:\d\d)$/.test(value) ? value : value + "Z");
    }

    function plural(count, noun) {
        return count + " " + noun + (count === 1 ? "" : "s");
    }

    function duration(ms) {
        const minutes = Math.max(0, Math.round(ms / 60000));
        if (minutes < 60) {
            return minutes + "m";
        }
        const hours = Math.floor(minutes / 60);
        return hours + "h " + (minutes % 60) + "m";
    }

    function page_settings(page) {
        const data = page.dataset;
        let default_f = [];
        try {
            default_f = JSON.parse(data.defaultF || "[]");
        } catch (e) {
            default_f = [];
        }
        return {
            view: data.view,
            path: data.api.substring(aceApi.BASE.length),  // the API path under /api/v2, for aceApi
            screen: data.screen,
            default_f: default_f,
            runs_url: data.runsUrl,
            batches_url: data.batchesUrl,
            run_url: data.runUrl,
            test_url: data.testUrl,
            tz: data.tz,
            can_manage: data.canManage === "true",
        };
    }

    function message(text_or_node, css) {
        const target = document.getElementById("svs_runs_message");
        target.className = "alert " + (css || "alert-info");
        if (!text_or_node) {
            target.classList.add("d-none");
            target.replaceChildren();
            return;
        }
        target.replaceChildren(text_or_node instanceof Node ? text_or_node : document.createTextNode(text_or_node));
    }

    //
    // the runs' cells
    //

    function run_label(row) {
        return (row.test_name || row.test_guid) + " (" + row.run_id.substring(0, 8) + ")";
    }

    function state_node(row) {
        const state = STATES[row.state] || {css: "", title: ""};
        const node = el("div");
        const name = el("span", state.css, row.state);
        name.title = state.title + (row.error_reason ? ": " + row.error_reason : "") +
            (row.close_reason ? ": " + row.close_reason : "");
        node.appendChild(name);
        if (row.changed_since_review) {
            node.appendChild(el("div", "small text-warning-emphasis", "changed since review"));
        }
        if (row.result_stale) {
            const stale = el("div", "small text-muted", "result updating");
            stale.title = "something changed since the result was computed; it is recomputed shortly";
            node.appendChild(stale);
        }
        return node;
    }

    function test_node(settings, row) {
        const node = el("div");
        node.appendChild(link(settings.run_url.replace("__RUN__", encodeURIComponent(row.run_id)),
                              row.test_name || row.test_guid));
        const details = el("div", "small text-muted");
        const test = link(settings.test_url.replace("__TEST__", encodeURIComponent(row.test_guid)), row.test_guid,
                          "font-monospace text-break-all link-secondary");
        test.title = "the test's page";
        append(details, row.technique ? row.technique + " · " : "", test);
        if (row.technique_name) {
            details.title = row.technique_name;
        }
        node.appendChild(details);
        return node;
    }

    function targets_node(row) {
        const node = el("div", "text-break-all");
        row.targets.forEach(function(target, index) {
            if (index) {
                node.appendChild(el("br"));
            }
            node.appendChild(document.createTextNode(target.username ? target.hostname + "/" + target.username : target.hostname));
        });
        return node;
    }

    function launcher_node(row) {
        const node = el("div", "text-break-all", row.launcher);
        if (row.batch_id) {
            const batch = el("div", "small text-muted", "batch " + row.batch_id);
            node.appendChild(batch);
        }
        return node;
    }

    function times_node(row) {
        const node = el("div", "small text-nowrap");
        [["created", row.created_at], ["started", row.started_at], ["ended", row.ended_at]].forEach(function(item) {
            if (item[1]) {
                node.appendChild(append(el("div"), el("span", "text-muted", item[0] + " "), date(item[1])));
            }
        });
        return node;
    }

    function time_left_node(row) {
        if (row.state !== "started" || !row.observation_ends_at) {
            return null;
        }
        const node = el("span", "svs-time-left text-nowrap");
        node.dataset.endsAt = String(utc_ms(row.observation_ends_at));
        node.title = "the observation window ends at " + date(row.observation_ends_at) + " UTC";
        update_time_left(node);
        return node;
    }

    function update_time_left(node) {
        const left = Number(node.dataset.endsAt) - Date.now();
        node.textContent = left > 0 ? duration(left) : "ending";
    }

    function result_node(row) {
        const node = el("div", "small");
        if (row.result_expected) {
            const hits = el("div", null, row.result_hit + "/" + row.result_expected + " expected");
            hits.title = "expected signatures that fired, of those the result judged";
            node.appendChild(hits);
        }
        if (row.result_missing) {
            const missing = el("div", "text-danger", row.result_missing + " missing");
            if (row.result_possibly_suppressed) {
                missing.appendChild(el("span", "text-muted", " (" + row.result_possibly_suppressed + " possibly suppressed)"));
            }
            node.appendChild(missing);
        }
        if (row.result_candidate) {
            node.appendChild(el("div", "text-warning-emphasis", plural(row.result_candidate, "candidate")));
        }
        if (!node.childNodes.length) {
            node.appendChild(el("span", "text-muted", "–"));
        }
        return node;
    }

    function alerts_node(row) {
        if (!row.alerts) {
            return el("span", "text-muted", "0");
        }
        const node = el("div", "small");
        node.appendChild(el("div", null, plural(row.alerts, "alert")));
        const details = [];
        if (row.marker_alerts) {
            details.push(row.marker_alerts + " by marker");
        }
        if (row.context_alerts) {
            details.push(row.context_alerts + " by context");
        }
        if (row.late_alerts) {
            details.push(row.late_alerts + " late");
        }
        node.appendChild(el("div", "text-muted", details.join(", ")));
        return node;
    }

    //
    // bulk actions
    //

    // shows a modal; bind_submit(done) wires the modal's submit to call done(value) and returns what
    // unwires it. Resolves to that value once the modal is hidden (so the next modal can open), or to
    // null when the person closes it without submitting.
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

    // Cancel and Close ask first; Close asks why, which an ended run needs
    function ask(title, text, rows, submit_label, reason) {
        const modal = document.getElementById("svs_runs_action_modal");
        const form = document.getElementById("svs_runs_action_form");
        const field = document.getElementById("svs_runs_action_reason");
        document.getElementById("svs_runs_action_title").textContent = title;
        document.getElementById("svs_runs_action_text").textContent = text;
        document.getElementById("svs_runs_action_runs").replaceChildren.apply(
            document.getElementById("svs_runs_action_runs"),
            rows.map(function(row) { return el("li", null, run_label(row) + ", " + row.state); }));
        document.getElementById("svs_runs_action_submit").textContent = submit_label;
        document.getElementById("svs_runs_action_reason_group").classList.toggle("d-none", !reason);
        field.value = "";
        field.required = !!(reason && reason.required);
        document.getElementById("svs_runs_action_reason_hint").textContent = reason ? reason.hint : "";

        return modal_promise(modal, function(done) {
            function submit(event) {
                event.preventDefault();
                done({reason: field.value.trim() || null});
            }
            form.addEventListener("submit", submit);
            return function() { form.removeEventListener("submit", submit); };
        });
    }

    // resolves to true when the person agrees to take the runs from their owners
    function confirm_takes(left_alone, rows_by_id) {
        const modal = document.getElementById("svs_runs_take_modal");
        const list = document.getElementById("svs_runs_take_runs");
        list.replaceChildren.apply(list, Object.keys(left_alone).map(function(run_id) {
            const row = rows_by_id[run_id];
            return el("li", null, (row ? run_label(row) : run_id) + ", owned by " + left_alone[run_id]);
        }));
        const button = document.getElementById("svs_runs_take_submit");
        return modal_promise(modal, function(done) {
            function take() { done(true); }
            button.addEventListener("click", take);
            return function() { button.removeEventListener("click", take); };
        }).then(function(value) { return value === true; });
    }

    function report(verb, rows_by_id, result) {
        function label(run_id) {
            return rows_by_id[run_id] ? run_label(rows_by_id[run_id]) : run_id;
        }
        const node = el("div");
        node.appendChild(el("div", null, verb + " " + plural(result.done.length, "run") + "."));
        const left_alone = Object.keys(result.left_alone);
        if (left_alone.length) {
            node.appendChild(el("div", null, "Left alone, someone else owns them: " + left_alone.map(function(run_id) {
                return label(run_id) + " (" + result.left_alone[run_id] + ")";
            }).join("; ") + "."));
        }
        const conflicts = Object.keys(result.conflicts);
        if (conflicts.length) {
            const list = el("ul", "mb-0");
            conflicts.forEach(function(run_id) {
                list.appendChild(el("li", null, label(run_id) + ": " + result.conflicts[run_id]));
            });
            node.append(el("div", null, "Not done:"), list);
        }
        if (result.unknown.length) {
            node.appendChild(el("div", null, "No longer exist: " + result.unknown.join(", ") + "."));
        }
        const clean = !left_alone.length && !conflicts.length && !result.unknown.length;
        message(node, clean ? "alert-success" : "alert-warning");
    }

    // POSTs the bulk action; for the runs it left alone because someone else owns them, asks the
    // person and sends those again, confirmed. Resolves to true: something may have changed.
    function bulk(settings, action, verb, rows, reason) {
        const rows_by_id = {};
        rows.forEach(function(row) { rows_by_id[row.run_id] = row; });
        const url = settings.path + "/bulk/" + action;
        return aceApi.post(url, {run_ids: Object.keys(rows_by_id), reason: reason})
            .then(function(result) {
                if (!Object.keys(result.left_alone).length) {
                    return result;
                }
                return confirm_takes(result.left_alone, rows_by_id).then(function(take) {
                    if (!take) {
                        return result;
                    }
                    return aceApi.post(url, {
                        run_ids: Object.keys(result.left_alone), confirmed_takes: result.left_alone, reason: reason,
                    }).then(function(second) {
                        return {
                            done: result.done.concat(second.done),
                            left_alone: second.left_alone,
                            conflicts: Object.assign({}, result.conflicts, second.conflicts),
                            unknown: result.unknown.concat(second.unknown),
                        };
                    });
                });
            })
            .then(function(result) {
                report(verb, rows_by_id, result);
                return true;
            });
    }

    function bulk_actions(settings) {
        return [
            {
                label: "Take ownership",
                title: "Make the selected runs yours",
                run: function(keys, rows) {
                    message("");
                    return bulk(settings, "take-ownership", "Took", rows, null);
                },
            },
            {
                label: "Cancel…",
                title: "Cancel the selected runs that are created or started, as the launcher would",
                run: function(keys, rows) {
                    message("");
                    return ask("Cancel " + plural(rows.length, "run"),
                               "A canceled run still attributes alerts until its attribution window ends. " +
                               "Runs that are neither created nor started are left as they are.",
                               rows, "Cancel the runs", null)
                        .then(function(answer) {
                            return answer ? bulk(settings, "cancel", "Canceled", rows, null) : false;
                        });
                },
            },
            {
                label: "Close…",
                title: "Discard the selected runs that ended, were canceled or failed: nothing is learned from them",
                run: function(keys, rows) {
                    message("");
                    const ended = rows.some(function(row) { return row.state === "ended"; });
                    return ask("Close " + plural(rows.length, "run"),
                               "Nothing is learned from a closed run, and its alerts are closed as SIMULATED. " +
                               "Only ended, canceled and failed runs can be closed.",
                               rows, "Close the runs",
                               {required: ended, hint: ended ? "An ended run waits for a review: say why it is closed instead."
                                                             : "Optional for canceled and failed runs; required for ended ones."})
                        .then(function(answer) {
                            return answer ? bulk(settings, "close", "Closed", rows, answer.reason) : false;
                        });
                },
            },
        ];
    }

    //
    // the views
    //

    function view_toggle(settings) {
        // the filters carry over: both views read the same f= values
        [["svs_view_runs", settings.runs_url], ["svs_view_batches", settings.batches_url]].forEach(function(item) {
            const button = document.getElementById(item[0]);
            button.addEventListener("click", function(event) {
                event.preventDefault();
                window.location.href = item[1] + window.location.search;
            });
        });
    }

    // the share of missing expected signatures that were possibly suppressed, over the reviewed runs:
    // when it is worth keeping the hunter from suppressing test targets (docs/SVS.md, Part 3, *Hunt
    // suppression*)
    function show_suppression_share(settings) {
        const target = document.getElementById("svs_runs_share");
        if (!target) {
            return;
        }
        aceApi.get(settings.path + "/suppression-share")
            .then(function(share) {
                if (!share.reviewed_runs) {
                    return;
                }
                const percent = share.share === null ? null : Math.round(share.share * 1000) / 10;
                let text = share.missing === 0
                    ? "No expected signature is missing from the " + plural(share.reviewed_runs, "reviewed run") + "."
                    : "Possibly suppressed: " + share.possibly_suppressed + " of the " + share.missing +
                      " missing expected signatures (" + percent + "%) over " + plural(share.reviewed_runs, "reviewed run") + ".";
                if (share.reconsider) {
                    text += " That is more than 10%: suppression a run doesn't key by itself (hunts without group_by, or groups that don't carry the test host) is worth reconsidering.";
                } else if (!share.trigger_reached) {
                    text += " Judged after 50 reviewed runs or 90 days.";
                }
                target.className = "small mb-2 " + (share.reconsider ? "text-warning-emphasis fw-semibold" : "text-muted");
                target.textContent = text;
            })
            .catch(function(err) {
                // the list works without it
                console.error("unable to read the suppression share", err);
            });
    }

    function start_runs(page, settings) {
        show_suppression_share(settings);
        const columns = [
            {label: "State", width: "8rem", render: state_node},
            {label: "Test", render: function(row) { return test_node(settings, row); }},
            {label: "Targets", width: "11%", render: targets_node},
            {label: "Platform", width: "6rem", title: "the platform the run is on", render: function(row) { return row.platform; }},
            {label: "Launcher", width: "10%", title: "and batch", render: launcher_node},
            {label: "Times", width: "14rem", title: "UTC", render: times_node},
            {label: "Time left", width: "6rem", title: "until the observation window of a started run ends", render: time_left_node},
            {label: "Result", width: "10rem", title: "expected signatures that fired, missing ones, and candidates", render: result_node},
            {label: "Alerts", width: "9rem", title: "the alerts attributed to the run", render: alerts_node},
            {label: "Owner", width: "7rem", css: "text-break-all", render: function(row) { return row.owner || ""; }},
            {label: "Reviewer", width: "7rem", css: "text-break-all", render: function(row) { return row.reviewer || ""; }},
        ];

        FilterListPage.create({
            root: document.getElementById("svs_runs_list"),
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
            emptyText: "No runs match these filters.",
            defaultF: settings.default_f,
            select: settings.can_manage ? {
                key: function(row) { return row.run_id; },
                noun: "run",
                actions: bulk_actions(settings),
            } : null,
        });

        window.setInterval(function() {
            document.querySelectorAll(".svs-time-left").forEach(update_time_left);
        }, TICK_SECONDS * 1000);
    }

    function start_batches(page, settings) {
        let list = null;

        // the batch's runs: these filters, with this batch in place of any other
        function open_batch(batch_id) {
            const filters = list.filters().filter(function(entry) { return entry.name !== "Batch" || entry.inverted; });
            filters.push({name: "Batch", inverted: false, values: [batch_id]});
            aceApi.post("/filter-screens/" + encodeURIComponent(settings.screen) + "/encode", {filters: filters})
                .then(function(result) {
                    window.location.href = settings.runs_url + aceApi.query({f: result.f});
                })
                .catch(function(err) { message("Unable to open the batch: " + err.message, "alert-danger"); });
        }

        function batch_node(row) {
            const node = link("#", row.batch_id, "text-break-all");
            node.title = "the batch's runs that these filters match";
            node.addEventListener("click", function(event) {
                event.preventDefault();
                open_batch(row.batch_id);
            });
            return node;
        }

        function states_node(row) {
            const node = el("div", "small");
            Object.keys(STATES).forEach(function(state) {
                if (row.states[state]) {
                    node.appendChild(append(el("span", "me-2 text-nowrap"), el("span", STATES[state].css, state), " " + row.states[state]));
                }
            });
            return node;
        }

        const columns = [
            {label: "Batch", render: batch_node},
            {label: "Runs", width: "5rem", render: function(row) { return row.runs; }},
            {label: "By state", width: "22%", render: states_node},
            {label: "Needs attention", width: "8rem", render: function(row) {
                return el("span", row.needs_attention ? "fw-semibold" : "text-muted", row.needs_attention);
            }},
            {label: "First created", width: "11rem", css: "text-nowrap", title: "UTC", render: function(row) { return date(row.first_created_at); }},
            {label: "Last created", width: "11rem", css: "text-nowrap", title: "UTC", render: function(row) { return date(row.last_created_at); }},
            {label: "Result", width: "10rem", title: "summed over the runs", render: result_node},
        ];

        list = FilterListPage.create({
            root: document.getElementById("svs_runs_list"),
            screen: settings.screen,
            api: settings.path + "/batches",
            columns: columns,
            // the API has one order, the batch with the latest run first
            defaultSort: null,
            defaultDesc: true,
            pageSizes: [25, 50, 100, 250],
            defaultLimit: 50,
            tz: settings.tz,
            exports: ["csv", "ndjson"],
            download: null,
            emptyText: "No batches: none of the runs these filters match has a batch.",
            defaultF: settings.default_f,
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const page = document.getElementById("svs_runs_page");
        if (!page) {
            return;
        }
        const settings = page_settings(page);
        view_toggle(settings);
        if (settings.view === "batches") {
            start_batches(page, settings);
        } else {
            start_runs(page, settings);
        }
    });
})();
