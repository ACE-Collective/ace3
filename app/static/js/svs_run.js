// SVS -> Runs -> one run (docs/SVS.md, Part 5, *The run page*; docs/SVS_RUNS.md, *In the GUI*): the
// run review, and the operator's screen while the run is in flight.
//
// A shell over /api/v2/svs: the run (GET /runs/{id}, with what stands in the way of a review and the
// link to the site's log search), its result and how each signature did in the test's earlier runs,
// its alerts, the test's decisions (expectations and ignores), its comments and its event log. With
// svs:run_manage the page takes, cancels, closes and reviews the run, decides its candidates and
// changes which alerts it holds; a global ignore needs svs:admin. While the run is started, or its
// result is being recomputed, the page reloads itself. Every value shown came from a launcher, a
// catalog, an alert or a person, so it is placed as text, never markup.

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

    // a result status: how it reads, its color, and its mark in a signature's history
    const STATUSES = {
        hit: {label: "hit", css: "text-success", mark: "●", title: "expected, and it fired"},
        missing: {label: "missing", css: "text-danger fw-semibold", mark: "○", title: "expected, and it didn't fire"},
        possibly_suppressed: {label: "missing, possibly suppressed", css: "text-warning-emphasis", mark: "◐",
                              title: "expected and didn't fire, but the hunt alerted within its suppression period"},
        candidate: {label: "candidate", css: "text-warning-emphasis fw-semibold", mark: "?",
                    title: "it fired, and nobody has decided about it"},
        rejected: {label: "rejected", css: "text-muted", mark: "×", title: "it fired, and it was rejected for the test"},
        ignored: {label: "ignored", css: "text-muted", mark: "–", title: "it fired, and it is ignored"},
        cleanup: {label: "cleanup only", css: "text-muted fst-italic", mark: "c",
                  title: "it fired only during the test's cleanup: not a candidate, and never an expectation"},
    };

    const SVS_STATUSES = {
        "test": "TEST: every detection is attributed, at least one by a marker",
        "test?": "TEST?: every detection is attributed, by context only",
        "partial": "PARTIAL TEST: some detections are attributed",
        "mismatch": "a marker in the alert doesn't agree with its run",
    };

    // the run reloads itself this often while it is started or its result is being recomputed
    const REFRESH_SECONDS = 30;
    // the earlier runs of the test the result's history goes back over
    const HISTORY_RUNS = 10;
    const PAGE_SIZE = 500;
    const MAX_PAGES = 20;
    const ACTIVE_STATES = ["created", "started"];
    const REVIEWABLE_STATES = ["ended", "reviewed"];

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
        if (hours < 48) {
            return hours + "h " + (minutes % 60) + "m";
        }
        return Math.floor(hours / 24) + "d " + (hours % 24) + "h";
    }

    function mono(text, css) {
        return el("span", "font-monospace text-break-all" + (css ? " " + css : ""), text);
    }

    function muted(text) {
        return el("span", "text-muted", text);
    }

    function copy_button(text) {
        const element = button("", "btn-link p-0 ms-1 align-baseline", "Copy", function() {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text);
            }
        });
        element.appendChild(el("span", "bi bi-clipboard"));
        element.setAttribute("aria-label", "Copy " + text);
        return element;
    }

    function counts_text(counts) {
        return Object.keys(counts || {}).map(function(status) {
            return counts[status] + " " + (STATUSES[status] ? STATUSES[status].label : status);
        }).join(", ") || "nothing";
    }

    //
    // the page
    //

    function start(page) {
        const data = page.dataset;
        const settings = {
            path: data.api.substring(aceApi.BASE.length),
            run_id: data.runId,
            runs_url: data.runsUrl,
            test_url: data.testUrl,
            screen: data.screen,
            alert_url: data.alertUrl,
            samples_url: data.samplesUrl,
            username: data.username,
            can_manage: data.canManage === "true",
            is_admin: data.isAdmin === "true",
        };
        const run_path = settings.path + "/runs/" + encodeURIComponent(settings.run_id);
        const state = {};
        let editing_comment = false;

        function alert_link(alert_uuid, text) {
            return link(settings.alert_url + "?direct=" + encodeURIComponent(alert_uuid), text || alert_uuid.substring(0, 8),
                        text ? null : "font-monospace");
        }

        // another run's page: the run pages are under the Runs tab's URL
        function other_run_url(run_id) {
            return settings.runs_url + "/" + encodeURIComponent(run_id);
        }

        function signature_name(signature_uuid) {
            const row = (state.results || []).find(function(r) { return r.signature_uuid === signature_uuid; });
            return row && row.signature_name ? row.signature_name : signature_uuid;
        }

        function show_error(text) {
            const node = document.getElementById("svs_run_error");
            node.textContent = text || "";
            node.classList.toggle("d-none", !text);
        }

        function message(text_or_node, css) {
            const node = document.getElementById("svs_run_message");
            node.className = "alert " + (css || "alert-info");
            if (!text_or_node) {
                node.classList.add("d-none");
                node.replaceChildren();
                return;
            }
            node.replaceChildren(text_or_node instanceof Node ? text_or_node : document.createTextNode(text_or_node));
        }

        // every page of a listing
        function all_pages(path, params) {
            const rows = [];
            let first = null;
            function next(cursor, count) {
                const query = Object.assign({limit: PAGE_SIZE}, params || {}, {cursor: cursor || undefined});
                return aceApi.get(path + aceApi.query(query)).then(function(result) {
                    first = first || result;
                    Array.prototype.push.apply(rows, result.data);
                    if (result.next_cursor && count < MAX_PAGES) {
                        return next(result.next_cursor, count + 1);
                    }
                    return {data: rows, first: first, truncated: !!result.next_cursor};
                });
            }
            return next(null, 1);
        }

        function load() {
            return aceApi.get(run_path).then(function(run) {
                return Promise.all([
                    all_pages(run_path + "/results"),
                    all_pages(run_path + "/alerts"),
                    aceApi.get(run_path + "/history" + aceApi.query({runs: HISTORY_RUNS})),
                    all_pages(settings.path + "/expectations/", {test: run.test_guid}),
                    all_pages(settings.path + "/ignores/", {test: run.test_guid}),
                    aceApi.get(run_path + "/comments"),
                    all_pages(run_path + "/events"),
                ]).then(function(parts) {
                    state.run = run;
                    state.results = parts[0].data;
                    state.result_stale = !!parts[0].first.stale;
                    state.computed_at = parts[0].first.computed_at;
                    state.alerts = parts[1].data;
                    state.history = parts[2];
                    state.expectations = parts[3].data;
                    state.ignores = parts[4].data;
                    state.comments = parts[5];
                    state.events = parts[6].data;
                    render();
                });
            });
        }

        function reload() {
            return load().catch(function(err) { show_error("Unable to load the run: " + err.message); });
        }

        function render() {
            show_error("");
            document.title = (state.run.test_name || state.run.test_guid) + " - SVS run";
            render_header();
            render_review();
            render_timeline();
            render_facts();
            render_result();
            render_candidates();
            render_alerts();
            render_logs();
            render_comments();
            render_events();
            document.getElementById("svs_run_body").classList.remove("d-none");
        }

        //
        // asking first
        //

        // shows the ask modal; resolves to {reason} once it was submitted, or null
        function ask(options) {
            const modal = document.getElementById("svs_run_ask_modal");
            const form = document.getElementById("svs_run_ask_form");
            const field = document.getElementById("svs_run_ask_reason");
            document.getElementById("svs_run_ask_title").textContent = options.title;
            document.getElementById("svs_run_ask_text").textContent = options.text || "";
            document.getElementById("svs_run_ask_submit").textContent = options.submit;
            document.getElementById("svs_run_ask_reason_group").classList.toggle("d-none", !options.reason);
            field.value = "";
            field.required = !!(options.reason && options.reason.required);
            document.getElementById("svs_run_ask_reason_hint").textContent = options.reason ? options.reason.hint || "" : "";

            return new Promise(function(resolve) {
                const instance = bootstrap.Modal.getOrCreateInstance(modal);
                let answer = null;
                function submit(event) {
                    event.preventDefault();
                    answer = {reason: field.value.trim() || null};
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
                    if (done_text) {
                        message(typeof done_text === "function" ? done_text(result) : done_text, "alert-success");
                    }
                    return reload();
                })
                .catch(function(err) {
                    if (err.status === 412) {
                        // someone else decided first: show the page as it is now
                        message(err.message + ". This page now shows their decision.", "alert-warning");
                        return reload();
                    }
                    message(err.message, "alert-danger");
                });
        }

        //
        // the header and its actions
        //

        function bulk(action, reason) {
            // a single run through the bulk endpoints; someone else's run is taken only once confirmed
            const url = settings.path + "/runs/bulk/" + action;
            const body = {run_ids: [settings.run_id], reason: reason};
            return aceApi.post(url, body).then(function(result) {
                const owner = result.left_alone[settings.run_id];
                if (!owner) {
                    return result;
                }
                return ask({title: "Take this run from " + owner + "?",
                            text: owner + " owns this run. Take it from them and continue?", submit: "Take it"})
                    .then(function(answer) {
                        if (!answer) {
                            return result;
                        }
                        body.confirmed_takes = result.left_alone;
                        return aceApi.post(url, body);
                    });
            }).then(function(result) {
                if (result.conflicts[settings.run_id]) {
                    throw new Error(result.conflicts[settings.run_id]);
                }
                if (result.unknown.length) {
                    throw new Error("The run no longer exists.");
                }
                return result.done.length ? result : false;
            });
        }

        function render_header() {
            const run = state.run;
            const title = document.getElementById("svs_run_title");
            const run_state = STATES[run.state] || {css: "", title: ""};
            const state_node = el("span", "fs-5 ms-2 " + run_state.css, run.state);
            state_node.title = run_state.title;
            title.replaceChildren(document.createTextNode(run.test_name || run.test_guid), state_node);

            const subtitle = document.getElementById("svs_run_subtitle");
            subtitle.replaceChildren();
            append(subtitle, run.technique ? run.technique + (run.technique_name ? " " + run.technique_name : "") + " · " : "",
                   "run ", mono(run.run_id));
            if (run.changed_since_review) {
                append(subtitle, " · ", el("span", "text-warning-emphasis", "changed since review"));
            }

            const actions = document.getElementById("svs_run_actions");
            actions.replaceChildren();
            if (!settings.can_manage) {
                return;
            }
            if (run.owner !== settings.username) {
                actions.appendChild(button("Take ownership", null, "Make this run yours", function() {
                    act(bulk("take-ownership", null), "The run is yours.");
                }));
            }
            if (ACTIVE_STATES.indexOf(run.state) >= 0) {
                actions.appendChild(button("Cancel…", null, "Cancel the run, as the launcher would", function() {
                    act(ask({title: "Cancel this run?", submit: "Cancel the run",
                             text: "A canceled run still attributes alerts until its attribution window ends. " +
                                   "One that never started is closed at once."})
                        .then(function(answer) { return answer ? bulk("cancel", null) : false; }),
                        "The run is canceled.");
                }));
            }
            if (["ended", "canceled", "error"].indexOf(run.state) >= 0) {
                const ended = run.state === "ended";
                actions.appendChild(button("Close…", "btn-outline-danger",
                                           "Discard the run: nothing is learned from it", function() {
                    act(ask({title: "Close this run?", submit: "Close the run",
                             text: "Nothing is learned from a closed run, and its fully attributed open alerts are " +
                                   "closed as SIMULATED.",
                             reason: {required: ended,
                                      hint: ended ? "It waits for a review: say why it is closed instead." : "Optional."}})
                        .then(function(answer) { return answer ? bulk("close", answer.reason) : false; }),
                        "The run is closed.");
                }));
            }
        }

        function review(confirmed_take_from) {
            const body = confirmed_take_from ? {confirmed_take_from: confirmed_take_from} : {};
            return aceApi.post(run_path + "/review", body).catch(function(err) {
                if (err.status === 409 && err.detail && err.detail.owner && !confirmed_take_from) {
                    const owner = err.detail.owner;
                    return ask({title: "Take this run from " + owner + "?", submit: "Take it and review",
                                text: owner + " owns this run. Reviewing it takes it from them."})
                        .then(function(answer) { return answer ? review(owner) : false; });
                }
                throw err;
            });
        }

        function render_review() {
            const run = state.run;
            const node = document.getElementById("svs_run_review");
            node.replaceChildren();
            if (REVIEWABLE_STATES.indexOf(run.state) < 0 || !run.review_blockers) {
                return;
            }
            const blockers = run.review_blockers;
            const box = el("div", "border rounded p-2 d-flex flex-wrap align-items-center gap-2");
            const text = el("div", "me-auto small");
            if (run.state === "reviewed") {
                append(text, "Reviewed by " + (run.reviewer || "?") + " at " + date(run.reviewed_at) + " UTC.");
                if (run.changed_since_review) {
                    append(text, " ", el("span", "text-warning-emphasis",
                                        "It changed since: review it again to sign off what changed."));
                }
            } else {
                append(text, "This run ended and waits for a review.");
            }
            const waiting = [];
            if (blockers.candidates.length) {
                const item = el("li");
                append(item, plural(blockers.candidates.length, "candidate signature") + " to decide (",
                       link("#svs_run_candidates_title", "Candidates"), ")");
                waiting.push(item);
            }
            if (blockers.context_alerts.length) {
                const item = el("li");
                append(item, plural(blockers.context_alerts.length, "alert") +
                       " attributed by context alone to keep or mark not a test (", link("#svs_run_alerts_title", "Alerts"), ")");
                waiting.push(item);
            }
            if (blockers.stale) {
                waiting.push(el("li", null, "the result is being recomputed"));
            }
            if (waiting.length) {
                const list = el("ul", "mb-0");
                waiting.forEach(function(item) { list.appendChild(item); });
                append(text, el("div", null, "Before it can be reviewed:"), list);
            }
            box.appendChild(text);

            if (settings.can_manage) {
                const blocked = blockers.candidates.length > 0 || blockers.context_alerts.length > 0;
                const label = run.state === "reviewed" ? "Review again" : "Mark reviewed";
                const review_button = button(label, "btn-outline-success",
                                             "Sign the result off: its fully attributed open alerts become SIMULATED",
                                             function() {
                    review_button.disabled = true;
                    act(review(null), function(result) {
                        return (result.re_review ? "Reviewed again: " : "Reviewed: ") + counts_text(result.counts) + "; " +
                            plural(result.alerts_closed, "alert") + " closed as SIMULATED" +
                            (result.fp_verdicts ? ", " + plural(result.fp_verdicts, "FP verdict") + " on ignored detections" : "") + ".";
                    }).then(function() { review_button.disabled = false; });
                });
                review_button.disabled = blocked;
                box.appendChild(review_button);
            }
            node.appendChild(box);
        }

        //
        // the timeline and the facts
        //

        function render_timeline() {
            const run = state.run;
            const node = document.getElementById("svs_run_timeline");
            node.replaceChildren();
            const now = Date.now();
            if (run.started_at) {
                node.appendChild(windows_strip(run, now));
            }

            const legend = el("div", "small d-flex flex-wrap gap-3");
            [["registered", run.created_at], ["started", run.started_at], ["executed", run.executed_at],
             ["cleanup began", run.cleanup_at],
             ["observation ends", run.observation_ends_at], ["ended", run.ended_at], ["canceled", run.canceled_at],
             ["attribution ends", run.attribution_ends_at], ["closed", run.closed_at], ["reviewed", run.reviewed_at]]
                .forEach(function(item) {
                    if (item[1]) {
                        legend.appendChild(append(el("span", "text-nowrap"), muted(item[0] + " "), date(item[1])));
                    }
                });
            if (run.state === "started" && run.observation_ends_at) {
                legend.appendChild(el("span", "text-primary text-nowrap",
                                      duration(utc_ms(run.observation_ends_at) - now) + " left"));
            }
            legend.appendChild(muted("(UTC)"));
            node.appendChild(legend);
        }

        // the observation window, then the late part of the attribution window, from the run's
        // registration on, with now on it while it is inside
        function windows_strip(run, now) {
            const begin = Math.min(utc_ms(run.created_at), utc_ms(run.started_at));
            const ends = [run.attribution_ends_at, run.observation_ends_at, run.closed_at, run.canceled_at]
                .filter(Boolean).map(utc_ms);
            const end = Math.max.apply(null, ends.concat([utc_ms(run.started_at) + 1]));
            const span = end - begin || 1;
            function at(ms) {
                return Math.min(100, Math.max(0, (ms - begin) / span * 100));
            }
            function bar(from, to, css, title) {
                const part = el("div", "position-absolute top-0 h-100 " + css);
                part.style.left = at(from) + "%";
                part.style.width = Math.max(0.5, at(to) - at(from)) + "%";
                part.title = title;
                return part;
            }

            const strip = el("div", "position-relative bg-body-secondary rounded mb-1");
            strip.style.height = "0.9rem";
            strip.setAttribute("role", "img");
            const started = utc_ms(run.started_at);
            if (run.observation_ends_at) {
                strip.appendChild(bar(started, utc_ms(run.observation_ends_at), "bg-primary rounded-start",
                                      "observation window: " + date(run.started_at) + " to " + date(run.observation_ends_at) + " UTC"));
            }
            if (run.attribution_ends_at && run.observation_ends_at) {
                strip.appendChild(bar(utc_ms(run.observation_ends_at), utc_ms(run.attribution_ends_at), "bg-primary-subtle rounded-end",
                                      "late alerts are still attributed until " + date(run.attribution_ends_at) + " UTC"));
            }
            if (now > begin && now < end) {
                const marker = el("div", "position-absolute h-100 bg-dark");
                marker.style.left = at(now) + "%";
                marker.style.width = "2px";
                marker.title = "now";
                strip.appendChild(marker);
            }
            strip.setAttribute("aria-label", "the run's windows");
            return strip;
        }

        function open_batch(batch_id) {
            const filters = [{name: "Batch", inverted: false, values: [batch_id]}];
            aceApi.post("/filter-screens/" + encodeURIComponent(settings.screen) + "/encode", {filters: filters})
                .then(function(result) { window.location.href = settings.runs_url + aceApi.query({f: result.f}); })
                .catch(function(err) { message("Unable to open the batch: " + err.message, "alert-danger"); });
        }

        function render_facts() {
            const run = state.run;
            const list = document.getElementById("svs_run_facts");
            list.replaceChildren();
            function fact(term, value) {
                if (value === null || value === undefined || value === "") {
                    return;
                }
                list.appendChild(el("dt", "col-sm-2 fw-normal text-muted", term));
                list.appendChild(append(el("dd", "col-sm-10 mb-1"), value));
            }
            const test = link(settings.test_url.replace("__TEST__", encodeURIComponent(run.test_guid)),
                              run.test_name || run.test_guid);
            test.title = "the test's page: its catalog entry, expectations and runs";
            fact("Test", append(el("span"), test, run.test_name ? " " : "", run.test_name ? mono(run.test_guid, "small") : ""));
            const commit = mono(run.catalog_commit.substring(0, 12));
            commit.title = run.catalog_commit;
            const content = mono(run.test_content_hash.substring(0, 12), "text-muted");
            content.title = "the test's content hash when the run was registered: " + run.test_content_hash;
            fact("Catalog commit", append(el("span"), commit, " ", content));
            fact("Marker", append(el("span"), mono(run.marker), copy_button(run.marker)));
            const targets = el("span");
            run.targets.forEach(function(target, index) {
                append(targets, index ? ", " : "", target.username ? target.hostname + "/" + target.username : target.hostname);
            });
            fact("Targets", targets);
            fact("Platform", run.platform);
            fact("Launcher", run.launcher + (run.registered_by ? " (key of " + run.registered_by + ")" : ""));
            if (run.batch_id) {
                const batch = link("#", run.batch_id, "text-break-all");
                batch.title = "the batch's runs";
                batch.addEventListener("click", function(event) {
                    event.preventDefault();
                    open_batch(run.batch_id);
                });
                fact("Batch", batch);
            }
            fact("Windows", "observes for " + duration(run.observation_seconds * 1000) + ", attributes for " +
                 duration(run.attribution_seconds * 1000));
            fact("Owner", run.owner || muted("nobody"));
            if (run.exit_code !== null && run.exit_code !== undefined) {
                fact("Exit code", String(run.exit_code));
            }
            fact("Launcher error", run.launcher_error ? el("span", "text-danger", run.launcher_error) : null);
            if (run.launcher_output) {
                // what the test printed, folded: it can be 64 KiB
                const output = el("details");
                output.appendChild(el("summary", "small", run.launcher_output.split("\n").length + " lines"));
                output.appendChild(el("pre", "small mb-0 text-break-all bg-body-tertiary p-2", run.launcher_output));
                output.open = !!run.exit_code || !!run.launcher_error;
                fact("Output", output);
            }
            fact("Error", run.error_reason ? el("span", "text-danger", run.error_reason) : null);
            fact("Close reason", run.close_reason);
            if (run.extra && Object.keys(run.extra).length) {
                fact("Extra", el("pre", "small mb-0 text-break-all", JSON.stringify(run.extra, null, 2)));
            }
        }

        //
        // the result
        //

        function status_node(status) {
            if (!status) {
                return muted("no longer in the result");
            }
            const info = STATUSES[status] || {label: status, css: "", title: ""};
            const node = el("span", info.css, info.label);
            node.title = info.title;
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

        function decision(signature_uuid) {
            // the run is judged by its own platform's expectations only
            const expectation = state.expectations.find(function(e) {
                return e.signature_uuid === signature_uuid && e.platform === state.run.platform;
            });
            const test_ignore = state.ignores.find(function(i) { return i.signature_uuid === signature_uuid && i.scope === "test"; });
            const global_ignore = state.ignores.find(function(i) { return i.signature_uuid === signature_uuid && i.scope === "global"; });
            return {expectation: expectation, test_ignore: test_ignore, global_ignore: global_ignore};
        }

        function expected_elsewhere(signature_uuid) {
            // the test's other platforms that expect the signature: a hint for deciding it here
            return state.expectations.filter(function(e) {
                return e.signature_uuid === signature_uuid && e.platform !== state.run.platform && e.state === "expected";
            }).map(function(e) { return e.platform; }).sort();
        }

        function decision_node(signature_uuid) {
            const found = decision(signature_uuid);
            const node = el("div", "small");
            function line(text, who, reason) {
                const item = el("div", null, text);
                if (who) {
                    item.appendChild(muted(" by " + who));
                }
                if (reason) {
                    item.title = reason;
                    item.appendChild(muted(": " + reason));
                }
                node.appendChild(item);
            }
            if (found.expectation) {
                line(found.expectation.state, found.expectation.decided_by, found.expectation.reason);
            }
            if (found.test_ignore) {
                line("ignored for this test", found.test_ignore.created_by, found.test_ignore.reason);
            }
            if (found.global_ignore) {
                line("ignored for every test", found.global_ignore.created_by, found.global_ignore.reason);
            }
            return node;
        }

        function history_node(signature_uuid) {
            const history = state.history;
            const entry = history.signatures.find(function(s) { return s.signature_uuid === signature_uuid; });
            const node = el("div", "text-nowrap font-monospace");
            if (!entry || !history.runs.length) {
                return muted("first run");
            }
            entry.statuses.forEach(function(status, index) {
                const earlier = history.runs[index];
                const info = STATUSES[status] || {mark: "·", css: "text-muted", label: "not in its result"};
                const mark = link(other_run_url(earlier.run_id), info.mark, "text-decoration-none me-1 " + info.css);
                mark.title = date(earlier.created_at) + " UTC, " + earlier.state + ": " + info.label;
                node.appendChild(mark);
            });
            node.title = "the test's earlier runs, latest first";
            return node;
        }

        function remove_decision(signature_uuid) {
            const found = decision(signature_uuid);
            const guid = encodeURIComponent(state.run.test_guid);
            const sig = encodeURIComponent(signature_uuid);
            const platform = encodeURIComponent(state.run.platform);
            const requests = [];
            if (found.expectation) {
                requests.push(aceApi.del(settings.path + "/tests/" + guid + "/expectations/" + platform + "/" + sig));
            }
            if (found.test_ignore) {
                requests.push(aceApi.del(settings.path + "/tests/" + guid + "/ignores/" + sig));
            }
            if (found.global_ignore && settings.is_admin) {
                requests.push(aceApi.del(settings.path + "/ignores/global/" + sig));
            }
            return Promise.all(requests);
        }

        function captured_files_link() {
            // the files captured from the alerts the run holds, on the Samples page
            const uuids = state.alerts.filter(function(a) { return a.holds; }).map(function(a) { return a.alert_uuid; });
            if (!settings.samples_url || !uuids.length) {
                return null;
            }
            const node = link("#", "files captured from this run's alerts", "small");
            node.title = "what the run's alerts captured for other rules: did this rule's target reach ACE?";
            node.addEventListener("click", function(event) {
                event.preventDefault();
                aceApi.post("/filter-screens/svs_samples/encode", {filters: [{name: "Alert", inverted: false, values: uuids}]})
                    .then(function(result) { window.location.href = settings.samples_url + aceApi.query({f: result.f}); })
                    .catch(function(err) { message("Unable to open the samples: " + err.message, "alert-danger"); });
            });
            return node;
        }

        // only an ended or reviewed run's result is recomputed; a started run's is computed when it ends
        function result_updating() {
            return state.result_stale && REVIEWABLE_STATES.indexOf(state.run.state) >= 0;
        }

        function render_result() {
            const run = state.run;
            const node = document.getElementById("svs_run_result");
            node.replaceChildren();
            if (result_updating()) {
                node.appendChild(el("div", "small text-warning-emphasis mb-1",
                                    "Something changed since this result was computed; it is recomputed shortly."));
            }
            if (!state.results.length) {
                node.appendChild(muted(REVIEWABLE_STATES.indexOf(run.state) >= 0 || run.ended_at
                    ? "Nothing fired, and nothing is expected of this test."
                    : "A run's result is computed when it ends."));
                return;
            }
            const reviewed = run.state === "reviewed" || state.results.some(function(r) { return r.reviewed_status; });
            const table = el("table", "table table-sm align-middle mb-1");
            const head = el("tr");
            ["Status", "Signature", "Alerts"].concat(reviewed ? ["As reviewed"] : [])
                .concat(["Decided", "Earlier runs"]).concat(settings.can_manage ? [""] : [])
                .forEach(function(label) { head.appendChild(el("th", "small", label)); });
            table.appendChild(append(el("thead"), head));
            const body = el("tbody");
            // what fired only during the test's cleanup is shown apart, after the rest
            const cleanup = state.results.filter(function(r) { return r.status === "cleanup"; });
            const ordered = state.results.filter(function(r) { return r.status !== "cleanup"; }).concat(cleanup);
            ordered.forEach(function(row) {
                if (cleanup.length && row === cleanup[0]) {
                    const cell = el("td", "small text-muted pt-3",
                                    "Fired only during the test's cleanup (after " + date(run.cleanup_at) +
                                    " UTC): never a candidate, never learned as an expectation.");
                    cell.colSpan = head.children.length;
                    body.appendChild(append(el("tr"), cell));
                }
                const tr = el("tr", row.status ? null : "text-muted");
                const status = append(el("td"), status_node(row.status));
                if (row.status === "possibly_suppressed" && row.suppressing_alert_uuid) {
                    const why = el("div", "small");
                    append(why, muted("by the hunt's alert "), alert_link(row.suppressing_alert_uuid));
                    if (row.suppression_imprecise) {
                        why.appendChild(muted(" (the hunt deduplicates its alerts: maybe not)"));
                    }
                    status.appendChild(why);
                }
                if ((row.status === "missing" || row.status === "possibly_suppressed") && row.signature_family === "yara") {
                    const files = captured_files_link();
                    if (files) {
                        status.appendChild(append(el("div"), files));
                    }
                }
                tr.appendChild(status);
                tr.appendChild(append(el("td"), signature_node(row)));
                const alerts = append(el("td", "small"), String(row.alert_count));
                if (row.fallback_time) {
                    alerts.appendChild(el("div", "text-warning-emphasis", "by a fallback time"));
                }
                if (row.late_only) {
                    alerts.appendChild(el("div", "text-muted", "late only"));
                }
                if (row.context_only) {
                    alerts.appendChild(el("div", "text-muted", "by context only"));
                }
                tr.appendChild(alerts);
                if (reviewed) {
                    const as_reviewed = el("td", "small");
                    if (row.reviewed_status) {
                        as_reviewed.appendChild(status_node(row.reviewed_status));
                        if (row.reviewed_alert_count !== null) {
                            as_reviewed.appendChild(muted(" (" + row.reviewed_alert_count + ")"));
                        }
                    }
                    tr.appendChild(as_reviewed);
                }
                tr.appendChild(append(el("td"), decision_node(row.signature_uuid)));
                tr.appendChild(append(el("td"), history_node(row.signature_uuid)));
                if (settings.can_manage) {
                    const cell = el("td", "text-end");
                    const found = decision(row.signature_uuid);
                    const removable = found.expectation || found.test_ignore || (found.global_ignore && settings.is_admin);
                    if (removable && row.status !== "candidate") {
                        cell.appendChild(button("Undo…", "btn-outline-dark py-0",
                                                "Remove what was decided about this signature for the test", function() {
                            act(ask({title: "Remove the decision?", submit: "Remove it",
                                     text: "What was decided about " + (row.signature_name || row.signature_uuid) +
                                           " is removed for " + (found.test_ignore || found.global_ignore
                                               ? "every run of this test" : "this test's runs on " + state.run.platform) +
                                           (found.global_ignore && settings.is_admin ? ", and its global ignore for every test" : "") +
                                           ". It is a candidate again the next time it fires, and the results of the " +
                                           "affected runs are recomputed."})
                                .then(function(answer) { return answer ? remove_decision(row.signature_uuid) : false; }),
                                "Removed; the result is recomputed shortly.");
                        }));
                    }
                    tr.appendChild(cell);
                }
                body.appendChild(tr);
            });
            table.appendChild(body);
            const wrapper = el("div", "table-responsive");
            wrapper.appendChild(table);
            node.appendChild(wrapper);
            if (state.computed_at) {
                node.appendChild(el("div", "small text-muted", "Computed at " + date(state.computed_at) + " UTC."));
            }
        }

        //
        // the candidates
        //

        function decide(row, how) {
            const guid = encodeURIComponent(state.run.test_guid);
            const sig = encodeURIComponent(row.signature_uuid);
            const platform = state.run.platform;
            const name = row.signature_name || row.signature_uuid;
            const options = {
                expected: {title: "Expect " + name + " on " + platform + "?", submit: "Expected",
                           text: "Every run of this test on " + platform + " should fire it. A run where it doesn't " +
                                 "is missing it."},
                rejected: {title: "Reject " + name + " on " + platform + "?", submit: "Rejected",
                           text: "It fires, but it isn't what this test is about on " + platform + ". It isn't " +
                                 "proposed again for runs on " + platform + "."},
                ignore_test: {title: "Ignore " + name + " for this test?", submit: "Ignore it",
                              text: "It is noise during this test's runs, such as the launcher's own remoting. " +
                                    "Reviewing a run gives its detections an FP verdict."},
                ignore_global: {title: "Ignore " + name + " for every test?", submit: "Ignore it everywhere",
                                text: "It is noise during every test's runs. This changes every test's results."},
            }[how];
            options.reason = {required: false, hint: "Why, for whoever reads the decision later."};
            return ask(options).then(function(answer) {
                if (!answer) {
                    return false;
                }
                // a candidate has no decision: only while there still is none, or a reviewer deciding
                // at the same time would be overwritten without knowing
                const undecided = {"If-None-Match": "*"};
                if (how === "expected" || how === "rejected") {
                    return aceApi.put(settings.path + "/tests/" + guid + "/expectations/" +
                                      encodeURIComponent(platform) + "/" + sig,
                                      {state: how, reason: answer.reason, run_id: settings.run_id}, undecided);
                }
                if (how === "ignore_test") {
                    return aceApi.put(settings.path + "/tests/" + guid + "/ignores/" + sig, {reason: answer.reason},
                                      undecided);
                }
                return aceApi.put(settings.path + "/ignores/global/" + sig, {reason: answer.reason}, undecided);
            });
        }

        function alerts_carrying(signature_uuid) {
            return state.alerts.filter(function(alert) {
                return alert.detections.some(function(detection) {
                    return detection.attribution && !detection.attribution.removed_at &&
                        detection.attribution.signature_uuid === signature_uuid;
                });
            });
        }

        function render_candidates() {
            const node = document.getElementById("svs_run_candidates");
            node.replaceChildren();
            const candidates = state.results.filter(function(row) { return row.status === "candidate"; });
            if (!candidates.length) {
                node.appendChild(muted(state.results.length ? "None: every signature that fired is decided." : "None."));
                return;
            }
            node.appendChild(el("p", "small text-muted mb-1",
                                "Signatures that fired during the run and that nobody has decided about for this test " +
                                "on " + state.run.platform + ". " +
                                "A run is reviewed once each is decided."));
            const list = el("div", "list-group mb-1");
            candidates.forEach(function(row) {
                const item = el("div", "list-group-item d-flex flex-wrap align-items-center gap-2");
                const about = el("div", "me-auto");
                about.appendChild(signature_node(row));
                const carrying = alerts_carrying(row.signature_uuid);
                if (carrying.length) {
                    const alerts = el("div", "small");
                    alerts.appendChild(muted("in "));
                    carrying.forEach(function(alert, index) {
                        append(alerts, index ? ", " : "",
                               alert_link(alert.alert_uuid, alert.alert && alert.alert.description ? alert.alert.description : null));
                    });
                    about.appendChild(alerts);
                }
                const elsewhere = expected_elsewhere(row.signature_uuid);
                if (elsewhere.length) {
                    const hint = el("div", "small text-muted", "expected on " + elsewhere.join(", "));
                    hint.title = "this test's runs on " + (elsewhere.length > 1 ? "those platforms" : "that platform") +
                        " expect it; a decision here is for " + state.run.platform + " only";
                    about.appendChild(hint);
                }
                item.appendChild(about);
                const found = decision(row.signature_uuid);
                if (found.expectation || found.test_ignore || found.global_ignore) {
                    // decided since the result was computed; the recompute makes it no longer a candidate
                    const pending = el("div", "small text-muted");
                    append(pending, decision_node(row.signature_uuid), "the result is being recomputed");
                    item.appendChild(pending);
                } else if (settings.can_manage) {
                    const buttons = el("div", "d-flex flex-wrap gap-1");
                    [["Expected", "expected", "btn-outline-success"], ["Rejected", "rejected", "btn-outline-dark"],
                     ["Ignore for this test", "ignore_test", "btn-outline-secondary"]]
                        .concat(settings.is_admin ? [["Ignore everywhere", "ignore_global", "btn-outline-secondary"]] : [])
                        .forEach(function(choice) {
                            buttons.appendChild(button(choice[0] + "…", choice[2] + " py-0", null, function() {
                                act(decide(row, choice[1]), "Decided; the result is recomputed shortly.");
                            }));
                        });
                    item.appendChild(buttons);
                }
                list.appendChild(item);
            });
            node.appendChild(list);
        }

        //
        // the alerts
        //

        function change_association(alert, action, options) {
            const path = run_path + "/alerts/" + encodeURIComponent(alert.alert_uuid) + "/" + action;
            const asked = options ? ask(options) : Promise.resolve({reason: null});
            return asked.then(function(answer) {
                if (!answer) {
                    return false;
                }
                return aceApi.post(path, action === "keep" ? undefined : {reason: answer.reason});
            });
        }

        function association_text(result) {
            const parts = ["Done; the alert is now " + (result.svs_status ? result.svs_status.toUpperCase() : "not a test alert") +
                           " in " + result.queue];
            if (result.moved) {
                parts.push("it moved queues");
            }
            if (result.reopened) {
                parts.push("it is OPEN again");
            }
            return parts.join(", ") + ".";
        }

        function attribution_node(alert) {
            const node = el("div", "small");
            if (!alert.holds) {
                const removed = alert.detections.map(function(d) { return d.attribution; }).filter(Boolean)
                    .filter(function(a) { return a.removed_at; });
                const last = removed[removed.length - 1];
                node.appendChild(muted("no longer attributed"));
                if (last) {
                    node.appendChild(el("div", "text-muted",
                                        (last.removed_by_user || last.removed_by) + ", " + date(last.removed_at) +
                                        (last.removal_reason ? ": " + last.removal_reason : "")));
                }
                return node;
            }
            const parts = [alert.confidence === "context" ? "by context alone" : "by marker"];
            if (alert.manual) {
                parts.push("by hand");
            }
            if (alert.late) {
                parts.push("late");
            }
            if (alert.cleanup) {
                parts.push("cleanup");
            }
            if (alert.fallback_time) {
                parts.push("judged by a fallback time");
            }
            if (alert.kept) {
                parts.push("kept");
            }
            node.appendChild(el("div", null, parts.join(", ")));
            if (alert.undecided_context) {
                node.appendChild(el("div", "text-warning-emphasis", "keep it, or mark it not a test"));
            }
            return node;
        }

        function detections_node(alert) {
            const list = el("ul", "list-unstyled small mb-0");
            alert.detections.forEach(function(detection) {
                const a = detection.attribution;
                const item = el("li", a && !a.removed_at ? null : "text-muted");
                const text = el("span", a && a.removed_at ? "text-decoration-line-through" : null,
                                detection.description || ("detection " + detection.detection.substring(0, 12) + " (gone)"));
                item.appendChild(text);
                const family = detection.signature_family || (a && a.signature_family);
                if (family) {
                    item.appendChild(muted(" · " + family));
                }
                if (!a) {
                    item.appendChild(muted(" · not attributed to this run"));
                } else if (!a.removed_at && a.confidence === "context") {
                    item.appendChild(muted(" · context"));
                }
                if (a && a.late && !a.removed_at) {
                    item.appendChild(muted(" · late"));
                }
                if (a && a.cleanup && !a.removed_at) {
                    item.appendChild(muted(" · cleanup"));
                }
                if (a && a.fallback_time && !a.removed_at) {
                    const fallback = el("span", "text-warning-emphasis", " · " + (a.event_time_source === "query_time"
                        ? "the hunt's query time" : "the alert's insert time"));
                    fallback.title = "not the event's own time: it may have put the alert in the wrong window";
                    item.appendChild(fallback);
                }
                list.appendChild(item);
            });
            return list;
        }

        function alert_actions(alert) {
            const cell = el("td", "text-end");
            if (!settings.can_manage) {
                return cell;
            }
            const buttons = el("div", "d-flex flex-column gap-1 align-items-end");
            if (alert.undecided_context) {
                buttons.appendChild(button("Keep", "btn-outline-success py-0",
                                           "It is this run's: keep its context attributions", function() {
                    act(change_association(alert, "keep", null), association_text);
                }));
            }
            if (alert.holds && alert.confidence === "context") {
                buttons.appendChild(button("Not a test…", "btn-outline-dark py-0",
                                           "It isn't this run's: disassociate it", function() {
                    act(change_association(alert, "not-a-test", {
                        title: "Not a test?", submit: "Not a test",
                        text: "The alert is disassociated from the run and goes back to the queue SVS took it from.",
                        reason: {required: false}}), association_text);
                }));
            }
            if (alert.holds) {
                buttons.appendChild(button("Disassociate…", "btn-outline-danger py-0",
                                           "Remove the alert from this run", function() {
                    act(change_association(alert, "disassociate", {
                        title: "Disassociate the alert?", submit: "Disassociate",
                        text: "The router never attributes it to this run again. A SIMULATED alert that is no longer " +
                              "a test alert is OPEN again.",
                        reason: {required: false}}), association_text);
                }));
            } else {
                buttons.appendChild(button("Associate…", "btn-outline-dark py-0",
                                           "Attribute every detection of the alert to this run, by hand", function() {
                    act(change_association(alert, "associate", {
                        title: "Associate the alert again?", submit: "Associate",
                        text: "Every detection of the alert is attributed to this run, as a marker would.",
                        reason: {required: false}}), association_text);
                }));
            }
            cell.appendChild(buttons);
            return cell;
        }

        function render_alerts() {
            const node = document.getElementById("svs_run_alerts");
            node.replaceChildren();
            if (!state.alerts.length) {
                node.appendChild(muted(ACTIVE_STATES.indexOf(state.run.state) >= 0
                    ? "No alerts yet. They show up here as they are attributed."
                    : "No alert was attributed to this run."));
                return;
            }
            const table = el("table", "table table-sm align-middle mb-0");
            const head = el("tr");
            ["Alert", "SVS", "Attribution", "Detections", "Queue"].concat(settings.can_manage ? [""] : [])
                .forEach(function(label) { head.appendChild(el("th", "small", label)); });
            table.appendChild(append(el("thead"), head));
            const body = el("tbody");
            // the alerts it holds first, each group in the order they came
            const ordered = state.alerts.filter(function(a) { return a.holds; })
                .concat(state.alerts.filter(function(a) { return !a.holds; }));
            ordered.forEach(function(alert) {
                const row = alert.alert;
                const tr = el("tr", alert.holds ? null : "text-muted");
                const about = el("td");
                about.appendChild(alert_link(alert.alert_uuid, row && row.description ? row.description : null));
                about.appendChild(el("div", "small text-muted",
                                     row ? date(row.insert_date) + " UTC" + (row.event_time ? ", event " + date(row.event_time) : "")
                                         : "the alert is gone"));
                tr.appendChild(about);
                const svs = el("td", "small text-nowrap");
                if (row && row.svs_status) {
                    const status = el("span", row.svs_status === "mismatch" ? "text-danger" : null, row.svs_status.toUpperCase());
                    status.title = SVS_STATUSES[row.svs_status] || "";
                    svs.appendChild(status);
                }
                tr.appendChild(svs);
                tr.appendChild(append(el("td"), attribution_node(alert)));
                tr.appendChild(append(el("td"), detections_node(alert)));
                const where = el("td", "small");
                if (row) {
                    append(where, row.queue, el("div", "text-muted", row.disposition || "OPEN"),
                           row.owner ? el("div", "text-muted", row.owner) : null);
                }
                tr.appendChild(where);
                if (settings.can_manage) {
                    tr.appendChild(alert_actions(alert));
                }
                body.appendChild(tr);
            });
            table.appendChild(body);
            const wrapper = el("div", "table-responsive");
            wrapper.appendChild(table);
            node.appendChild(wrapper);
        }

        const associate_form = document.getElementById("svs_run_associate_form");
        if (associate_form) {
            associate_form.addEventListener("submit", function(event) {
                event.preventDefault();
                const uuid = document.getElementById("svs_run_associate_uuid");
                const reason = document.getElementById("svs_run_associate_reason");
                act(aceApi.post(run_path + "/alerts/" + encodeURIComponent(uuid.value.trim().toLowerCase()) + "/associate",
                                {reason: reason.value.trim() || null})
                        .then(function(result) {
                            uuid.value = "";
                            reason.value = "";
                            return result;
                        }),
                    association_text);
            });
        }

        //
        // the logs
        //

        function render_logs() {
            const run = state.run;
            const node = document.getElementById("svs_run_logs");
            node.replaceChildren();
            node.appendChild(el("p", "small text-muted mb-1",
                                "Every record ACE writes about this run carries these fields: search the site's log " +
                                "tooling for them to see what ACE did, on every node."));
            const keys = el("dl", "row small mb-1");
            const earliest = run.started_at || run.created_at;
            const end = run.attribution_ends_at || run.canceled_at || run.closed_at;
            const latest = end && utc_ms(end) < Date.now() ? date(end) : "now";
            [["svs_run", run.run_id], ["svs_marker", run.marker], ["svs_test", run.test_guid]].forEach(function(item) {
                keys.appendChild(el("dt", "col-sm-2 fw-normal text-muted", item[0]));
                const text = item[0] + "=" + item[1];
                keys.appendChild(append(el("dd", "col-sm-10 mb-1"), mono(text), copy_button(text)));
            });
            keys.appendChild(el("dt", "col-sm-2 fw-normal text-muted", "targets"));
            keys.appendChild(el("dd", "col-sm-10 mb-1", run.targets.map(function(t) { return t.fqdn || t.hostname; }).join(", ")));
            keys.appendChild(el("dt", "col-sm-2 fw-normal text-muted", "window"));
            keys.appendChild(el("dd", "col-sm-10 mb-1", date(earliest) + " to " + latest + " (UTC)"));
            node.appendChild(keys);
            if (run.log_search_url) {
                const search = link(run.log_search_url, "Search the logs for this run");
                search.target = "_blank";
                search.rel = "noopener noreferrer";
                node.appendChild(append(el("div"), search, el("span", "bi bi-box-arrow-up-right ms-1 small")));
            }
        }

        //
        // the comments
        //

        function comment_node(comment) {
            const item = el("div", "list-group-item");
            const head = el("div", "d-flex flex-wrap gap-2 small");
            append(head, el("span", "fw-semibold", comment.user || "?"),
                   muted(date(comment.created_at) + " UTC" + (date(comment.updated_at) !== date(comment.created_at) ? " (edited)" : "")));
            const text = el("div", "text-break", comment.comment);
            text.style.whiteSpace = "pre-wrap";
            if (settings.can_manage && comment.user === settings.username) {
                const tools = el("span", "ms-auto");
                tools.appendChild(button("Edit", "btn-link py-0", null, function() { edit_comment(item, text, comment); }));
                tools.appendChild(button("Delete…", "btn-link text-danger py-0", null, function() {
                    act(ask({title: "Delete the comment?", submit: "Delete"})
                        .then(function(answer) {
                            return answer ? aceApi.del(run_path + "/comments/" + comment.id) : false;
                        }));
                }));
                head.appendChild(tools);
            }
            item.append(head, text);
            return item;
        }

        function edit_comment(item, text, comment) {
            editing_comment = true;
            const form = el("form", "mt-1");
            const field = el("textarea", "form-control form-control-sm mb-1");
            field.rows = 3;
            field.maxLength = 16384;
            field.required = true;
            field.value = comment.comment;
            const save = el("button", "btn btn-sm btn-outline-primary me-1", "Save");
            save.type = "submit";
            const cancel = button("Cancel", "btn-outline-dark", null, function() {
                editing_comment = false;
                form.replaceWith(text);
            });
            form.append(field, save, cancel);
            form.addEventListener("submit", function(event) {
                event.preventDefault();
                editing_comment = false;
                act(aceApi.patch(run_path + "/comments/" + comment.id, {comment: field.value}));
            });
            text.replaceWith(form);
            field.focus();
        }

        function render_comments() {
            const node = document.getElementById("svs_run_comments");
            node.replaceChildren();
            if (!state.comments.length) {
                node.appendChild(muted("No comments."));
                return;
            }
            const list = el("div", "list-group");
            state.comments.forEach(function(comment) { list.appendChild(comment_node(comment)); });
            node.appendChild(list);
        }

        const comment_form = document.getElementById("svs_run_comment_form");
        if (comment_form) {
            comment_form.addEventListener("submit", function(event) {
                event.preventDefault();
                // one comment per submit: a double click must not post it twice
                const submit = comment_form.querySelector("button[type=submit]");
                if (submit.disabled) {
                    return;
                }
                submit.disabled = true;
                const field = document.getElementById("svs_run_comment_text");
                act(aceApi.post(run_path + "/comments", {comment: field.value}).then(function(result) {
                    field.value = "";
                    return result;
                })).then(function() { submit.disabled = false; });
            });
        }

        //
        // the event log
        //

        function detections_count(detections) {
            return detections && detections.length ? plural(detections.length, "detection") : "";
        }

        function event_details(event) {
            const d = event.details || {};
            const node = el("div", "small");
            switch (event.kind) {
            case "registered":
                append(node, "by " + (d.launcher || event.actor) + (d.batch_id ? ", batch " + d.batch_id : "") +
                       (d.platform ? "; on " + d.platform : "") +
                       (d.observation_source ? "; window from " + d.observation_source : ""));
                break;
            case "transition":
                append(node, (event.from_state || "") + " → " + (event.to_state || ""), d.reason ? ": " + d.reason : "");
                break;
            case "launcher_call":
                append(node, (d.call || "?") + ": " + (d.outcome || "?"),
                       d.payload ? " " + JSON.stringify(d.payload) : "");
                break;
            case "attributed":
                append(node, alert_link(d.alert_uuid || ""), " ", detections_count(d.detections),
                       (d.detections || []).some(function(x) { return x.late; }) ? ", late" : "",
                       (d.detections || []).every(function(x) { return x.confidence === "context"; }) ? ", by context" : "");
                break;
            case "attribution_removed":
                append(node, alert_link(d.alert_uuid || ""), " ", detections_count(d.detections), d.reason ? ": " + d.reason : "");
                break;
            case "alerts_closed":
                append(node, plural((d.alerts || []).length, "alert") + " closed as " + (d.disposition || "SIMULATED") +
                       (d.late ? ", late" : "") + (d.reviewed ? ", by the review" : ""));
                break;
            case "result_computed":
                append(node, counts_text(d.counts), d.previous ? el("span", "text-muted", " (was " + counts_text(d.previous) + ")") : "");
                break;
            case "candidate_decision":
                append(node, signature_name(d.signature_uuid) + ": " + d.state, d.reason ? ": " + d.reason : "");
                break;
            case "associated":
            case "disassociated":
                append(node, alert_link(d.alert_uuid || ""), d.not_a_test ? " not a test" : "",
                       d.late ? " late" : "", d.reason ? ": " + d.reason : "");
                break;
            case "context_kept":
                append(node, alert_link(d.alert_uuid || ""));
                break;
            case "ownership_taken":
                append(node, d.from ? "from " + d.from : "nobody owned it");
                break;
            case "reviewed":
                append(node, (d.re_review ? "again: " : "") + counts_text(d.counts));
                break;
            default:
                if (event.details) {
                    append(node, JSON.stringify(event.details));
                }
            }
            return node;
        }

        function render_events() {
            const node = document.getElementById("svs_run_events");
            node.replaceChildren();
            if (!state.events.length) {
                node.appendChild(muted("No events."));
                return;
            }
            const table = el("table", "table table-sm mb-0");
            const head = el("tr");
            ["When (UTC)", "Who", "What", ""].forEach(function(label) { head.appendChild(el("th", "small", label)); });
            table.appendChild(append(el("thead"), head));
            const body = el("tbody");
            state.events.slice().reverse().forEach(function(event) {
                const tr = el("tr");
                tr.appendChild(el("td", "small text-nowrap", date(event.created_at)));
                tr.appendChild(el("td", "small text-break-all", event.actor_user || event.actor));
                tr.appendChild(el("td", "small text-nowrap", event.kind.replace(/_/g, " ")));
                tr.appendChild(append(el("td"), event_details(event)));
                body.appendChild(tr);
            });
            table.appendChild(body);
            node.appendChild(append(el("div", "table-responsive"), table));
        }

        //
        // keeping it current
        //

        window.setInterval(function() {
            if (!state.run || document.visibilityState !== "visible" || editing_comment ||
                document.querySelector(".modal.show")) {
                return;
            }
            if (ACTIVE_STATES.indexOf(state.run.state) >= 0 || result_updating()) {
                reload();
            }
        }, REFRESH_SECONDS * 1000);

        load().catch(function(err) {
            show_error(err.status === 404 ? "There is no run " + settings.run_id + "." : "Unable to load the run: " + err.message);
        });
    }

    document.addEventListener("DOMContentLoaded", function() {
        const page = document.getElementById("svs_run_page");
        if (page) {
            start(page);
        }
    });
})();
