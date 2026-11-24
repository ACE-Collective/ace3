// Feeds -> Watches, Feeds, Replay and a watch's Evaluation (docs/FEED_WATCHES.md).
//
// Every page is a shell: this script gets everything from /api/v2/feeds and /api/v2/feed-watches
// through aceApi (same origin, the Flask session cookie). Text from feeds and the model is untrusted:
// it only ever reaches the page through textContent.

var feedsUi = (function() {
    "use strict";

    function el(tag, attrs, children) {
        const node = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function(key) {
            const value = attrs[key];
            if (value === undefined || value === null || value === false) {
                return;
            }
            if (key === "text") {
                node.textContent = value;
            } else if (key === "className") {
                node.className = value;
            } else if (key.startsWith("on")) {
                node.addEventListener(key.substring(2), value);
            } else {
                node.setAttribute(key, value === true ? "" : value);
            }
        });
        (children || []).forEach(function(child) {
            if (child === null || child === undefined) {
                return;
            }
            node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
        });
        return node;
    }

    function link(href, text) {
        // only http(s) links from a feed are followed
        if (!href || !/^https?:\/\//i.test(href)) {
            return el("span", {text: text || href || ""});
        }
        return el("a", {href: href, target: "_blank", rel: "noopener noreferrer", text: text || href});
    }

    function when(value) {
        return value ? value.replace("T", " ").substring(0, 19) : "";
    }

    function show_error(error) {
        const box = document.getElementById("feeds_error");
        box.textContent = error && error.message ? error.message : String(error);
        box.classList.remove("d-none");
        window.scrollTo(0, 0);
    }

    function notice(text) {
        const box = document.getElementById("feeds_notice");
        box.textContent = text;
        box.classList.toggle("d-none", !text);
    }

    function clear_messages() {
        document.getElementById("feeds_error").classList.add("d-none");
        notice("");
    }

    function fill(tbody, rows) {
        tbody.replaceChildren.apply(tbody, rows);
    }

    function selected_ids(select) {
        return Array.from(select.selectedOptions).map(function(option) { return parseInt(option.value, 10); });
    }

    // every page of a listing, for the small ones a form needs whole (feeds, definitions, watches)
    function all_pages(path) {
        const rows = [];
        function next(cursor) {
            return aceApi.get(path + aceApi.query({cursor: cursor, limit: 500})).then(function(page) {
                rows.push.apply(rows, page.data);
                return page.next_cursor ? next(page.next_cursor) : rows;
            });
        }
        return next(null);
    }

    //
    // Feeds
    //

    function feeds_page(root) {
        const can_write = root.dataset.canWrite === "true";
        const tbody = document.querySelector("#feed_table tbody");
        const form = document.getElementById("feed_form");
        let entry_feed = null;
        let entry_cursor = null;

        function feed_row(feed) {
            const actions = [el("button", {type: "button", className: "btn btn-sm btn-link p-0 me-2", text: "Entries",
                                           onclick: function() { show_entries(feed); }})];
            if (can_write) {
                actions.push(el("button", {type: "button", className: "btn btn-sm btn-link p-0 me-2", text: "Edit",
                                           onclick: function() { edit(feed); }}));
                actions.push(el("button", {type: "button", className: "btn btn-sm btn-link p-0 text-danger", text: "Delete",
                                           onclick: function() { remove(feed); }}));
            }
            return el("tr", {className: feed.enabled ? "" : "text-muted"}, [
                el("td", {}, [feed.name, feed.has_secret ? el("span", {className: "badge text-bg-secondary ms-1", text: feed.auth_type}) : null,
                              feed.enabled ? null : el("span", {className: "badge text-bg-light ms-1", text: "disabled"})]),
                el("td", {style: "overflow-wrap:anywhere"}, [link(feed.url)]),
                el("td", {text: feed.title || ""}),
                el("td", {text: feed.poll_interval_seconds + "s"}),
                el("td", {text: when(feed.last_success_at) || (feed.baselined_at ? "" : "not yet")}),
                el("td", {className: "text-danger small"}, [when(feed.last_failure_at), feed.last_error ? el("div", {text: feed.last_error}) : null]),
                el("td", {className: "text-nowrap"}, actions),
            ]);
        }

        function load() {
            return all_pages("/feeds/").then(function(rows) { fill(tbody, rows.map(feed_row)); }).catch(show_error);
        }

        function edit(feed) {
            document.getElementById("feed_form_title").textContent = "Edit " + feed.name;
            document.getElementById("feed_id").value = feed.id;
            document.getElementById("feed_name").value = feed.name;
            document.getElementById("feed_url").value = feed.url;
            document.getElementById("feed_interval").value = feed.poll_interval_seconds;
            document.getElementById("feed_enabled").checked = feed.enabled;
            document.getElementById("feed_auth_type").value = feed.auth_type;
            document.getElementById("feed_auth_name").value = feed.auth_name || "";
            document.getElementById("feed_auth_secret").value = "";
            document.getElementById("feed_auth_secret").placeholder = feed.has_secret ? "stored; leave empty to keep it" : "stored encrypted; never shown again";
            form.scrollIntoView();
        }

        function reset() {
            form.reset();
            document.getElementById("feed_id").value = "";
            document.getElementById("feed_form_title").textContent = "Add a feed";
        }

        function remove(feed) {
            if (!window.confirm("Delete the feed " + feed.name + " and every entry ACE kept of it?")) {
                return;
            }
            aceApi.del("/feeds/" + feed.id).then(function() { notice("deleted " + feed.name); load(); }).catch(show_error);
        }

        function entry_card(entry) {
            return el("div", {className: "card mb-2"}, [el("div", {className: "card-body py-2"}, [
                el("div", {}, [link(entry.link, entry.title || entry.link || entry.identity),
                               entry.baseline ? el("span", {className: "badge text-bg-light ms-2", text: "first poll (preview only)"}) : null]),
                el("div", {className: "small text-muted", text: "published " + (when(entry.published_at) || "?") + ", first seen " + when(entry.first_seen_at) +
                           (entry.categories.length ? ", categories: " + entry.categories.join(", ") : "")}),
                el("div", {className: "small mt-1", style: "white-space:pre-wrap", text: entry.text + (entry.text_truncated ? " …" : "")}),
            ])]);
        }

        function load_entries(more) {
            aceApi.get("/feeds/" + entry_feed.id + "/entries" + aceApi.query({cursor: more ? entry_cursor : null, limit: 25})).then(function(page) {
                const list = document.getElementById("entry_list");
                if (!more) {
                    list.replaceChildren();
                }
                page.data.forEach(function(entry) { list.appendChild(entry_card(entry)); });
                if (!more && !page.data.length) {
                    list.appendChild(el("p", {className: "text-muted", text: "No entries yet."}));
                }
                entry_cursor = page.next_cursor;
                document.getElementById("entry_more").classList.toggle("d-none", !entry_cursor);
            }).catch(show_error);
        }

        function show_entries(feed) {
            entry_feed = feed;
            document.getElementById("entry_feed_name").textContent = feed.name;
            document.getElementById("entry_panel").classList.remove("d-none");
            load_entries(false);
        }

        document.getElementById("entry_more").addEventListener("click", function() { load_entries(true); });
        if (form) {
            document.getElementById("feed_form_reset").addEventListener("click", reset);
            form.addEventListener("submit", function(event) {
                event.preventDefault();
                clear_messages();
                const id = document.getElementById("feed_id").value;
                const interval = document.getElementById("feed_interval").value;
                const secret = document.getElementById("feed_auth_secret").value;
                const body = {
                    name: document.getElementById("feed_name").value,
                    url: document.getElementById("feed_url").value,
                    poll_interval_seconds: interval ? parseInt(interval, 10) : null,
                    enabled: document.getElementById("feed_enabled").checked,
                    auth_type: document.getElementById("feed_auth_type").value,
                    auth_name: document.getElementById("feed_auth_name").value || null,
                };
                if (secret) {
                    body.auth_secret = secret;
                }
                const saving = id ? aceApi.patch("/feeds/" + id, body) : aceApi.post("/feeds/", body);
                saving.then(function(feed) { notice("saved " + feed.name); reset(); load(); }).catch(show_error);
            });
        }
        load();
    }

    //
    // Watches
    //

    function watches_page(root) {
        const can_write = root.dataset.canWrite === "true";
        const evaluation_url = root.dataset.evaluationUrl;
        const form = document.getElementById("watch_form");
        let definitions = {};
        let failed_cursor = null;

        function definition_warning() {
            const box = document.getElementById("watch_definition_warning");
            const definition = definitions[document.getElementById("watch_definition").value];
            const text = definition && definition.question && !definition.yara
                ? "This definition has no rule: every entry of the watch's feeds goes to the LLM endpoint." : "";
            box.textContent = text;
            box.classList.toggle("d-none", !text);
        }

        function watch_row(watch) {
            const actions = [el("a", {href: evaluation_url.replace("/watches/0/", "/watches/" + watch.id + "/"), className: "me-2", text: "Evaluation"})];
            if (can_write) {
                actions.push(el("button", {type: "button", className: "btn btn-sm btn-link p-0 me-2", text: "Edit",
                                           onclick: function() { edit(watch); }}));
                actions.push(el("button", {type: "button", className: "btn btn-sm btn-link p-0",
                                           text: watch.mode === "delivering" ? "Switch to shadow" : "Start delivering",
                                           onclick: function() { save(watch.id, {mode: watch.mode === "delivering" ? "shadow" : "delivering"}); }}));
            }
            return el("tr", {className: watch.enabled ? "" : "text-muted"}, [
                el("td", {}, [watch.name, watch.enabled ? null : el("span", {className: "badge text-bg-light ms-1", text: "disabled"})]),
                el("td", {}, [watch.definition_name,
                              watch.flag ? el("div", {className: "small text-danger", text: watch.flag}) : null,
                              watch.warning ? el("div", {className: "small text-warning-emphasis", text: "question only: every entry goes to the LLM"}) : null]),
                el("td", {className: "small", text: watch.feeds.map(function(feed) { return feed.name; }).join(", ")}),
                el("td", {text: watch.queue}),
                el("td", {}, [el("span", {className: "badge " + (watch.mode === "delivering" ? "text-bg-success" : "text-bg-secondary"), text: watch.mode})]),
                el("td", {className: "small font-monospace", text: watch.watch_version}),
                el("td", {text: watch.pending_decisions + " / " + watch.failed_decisions}),
                el("td", {className: "text-nowrap"}, actions),
            ]);
        }

        function definition_row(definition) {
            return el("tr", {}, [
                el("td", {text: definition.name}),
                el("td", {className: "small", text: definition.repository + "/" + definition.path}),
                el("td", {text: definition.yara ? "yes" : ""}),
                el("td", {className: "small", text: definition.question || ""}),
                el("td", {className: definition.usable ? "" : "text-danger small",
                          text: definition.usable ? (definition.error || "ok") : (definition.present ? definition.error : "missing: " + (definition.error || ""))}),
            ]);
        }

        function failed_row(decision) {
            return el("tr", {}, [
                el("td", {className: "small", text: when(decision.decided_at || decision.created_at)}),
                el("td", {className: "small", text: decision.kind === "replay" ? "(replay)" : (decision.definition_name + " " + (decision.watch_version || ""))}),
                el("td", {}, [link(decision.entry.link, decision.entry.title || decision.entry.link)]),
                el("td", {text: String(decision.attempts)}),
                el("td", {className: "small text-danger", text: decision.last_error || ""}),
            ]);
        }

        function load_failed(more) {
            aceApi.get("/feed-watches/decisions" + aceApi.query({status: "failed", cursor: more ? failed_cursor : null, limit: 25})).then(function(page) {
                const tbody = document.querySelector("#failed_table tbody");
                if (!more) {
                    tbody.replaceChildren();
                }
                page.data.forEach(function(decision) { tbody.appendChild(failed_row(decision)); });
                failed_cursor = page.next_cursor;
                document.getElementById("failed_more").classList.toggle("d-none", !failed_cursor);
            }).catch(show_error);
        }

        function load() {
            all_pages("/feed-watches/").then(function(rows) {
                fill(document.querySelector("#watch_table tbody"), rows.map(watch_row));
            }).catch(show_error);
        }

        function edit(watch) {
            document.getElementById("watch_form_title").textContent = "Edit " + watch.name;
            document.getElementById("watch_id").value = watch.id;
            document.getElementById("watch_name").value = watch.name;
            document.getElementById("watch_definition").value = watch.definition_name;
            document.getElementById("watch_queue").value = watch.queue;
            document.getElementById("watch_mode").value = watch.mode;
            document.getElementById("watch_enabled").checked = watch.enabled;
            const ids = watch.feeds.map(function(feed) { return String(feed.id); });
            Array.from(document.getElementById("watch_feeds").options).forEach(function(option) {
                option.selected = ids.indexOf(option.value) >= 0;
            });
            definition_warning();
            form.scrollIntoView();
        }

        function reset() {
            form.reset();
            document.getElementById("watch_id").value = "";
            document.getElementById("watch_form_title").textContent = "Create a watch";
            definition_warning();
        }

        function save(id, body) {
            clear_messages();
            const saving = id ? aceApi.patch("/feed-watches/" + id, body) : aceApi.post("/feed-watches/", body);
            return saving.then(function(watch) {
                notice("saved " + watch.name + (watch.warning ? " (" + watch.warning + ")" : ""));
                if (form) {
                    reset();
                }
                load();
            }).catch(show_error);
        }

        all_pages("/feed-watches/definitions").then(function(rows) {
            fill(document.querySelector("#definition_table tbody"), rows.map(definition_row));
            const select = document.getElementById("watch_definition");
            rows.forEach(function(definition) {
                definitions[definition.name] = definition;
                if (select && definition.present) {
                    select.appendChild(el("option", {value: definition.name, text: definition.name + (definition.usable ? "" : " (unusable)")}));
                }
            });
            if (form) {
                definition_warning();
            }
        }).catch(show_error);

        if (form) {
            if (root.dataset.canReadFeeds === "true") {
                all_pages("/feeds/").then(function(feeds) {
                    const select = document.getElementById("watch_feeds");
                    feeds.forEach(function(feed) { select.appendChild(el("option", {value: feed.id, text: feed.name})); });
                }).catch(show_error);
            }
            document.getElementById("watch_definition").addEventListener("change", definition_warning);
            document.getElementById("watch_form_reset").addEventListener("click", reset);
            form.addEventListener("submit", function(event) {
                event.preventDefault();
                const id = document.getElementById("watch_id").value;
                save(id, {
                    name: document.getElementById("watch_name").value,
                    definition_name: document.getElementById("watch_definition").value,
                    feed_ids: selected_ids(document.getElementById("watch_feeds")),
                    queue: document.getElementById("watch_queue").value,
                    mode: document.getElementById("watch_mode").value,
                    enabled: document.getElementById("watch_enabled").checked,
                });
            });
        }
        document.getElementById("failed_more").addEventListener("click", function() { load_failed(true); });
        load();
        load_failed(false);
    }

    //
    // Replay
    //

    function replay_page(root) {
        const can_write = root.dataset.canWrite === "true";
        const form = document.getElementById("replay_form");
        let replay = null;
        let outcome = "";
        let cursor = null;
        let timer = null;
        let definitions = {};

        function warning() {
            const box = document.getElementById("replay_warning");
            const yara_source = document.getElementById("replay_yara").value.trim();
            const question = document.getElementById("replay_question").value.trim();
            const text = question && !yara_source ? "No rule: the question is asked of every entry, through the LLM endpoint." : "";
            box.textContent = text;
            box.classList.toggle("d-none", !text);
        }

        function status() {
            const counts = replay.counts;
            const parts = [
                "Replay " + replay.id + ": " + replay.state,
                counts.entries + " entries",
            ];
            if (replay.yara) {
                parts.push(counts.rule_matched + " matched the rule");
            }
            if (replay.question) {
                parts.push(counts.asked + " asked: " + counts.match + " match, " + counts.no_match + " no match, " +
                           counts.insufficient_evidence + " insufficient evidence, " + counts.pending + " pending, " + counts.failed + " failed");
            }
            const box = document.getElementById("replay_status");
            box.replaceChildren(el("div", {className: "alert " + (replay.state === "failed" ? "alert-danger" : "alert-secondary")}, [
                parts.join("; "), replay.error ? el("div", {text: replay.error}) : null]));
        }

        function label_buttons(result) {
            if (!can_write || !replay.watch_id) {
                return result.label ? el("span", {className: "badge text-bg-info", text: result.label}) : null;
            }
            function button(label, text) {
                return el("button", {type: "button", className: "btn btn-sm " + (result.label === label ? "btn-dark" : "btn-outline-dark"), text: text,
                                     onclick: function() {
                                         const path = "/feed-watches/" + replay.watch_id + "/labels/" + result.entry.id;
                                         const request = result.label === label ? aceApi.del(path) : aceApi.put(path, {label: label});
                                         request.then(function() { load_results(false); }).catch(show_error);
                                     }});
            }
            return el("div", {className: "btn-group btn-group-sm"}, [button("relevant", "Relevant"), button("not_relevant", "Not relevant")]);
        }

        function result_card(result) {
            const verdict = result.matched === null ? "pending" : (result.matched ? "match" : "miss");
            const evidence = [];
            if (result.yara_matched !== null && result.yara_matched !== undefined) {
                evidence.push(el("div", {className: "small"}, [el("b", {text: "Rule: "}), result.yara_matched ? "matched in " + result.yara_field : "no match"]));
                if (result.yara_excerpt) {
                    evidence.push(el("blockquote", {className: "small border-start ps-2 mb-1", text: result.yara_excerpt}));
                }
            }
            if (result.status) {
                evidence.push(el("div", {className: "small"}, [el("b", {text: "Question: "}), result.status === "decided" ? result.decision : result.status,
                                                               result.last_error && result.status !== "decided" ? " (" + result.last_error + ")" : ""]));
                if (result.excerpt) {
                    evidence.push(el("blockquote", {className: "small border-start ps-2 mb-1", text: result.excerpt}));
                }
                if (result.rationale) {
                    evidence.push(el("div", {className: "small text-muted", text: result.rationale}));
                }
            }
            return el("div", {className: "card mb-2"}, [el("div", {className: "card-body py-2"}, [
                el("div", {className: "d-flex justify-content-between"}, [
                    el("div", {}, [el("span", {className: "badge me-2 " + (verdict === "match" ? "text-bg-success" : verdict === "miss" ? "text-bg-light" : "text-bg-warning"), text: verdict}),
                                   link(result.entry.link, result.entry.title || result.entry.link)]),
                    label_buttons(result),
                ]),
                el("div", {className: "small text-muted", text: "published " + (when(result.entry.published_at) || "?") + ", first seen " + when(result.entry.first_seen_at)}),
            ].concat(evidence).concat([
                el("details", {className: "small"}, [el("summary", {text: "text"}), el("div", {style: "white-space:pre-wrap", text: result.text})]),
            ]))]);
        }

        function load_results(more) {
            aceApi.get("/feed-watches/replays/" + replay.id + "/results" + aceApi.query({outcome: outcome || null, cursor: more ? cursor : null, limit: 50})).then(function(page) {
                const list = document.getElementById("replay_results");
                if (!more) {
                    list.replaceChildren();
                }
                page.data.forEach(function(result) { list.appendChild(result_card(result)); });
                cursor = page.next_cursor;
                document.getElementById("replay_more").classList.toggle("d-none", !cursor);
            }).catch(show_error);
        }

        function poll(replay_id) {
            aceApi.get("/feed-watches/replays/" + replay_id).then(function(current) {
                replay = current;
                status();
                document.getElementById("replay_results_panel").classList.remove("d-none");
                load_results(false);
                if (current.state === "queued" || current.state === "running") {
                    timer = window.setTimeout(function() { poll(replay_id); }, 5000);
                }
            }).catch(show_error);
        }

        document.querySelectorAll("#replay_results_panel [data-outcome]").forEach(function(button) {
            button.addEventListener("click", function() {
                document.querySelectorAll("#replay_results_panel [data-outcome]").forEach(function(other) { other.classList.remove("active"); });
                button.classList.add("active");
                outcome = button.dataset.outcome;
                load_results(false);
            });
        });
        document.getElementById("replay_more").addEventListener("click", function() { load_results(true); });

        const replay_id = new URLSearchParams(window.location.search).get("replay");
        if (replay_id) {
            poll(replay_id);
        }

        if (!form) {
            return;
        }
        if (root.dataset.canReadFeeds === "true") {
            all_pages("/feeds/").then(function(feeds) {
                const select = document.getElementById("replay_feeds");
                feeds.forEach(function(feed) { select.appendChild(el("option", {value: feed.id, text: feed.name})); });
            }).catch(show_error);
        }
        all_pages("/feed-watches/").then(function(watches) {
            const select = document.getElementById("replay_watch");
            watches.forEach(function(watch) { select.appendChild(el("option", {value: watch.id, text: watch.name})); });
        }).catch(show_error);
        all_pages("/feed-watches/definitions").then(function(rows) {
            const select = document.getElementById("replay_from_definition");
            rows.forEach(function(definition) {
                definitions[definition.name] = definition;
                select.appendChild(el("option", {value: definition.name, text: definition.name}));
            });
        }).catch(show_error);
        document.getElementById("replay_from_definition").addEventListener("change", function(event) {
            const definition = definitions[event.target.value];
            if (definition) {
                document.getElementById("replay_yara").value = definition.yara || "";
                document.getElementById("replay_question").value = definition.question || "";
                warning();
            }
        });
        document.getElementById("replay_yara").addEventListener("input", warning);
        document.getElementById("replay_question").addEventListener("input", warning);
        form.addEventListener("submit", function(event) {
            event.preventDefault();
            clear_messages();
            if (timer) {
                window.clearTimeout(timer);
            }
            const watch_id = document.getElementById("replay_watch").value;
            aceApi.post("/feed-watches/replays", {
                yara: document.getElementById("replay_yara").value || null,
                question: document.getElementById("replay_question").value || null,
                feed_ids: selected_ids(document.getElementById("replay_feeds")),
                watch_id: watch_id ? parseInt(watch_id, 10) : null,
            }).then(function(created) {
                window.history.replaceState(null, "", "?replay=" + created.id);
                poll(created.id);
            }).catch(show_error);
        });
    }

    //
    // Evaluation
    //

    function evaluation_page(root) {
        const watch_id = root.dataset.watchId;
        aceApi.get("/feed-watches/" + watch_id).then(function(watch) {
            document.getElementById("evaluation_watch_name").textContent = watch.name;
        }).catch(show_error);
        aceApi.get("/feed-watches/" + watch_id + "/evaluation").then(function(evaluation) {
            document.getElementById("evaluation_summary").replaceChildren(el("p", {text:
                evaluation.labeled + " labeled entries: " + evaluation.relevant + " relevant, " + evaluation.not_relevant + " not relevant."}));
            const container = document.getElementById("evaluation_configurations");
            if (!evaluation.configurations.length) {
                container.appendChild(el("p", {className: "text-muted", text: "No decisions yet."}));
            }
            evaluation.configurations.forEach(function(configuration) {
                const rows = configuration.scores.map(function(score) {
                    return el("tr", {}, [
                        el("td", {text: score.predictor === "yara_only" ? "YARA only" : (configuration.model ? "model" : "rule")}),
                        el("td", {text: String(score.evaluated)}),
                        el("td", {text: String(score.true_positives)}),
                        el("td", {className: score.false_alerts ? "text-danger" : "", text: String(score.false_alerts)}),
                        el("td", {className: score.missed_relevant ? "text-danger" : "", text: String(score.missed_relevant)}),
                        el("td", {text: String(score.true_negatives)}),
                        el("td", {text: String(score.insufficient_evidence)}),
                        el("td", {text: score.pending + " / " + score.failed}),
                    ]);
                });
                const cost = configuration.questions_asked
                    ? configuration.questions_asked + " questions asked; latency avg " + Math.round(configuration.avg_latency_ms) + " ms, max " +
                      configuration.max_latency_ms + " ms; tokens " + configuration.prompt_tokens + " in, " + configuration.completion_tokens + " out" +
                      (configuration.response_models.length ? "; answered by " + configuration.response_models.join(", ") : "")
                    : "no questions asked";
                container.appendChild(el("div", {className: "card mb-3"}, [el("div", {className: "card-body"}, [
                    el("h5", {className: "card-title font-monospace", text: configuration.watch_version + (configuration.model ? " · " + configuration.model : "") +
                                                                           (configuration.prompt_hash ? " · prompt " + configuration.prompt_hash.substring(0, 12) : "")}),
                    el("p", {className: "small text-muted", text: cost}),
                    el("table", {className: "table table-sm mb-0"}, [
                        el("thead", {}, [el("tr", {}, ["", "labeled & decided", "true matches", "false alerts", "missed relevant", "true misses", "insufficient evidence", "pending / failed"].map(function(text) { return el("th", {text: text}); }))]),
                        el("tbody", {}, rows),
                    ]),
                ])]));
            });
        }).catch(show_error);
    }

    function start() {
        const pages = {feeds_page: feeds_page, watches_page: watches_page, replay_page: replay_page, evaluation_page: evaluation_page};
        Object.keys(pages).forEach(function(id) {
            const root = document.getElementById(id);
            if (root) {
                pages[id](root);
            }
        });
    }

    return {start: start};
})();

document.addEventListener("DOMContentLoaded", feedsUi.start);
