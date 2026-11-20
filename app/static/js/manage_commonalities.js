// The Commonalities panel of the alert management page.
//
// When shown, it asks POST /api/v2/alerts/commonalities which alerts on the page share observables
// and draws them as a grid: a row per alert, a column per shared observable, grouped. It redraws
// when the poll changes which alerts are listed. Whether it is shown and the observables the analyst
// ignores when grouping are kept in this browser (localStorage).
(function() {
    "use strict";

    const SHOWN_KEY = "ace.commonalities.shown";
    const IGNORE_KEY = "ace.commonalities.ignore";
    const MAX_ALERTS = 500;  // COMMONALITIES_MAX_ALERTS in aceapi_v2/alerts/schemas.py
    const MAX_IGNORED = 100;  // the max_length of CommonalitiesRequest.ignore
    // columns a group shows before the rest fold into one "+N more" column; values linking groups always show
    const MAX_COLUMNS = 10;

    let panel, button, count_badge;
    let shown = false;
    let ignored = [];
    let requested_key = null;
    let request_seq = 0;
    let result = null;
    let observable_alerts = [];  // per observable: the Set of its alert uuids
    let expanded = new Set();     // groups (group_key) showing every column
    let ignore_notice = "";       // why the last "ignore" was refused, shown with the ignore list

    function load(key, fallback) {
        try {
            const value = JSON.parse(localStorage.getItem(key));
            return value === null ? fallback : value;
        } catch (e) {
            return fallback;  // nothing stored, or storage unavailable: start from the default
        }
    }

    function save(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (e) {
            // storage unavailable (private mode): the choice lasts until the page is left
        }
    }

    function escape_html(text) {
        return String(text).replace(/[&<>"']/g, function(c) {
            return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
        });
    }

    function plural(n, word) {
        return n + " " + word + (n === 1 ? "" : "s");
    }

    // pale amber (one observable in common) to deep red (many)
    function intensity_color(t, alpha) {
        const lerp = function(a, b) { return (a + (b - a) * t).toFixed(0); };
        return "hsla(" + lerp(46, 4) + ", " + lerp(95, 78) + "%, " + lerp(80, 44) + "%, " + (alpha === undefined ? 1 : alpha) + ")";
    }

    function ink(t) {
        return t > 0.55 ? "#fff" : "#212529";
    }

    function page_rows() {
        return Array.from(document.querySelectorAll('#manage_alert_table tbody tr[id^="alert_row_"]'));
    }

    function row_uuid(tr) {
        return tr.id.substring("alert_row_".length);
    }

    function row_of(alert_uuid) {
        return document.getElementById("alert_row_" + alert_uuid);
    }

    function group_key(group) {
        return group.alert_uuids.slice().sort().join(",");
    }

    // every type:value the alerts have this value as
    function specs(observable) {
        return (observable.types || [observable.type]).map(function(t) { return t + ":" + observable.value; });
    }

    // whether saq.css colors this observable type (.user, .ipv4, ...); probed once per type
    const colored_types = {};
    function has_type_color(o_type) {
        if (!(o_type in colored_types)) {
            const probe = document.createElement("span");
            probe.className = "commonality-chip";
            document.body.appendChild(probe);
            const plain = getComputedStyle(probe).color;
            probe.classList.add(o_type);
            colored_types[o_type] = getComputedStyle(probe).color !== plain;
            probe.remove();
        }
        return colored_types[o_type];
    }

    // A type's color: the alert page's color for it or for the nearest type it extends (email_from takes
    // email_address's), else one derived from its name, so a type looks the same in every column.
    function type_color(o_type) {
        const chain = [o_type].concat((result && result.type_ancestors && result.type_ancestors[o_type]) || []);
        const colored = chain.find(has_type_color);
        if (colored) {
            return {cls: colored, style: ""};
        }
        let hash = 0;
        for (let i = 0; i < o_type.length; i++) {
            hash = (hash * 31 + o_type.charCodeAt(i)) >>> 0;
        }
        const dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
        return {cls: "", style: ' style="color:hsl(' + (hash % 360) + ', 60%, ' + (dark ? 72 : 32) + '%)"'};
    }

    // an observable as a chip colored by its (first) type
    function chip(observable, extra) {
        const types = observable.types || [observable.type];
        const color = type_color(observable.type);
        return '<span class="commonality-chip ' + escape_html(color.cls) + '"' + color.style + (extra || "") +
            ' title="' + escape_html(types.join(", ") + ": " + observable.value) + '">' +
            '<span class="commonality-chip-type">' + escape_html(observable.type) + (types.length > 1 ? " +" + (types.length - 1) : "") + '</span>' +
            '<span class="commonality-chip-value">' + escape_html(observable.value) + '</span></span>';
    }

    function set_shown(value) {
        shown = value;
        save(SHOWN_KEY, shown);
        button.classList.toggle("active", shown);
        button.setAttribute("aria-pressed", shown ? "true" : "false");
        panel.hidden = !shown;
        if (shown) {
            refresh(true);
        } else {
            requested_key = null;
            count_badge.hidden = true;
            clear_row_marks();
        }
    }

    function refresh(force) {
        if (!shown) {
            return;
        }
        const uuids = page_rows().map(row_uuid).slice(0, MAX_ALERTS);
        const key = JSON.stringify([uuids, ignored]);
        if (!force && key === requested_key) {
            decorate_rows();  // a morph may have replaced the rows' badges
            return;
        }
        requested_key = key;
        if (uuids.length === 0) {
            result = null;
            draw("<div class='commonality-empty'>No alerts on this page.</div>");
            return;
        }
        const seq = ++request_seq;
        aceApi.request("POST", "/alerts/commonalities", {alert_uuids: uuids, ignore: ignored}).then(function(response) {
            if (seq !== request_seq) {
                return;  // an answer for a page that has changed since
            }
            result = response;
            observable_alerts = result.observables.map(function(o) { return new Set(o.alert_uuids); });
            render();
        }).catch(function(error) {
            if (seq !== request_seq) {
                return;
            }
            result = null;
            requested_key = null;  // try again on the next change
            draw(ignored_list_html() + "<div class='alert alert-danger py-1 m-0'>Could not compare the alerts: " + escape_html(error.message) + "</div>");
        });
    }

    function draw(html) {
        panel.innerHTML = html;
        count_badge.hidden = !result;
        count_badge.textContent = result ? result.groups.length : "";
        decorate_rows();
    }

    // the columns the grid shows: per group, values linking groups and its first MAX_COLUMNS values (none
    // for a near-identical group), then one "+N more" column for the rest, unless the analyst expanded it
    function layout() {
        const columns = [];
        result.groups.forEach(function(group, g) {
            const owned = [];
            result.observables.forEach(function(o, i) { if (o.group === g) { owned.push(i); } });
            const all = expanded.has(group_key(group));
            const limit = group.near_identical ? 0 : MAX_COLUMNS;
            const hidden = [];
            owned.forEach(function(i, n) {
                if (all || result.observables[i].groups.length > 1 || n < limit) {
                    columns.push({index: i});
                } else {
                    hidden.push(i);
                }
            });
            if (hidden.length) {
                columns.push({more: g, hidden: hidden});
            }
        });
        return columns;
    }

    function render() {
        const rows = page_rows();
        const description = {};
        rows.forEach(function(tr) { description[row_uuid(tr)] = tr.getAttribute("data-description") || row_uuid(tr); });
        const columns = layout();
        const stripe = function(i) { return i % 2 ? " stripe" : ""; };
        const col_attr = function(c) { return c.more === undefined ? ' data-o="' + c.index + '"' : ' data-more="' + c.more + '"'; };

        const header = columns.map(function(c) {
            if (c.more !== undefined) {
                const group = result.groups[c.more];
                return '<th class="commonality-colh more"' + col_attr(c) + '><div class="commonality-lbl">' +
                    '<span class="commonality-chip commonality-more" role="button" tabindex="0" data-expand="' + c.more + '" title="show them">' +
                    (group.near_identical ? c.hidden.length + " shared" : "+" + c.hidden.length + " more") +
                    '</span></div><span class="commonality-tick"></span></th>';
            }
            const o = result.observables[c.index];
            return '<th class="commonality-colh"' + col_attr(c) + '><div class="commonality-lbl">' +
                chip(o, ' data-o="' + c.index + '" role="button" tabindex="0"') +
                (o.groups.length > 1 ? '<span class="commonality-link" title="links ' + o.groups.length + ' groups">&#x21C4;</span>' : "") +
                '</div><span class="commonality-tick"></span></th>';
        }).join("");

        const body = result.groups.map(function(group, g) {
            const color = intensity_color(group.intensity);
            const links = result.observables.filter(function(o) { return o.groups.length > 1 && o.groups.indexOf(g) >= 0; }).map(function(o) {
                const others = o.alert_uuids.filter(function(u) { return group.alert_uuids.indexOf(u) < 0; });
                return "also linked to " + plural(others.length, "alert") + " via <b>" + escape_html(o.value) + "</b>";
            }).join("; ");
            const owned = result.observables.filter(function(o) { return o.group === g; }).length;
            const is_expanded = expanded.has(group_key(group));
            let title = '<b>' + group.alert_uuids.length + ' potentially related alerts</b>';
            if (group.near_identical) {
                title = '<b>' + group.alert_uuids.length + ' near-identical alerts</b>: they share ' +
                    (group.shared === group.total ? "all " + group.total : group.shared + " of their " + group.total) + ' observables';
            }
            const toggle = owned > (group.near_identical ? 0 : MAX_COLUMNS) || is_expanded
                ? '<button type="button" class="btn btn-link btn-sm p-0 ms-2 align-baseline" data-expand="' + g + '">' +
                  (is_expanded ? "show fewer" : (group.near_identical ? "show the observables" : "show all " + owned)) + '</button>'
                : "";
            const head = '<tr class="commonality-ghead"><td colspan="' + (columns.length + 1) + '"><label>' +
                '<input class="form-check-input commonality-group-check" type="checkbox" data-g="' + g + '" title="select these alerts">' +
                '<span class="commonality-swatch" style="background:' + color + '"></span>' + title + '</label>' + toggle +
                (links ? '<span class="commonality-xlinks">&#x21C4; ' + links + '</span>' : "") + '</td></tr>';
            return head + group.alert_uuids.map(function(alert_uuid) {
                return '<tr data-alert="' + escape_html(alert_uuid) + '"><td class="commonality-rowh">' +
                    escape_html(description[alert_uuid] || alert_uuid) + '</td>' +
                    columns.map(function(c, n) {
                        let square = "";
                        if (c.more !== undefined) {
                            if (c.more === g) {
                                const has = c.hidden.filter(function(i) { return observable_alerts[i].has(alert_uuid); }).length;
                                square = '<div class="commonality-sq wide" style="background:' + color + ';color:' + ink(group.intensity) + '">' + has + '</div>';
                            }
                        } else {
                            const o = result.observables[c.index];
                            if (observable_alerts[c.index].has(alert_uuid)) {
                                square = '<div class="commonality-sq' + (o.groups.length > 1 ? " linked" : "") + '" style="background:' + color + '"></div>';
                            } else if (o.group === g) {
                                square = '<div class="commonality-sq empty"></div>';
                            }
                        }
                        return '<td class="commonality-cell' + stripe(n) + '"' + col_attr(c) + '>' + square + '</td>';
                    }).join("") + '</tr>';
            }).join("");
        }).join("");

        const counts = '<tr><td class="commonality-cntlabel">Alerts that have it</td>' + columns.map(function(c, n) {
            const text = c.more === undefined ? result.observables[c.index].alert_uuids.length : "";
            return '<td class="commonality-cnt' + stripe(n) + '"' + col_attr(c) + '>' + text + '</td>';
        }).join("") + '</tr>';

        const ignored_html = ignored_list_html();

        const over = rows.length > MAX_ALERTS ? '<div class="text-muted small">Comparing the first ' + MAX_ALERTS + ' of the ' + rows.length + ' alerts on this page.</div>' : "";

        const grid = result.groups.length === 0
            ? "<div class='commonality-empty'>No two alerts on this page have an observable in common.</div>"
            : '<table class="commonality-grid"><thead><tr><th></th>' + header + '</tr></thead><tbody>' + body + counts + '</tbody></table>';

        draw(ignored_html + over + '<div class="commonality-panel"><div class="commonality-grid-wrap">' + grid + '</div>' +
            '<div class="commonality-legend"><div class="fw-semibold">Commonalities on this page</div><dl class="mb-0">' +
            '<dt>Row</dt><dd>An alert that has at least one observable in common with another alert on this page.</dd>' +
            '<dt>Column</dt><dd>An observable value found in two or more of them, colored by type as on the alert page (+1 when the alerts have it as more than one type). Hover over a square to see what it is. Click a square, its label or its count to select its alerts, ignore it when grouping, or filter it out.</dd>' +
            '<dt>Filled square</dt><dd>The alert has that observable.</dd>' +
            '<dt>Square color</dt><dd>How much the group\'s alerts have in common:<br>one observable <span class="commonality-ramp"></span> many</dd>' +
            (result.observables.some(function(o) { return o.groups.length > 1; }) ? '<dt>&#x21C4; Outlined square</dt><dd>An observable that links the alert to another group.</dd>' : "") +
            '<dt>+N more</dt><dd>A group shows its ' + MAX_COLUMNS + ' most useful observables, and a near-identical group (each pair shares 90% or more) shows none; the number in the wide square is how many of the rest the alert has. Click it to show them.</dd>' +
            '<dt>Group checkbox</dt><dd>Selects the group\'s alerts in the list below, for the bulk actions.</dd></dl>' +
            '<div class="commonality-alone"><span class="commonality-alone-n">' + result.unrelated + '</span>unrelated alert' + (result.unrelated === 1 ? "" : "s") +
            ': nothing in common with any other alert on this page. Not shown in the grid.</div></div></div>' +
            '<div class="commonality-caption" id="commonality_caption"></div>');
        sync_group_checks();
    }

    // the observables ignored when grouping, each with a button that groups by it again
    function ignored_list_html() {
        if (ignored.length === 0) {
            return "";
        }
        return '<div class="commonality-ignored"><span class="text-muted">Ignored when grouping (' + ignored.length + ' of ' + MAX_IGNORED + '):</span>' +
            ignored.map(function(spec, i) {
                const at = spec.indexOf(":");
                return chip({type: spec.substring(0, at), value: spec.substring(at + 1)}) +
                    '<button type="button" class="btn btn-link btn-sm p-0 commonality-unignore" data-i="' + i + '" title="group by it again">&#x2715;</button>';
            }).join("") +
            (ignore_notice ? '<span class="text-danger ms-2 commonality-ignore-notice">' + escape_html(ignore_notice) + '</span>' : "") + '</div>';
    }

    // the "potentially related to N alerts" badge in each listed alert's description cell
    function decorate_rows() {
        page_rows().forEach(function(tr) {
            const alert_uuid = row_uuid(tr);
            const existing = tr.querySelector(".commonality-badge");
            const related = result && shown ? result.related[alert_uuid] : undefined;
            const group = related === undefined ? -1 : result.groups.findIndex(function(g) { return g.alert_uuids.indexOf(alert_uuid) >= 0; });
            if (group < 0) {
                if (existing) { existing.remove(); }
                return;
            }
            const text = "potentially related to " + plural(related, "alert");
            if (existing && existing.textContent === text) {
                return;
            }
            const cell = tr.querySelector('td[data-col-id="description"]');
            if (!cell) {
                return;
            }
            const badge = existing || document.createElement("span");
            const intensity = result.groups[group].intensity;
            badge.className = "commonality-badge";
            badge.style.background = intensity_color(intensity);
            badge.style.color = ink(intensity);
            badge.textContent = text;
            if (!existing) { cell.appendChild(badge); }
        });
    }

    function clear_row_marks() {
        document.querySelectorAll(".commonality-badge").forEach(function(b) { b.remove(); });
        highlight_rows([]);
    }

    function highlight_rows(uuids) {
        document.querySelectorAll("#manage_alert_table tr.commonality-hl").forEach(function(tr) { tr.classList.remove("commonality-hl"); });
        uuids.forEach(function(alert_uuid) {
            const tr = row_of(alert_uuid);
            if (tr) { tr.classList.add("commonality-hl"); }
        });
    }

    function caption(text) {
        const el = document.getElementById("commonality_caption");
        if (el) { el.textContent = text; }
    }

    function selected(alert_uuid) {
        const checkbox = document.getElementById("cb_" + alert_uuid);
        return !!(checkbox && checkbox.checked);
    }

    function sync_group_checks() {
        if (!result) {
            return;
        }
        panel.querySelectorAll(".commonality-group-check").forEach(function(checkbox) {
            const uuids = result.groups[+checkbox.getAttribute("data-g")].alert_uuids;
            const n = uuids.filter(selected).length;
            checkbox.checked = n === uuids.length;
            checkbox.indeterminate = n > 0 && n < uuids.length;
        });
    }

    // $_sel is a Datastar signal on #manage_page; ace-select and ace-deselect change it
    function set_selected(uuids, on) {
        document.getElementById("manage_page").dispatchEvent(new CustomEvent(on ? "ace-select" : "ace-deselect", {detail: {uuids: uuids}}));
        requestAnimationFrame(sync_group_checks);
    }

    function close_menu() {
        document.querySelectorAll(".commonality-menu").forEach(function(m) { m.remove(); });
    }

    function open_menu(label, index) {
        close_menu();
        const o = result.observables[index];
        const all_specs = specs(o);
        const menu = document.createElement("div");
        menu.className = "commonality-menu";
        menu.innerHTML = '<div class="commonality-menu-head">' + chip(o) + '<div class="text-muted small mt-1">in ' +
            plural(o.alert_uuids.length, "alert") + ' on this page' + (o.groups.length > 1 ? ", across " + o.groups.length + " groups" : "") + '</div></div>' +
            '<button type="button" data-act="select">Select the ' + plural(o.alert_uuids.length, "alert") + ' that have it</button>' +
            '<button type="button" data-act="ignore">Ignore it when grouping<small>The alerts stay in the list. They just aren\'t grouped by this observable any more.</small></button>' +
            '<button type="button" data-act="not">Filter out: <b>NOT Observable: ' + escape_html(all_specs.join(" | ")) + '</b><small>Adds this filter to the alert list, which removes the ' +
            plural(o.alert_uuids.length, "alert") + ' that have it.</small></button>';
        const r = label.getBoundingClientRect();
        menu.style.left = (r.right + window.scrollX + 8) + "px";
        menu.style.top = (r.top + window.scrollY) + "px";
        document.body.appendChild(menu);
        menu.addEventListener("click", function(e) {
            const action = e.target.closest("button");
            if (!action) {
                return;
            }
            close_menu();
            const act = action.getAttribute("data-act");
            if (act === "select") {
                set_selected(o.alert_uuids, true);
            } else if (act === "ignore") {
                const added = all_specs.filter(function(spec) { return ignored.indexOf(spec) < 0; });
                if (ignored.length + added.length > MAX_IGNORED) {
                    ignore_notice = "Not ignored: at most " + MAX_IGNORED + " can be. Group by one of these again (✕) to make room.";
                    render();
                    return;
                }
                ignore_notice = "";
                ignored = ignored.concat(added);
                save(IGNORE_KEY, ignored);
                refresh(true);
            } else if (act === "not") {
                apply_temp_filter([{name: "Observable", inverted: true, values: (o.types || [o.type]).map(function(t) { return [t, o.value]; })}],
                    "NOT Observable " + all_specs.join(" | "), panel.getAttribute("data-apply-url"), panel.getAttribute("data-manage-url"), true);
            }
        });
    }

    // what the square under the pointer is, next to the pointer, so a square far below its label still says what it is
    let tip = null;
    function show_tip(cell, e) {
        if (!tip) {
            tip = document.createElement("div");
            tip.className = "commonality-tip";
            document.body.appendChild(tip);
        }
        const index = +cell.getAttribute("data-o");
        const o = result.observables[index];
        const row = cell.parentElement.getAttribute("data-alert");
        let has = "";
        if (row) {
            has = '<div>' + (observable_alerts[index].has(row) ? "This alert has it." : "This alert does not have it.") + '</div>';
        }
        tip.innerHTML = chip(o) + '<div class="mt-1">' + plural(o.alert_uuids.length, "alert") + ' on this page have it' +
            (o.groups.length > 1 ? ", across " + o.groups.length + " groups" : "") + '.</div>' + has +
            '<div class="text-muted">Click for actions.</div>';
        tip.hidden = false;
        move_tip(e);
    }

    function move_tip(e) {
        if (!tip || tip.hidden || e.clientX === undefined) {
            return;
        }
        const width = tip.offsetWidth, height = tip.offsetHeight;
        let x = e.clientX + 16, y = e.clientY + 16;
        if (x + width > window.innerWidth - 8) { x = e.clientX - width - 16; }
        if (y + height > window.innerHeight - 8) { y = e.clientY - height - 16; }
        tip.style.left = Math.max(8, x) + "px";
        tip.style.top = Math.max(8, y) + "px";
    }

    function hide_tip() {
        if (tip) { tip.hidden = true; }
    }

    function hot_column(index, on) {
        panel.querySelectorAll('[data-o="' + index + '"]').forEach(function(el) { el.classList.toggle("hot", on); });
    }

    function on_hover(e) {
        const cell = e.target.closest(".commonality-cell, .commonality-colh, .commonality-rowh, .commonality-cnt");
        panel.querySelectorAll(".hot").forEach(function(el) { el.classList.remove("hot"); });
        if (!cell || !result || !cell.matches(".commonality-cell[data-o], .commonality-cnt[data-o]")) {
            hide_tip();
        }
        if (!cell || !result) {
            highlight_rows([]);
            caption("");
            return;
        }
        if (cell.classList.contains("commonality-rowh")) {
            const alert_uuid = cell.parentElement.getAttribute("data-alert");
            const others = result.observables.filter(function(o, i) { return observable_alerts[i].has(alert_uuid); })
                .reduce(function(all, o) { o.alert_uuids.forEach(function(u) { all.add(u); }); return all; }, new Set());
            others.delete(alert_uuid);
            cell.parentElement.classList.add("hot");
            highlight_rows([alert_uuid].concat(Array.from(others)));
            caption("Highlighted: this alert and the " + plural(others.size, "alert") + " potentially related to it");
            return;
        }
        if (cell.hasAttribute("data-more")) {
            const more = +cell.getAttribute("data-more");
            panel.querySelectorAll('[data-more="' + more + '"]').forEach(function(el) { el.classList.add("hot"); });
            highlight_rows(result.groups[more].alert_uuids);
            caption("The other observables this group shares. Click to show them.");
            return;
        }
        const index = +cell.getAttribute("data-o");
        const o = result.observables[index];
        hot_column(index, true);
        highlight_rows(o.alert_uuids);
        if (cell.classList.contains("commonality-cell")) {
            cell.parentElement.classList.add("hot");
        }
        if (cell.matches(".commonality-cell, .commonality-cnt")) {
            show_tip(cell, e);
        }
        caption("Highlighted: the " + plural(o.alert_uuids.length, "alert") + " that have " + o.type + " " + o.value + ". Click for actions.");
    }

    function init() {
        panel = document.getElementById("commonality_panel");
        button = document.getElementById("btn-commonalities");
        count_badge = document.getElementById("commonalities-count");
        if (!panel || !button) {
            return;
        }
        ignored = load(IGNORE_KEY, []).filter(function(spec) { return typeof spec === "string"; }).slice(-MAX_IGNORED);

        button.addEventListener("click", function() { set_shown(!shown); });
        panel.addEventListener("mouseover", on_hover);
        panel.addEventListener("mouseleave", function() { on_hover({target: panel}); });
        panel.addEventListener("mousemove", move_tip);
        // the menu is placed against the page, so it closes when the grid scrolls under it
        panel.addEventListener("scroll", function() { close_menu(); hide_tip(); }, true);
        panel.addEventListener("click", function(e) {
            const expand = e.target.closest("[data-expand]");
            if (expand && result) {
                e.preventDefault();
                const key = group_key(result.groups[+expand.getAttribute("data-expand")]);
                expanded.has(key) ? expanded.delete(key) : expanded.add(key);
                render();
                return;
            }
            const more = e.target.closest(".commonality-cell[data-more]");
            if (more && more.querySelector(".commonality-sq") && result) {
                const key = group_key(result.groups[+more.getAttribute("data-more")]);
                expanded.add(key);
                render();
                return;
            }
            const label = e.target.closest(".commonality-chip[data-o], .commonality-cell[data-o], .commonality-cnt[data-o]");
            if (label) {
                e.stopPropagation();
                hide_tip();
                open_menu(label, +label.getAttribute("data-o"));
                return;
            }
            const unignore = e.target.closest(".commonality-unignore");
            if (unignore) {
                ignore_notice = "";
                ignored = ignored.filter(function(_, i) { return i !== +unignore.getAttribute("data-i"); });
                save(IGNORE_KEY, ignored);
                refresh(true);
            }
        });
        panel.addEventListener("keydown", function(e) {
            if (e.target.closest("[data-expand]") && (e.key === "Enter" || e.key === " ")) {
                e.preventDefault();
                e.target.closest("[data-expand]").click();
                return;
            }
            const label = e.target.closest(".commonality-chip[data-o]");
            if (label && (e.key === "Enter" || e.key === " ")) {
                e.preventDefault();
                open_menu(label, +label.getAttribute("data-o"));
            }
        });
        panel.addEventListener("change", function(e) {
            const checkbox = e.target.closest(".commonality-group-check");
            if (checkbox && result) {
                set_selected(result.groups[+checkbox.getAttribute("data-g")].alert_uuids, checkbox.checked);
            }
        });
        document.addEventListener("click", function(e) {
            if (!e.target.closest(".commonality-menu")) { close_menu(); }
        });
        // a row's checkbox, or select-all, changed the selection
        document.getElementById("manage_page").addEventListener("change", function() { requestAnimationFrame(sync_group_checks); });

        // the poll morphs new rows in; compare the alerts listed once the morph settles
        let pending = null;
        new MutationObserver(function() {
            clearTimeout(pending);
            pending = setTimeout(function() { refresh(false); sync_group_checks(); }, 250);
        }).observe(document.getElementById("manage_page"), {childList: true, subtree: true});

        if (load(SHOWN_KEY, false) === true) {
            set_shown(true);
        }
    }

    document.addEventListener("DOMContentLoaded", init);
})();
