// A filtered, sorted, paged list screen built as a shell over the API (docs/SVS.md, Part 5): the
// Signatures -> Samples page, and the SVS screens after it.
//
// The screen's filters are the {name, inverted, values} entries of a filter screen
// (saq/gui/filter_screens.py). The controller reads the screen's descriptor from
// /api/v2/filter-screens/{screen}, builds a generic editor from it, and keeps everything a reader
// can share in the page URL:
//
//     ?f=label:conflicted&f=!stored:true   the filters, in the share-link encoding (saq/gui/filter_url.py)
//     &sort=last_captured&desc=true        the order
//     &limit=50                            the page size
//     &saved=<uuid>                        the saved filter that is open, if any
//
// The list API takes the same f= values, so the URL's filters go to it as they are. The encoding
// lives only in Python: the controller decodes a URL's filters, and encodes the editor's, through
// /api/v2/filter-screens/{screen}/{decode,encode}.
//
// A page includes the saved_filter_modals macro (app/templates/saved_filters/_modals.html), loads
// ace_api.js, saved_filters.js and this file, and creates the page:
//
//     FilterListPage.create({
//         root: element,                 // the page fills it with the filter bar, table and pager
//         screen: "svs_samples",         // the filter screen
//         api: "/svs/samples",           // the list API under /api/v2: GET {api}/ -> {data, next_cursor}
//         columns: [{                // one per table column
//             label, title, width, css,
//             sort, sortDesc,            // an API sort value (or null), and its first direction
//             render(row),               // a Node or text
//         }],
//         defaultSort: "last_captured", defaultDesc: true,
//         pageSizes: [25, 50, 100], defaultLimit: 50,
//         tz: "America/New_York",        // relative date filters resolve in it
//         exports: ["csv", "ndjson"],    // formats served at {api}/export/{format}
//         download: {path, hint},        // optional: a bulk download at {api}{path}?f=...
//         emptyText: "...",
//     });
//
// It creates the page's SAVED_FILTERS instance (saved_filters.js), which the macro's markup
// calls. Every value shown comes from analyzed data, so it is placed as text, never markup.

var FilterListPage = (function() {
    "use strict";

    const DATE_RANGE_HINT = "-7d, @d, -1d@d - now, or 01-15-2026 08:00 - 01-16-2026 08:00";

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

    function button(css, text, title, onclick) {
        const result = el("button", "btn btn-xs " + css, text);
        result.type = "button";
        if (title) {
            result.title = title;
        }
        if (onclick) {
            result.addEventListener("click", onclick);
        }
        return result;
    }

    function icon_button(css, icon, title, onclick) {
        const result = button(css, null, title, onclick);
        result.appendChild(el("span", "bi " + icon));
        return result;
    }

    // a filter list in a form two lists can be compared in, whatever order their entries are in
    function canonical(filters) {
        return JSON.stringify((filters || [])
            .map(function(entry) { return [entry.name, !!entry.inverted, (entry.values || []).map(String)]; })
            .sort());
    }

    function create(options) {
        const root = options.root;
        const screen = options.screen;
        const columns = options.columns;

        const state = {
            descriptor: null,        // the screen's filters, by name
            filters: [],             // what is shown: [{name, inverted, values}]
            f: [],                   // the same, encoded
            sort: options.defaultSort,
            desc: options.defaultDesc,
            limit: options.defaultLimit,
            saved: null,             // the uuid of the open saved filter
            saved_filters: [],       // the user's saved filters on this screen
            cursors: [null],         // cursors[i] fetches page i
            page: 0,
            generation: 0,           // drops responses to requests a newer one replaced
        };

        //
        // layout
        //

        const error = el("div", "alert alert-danger d-none");
        error.setAttribute("role", "alert");
        const warning = el("div", "alert alert-warning d-none");
        warning.setAttribute("role", "alert");
        const bar = el("div", "filter-list-bar mb-2");
        const table = el("table", "table table-sm table-hover filter-list-table");
        const thead = table.createTHead();
        const tbody = table.createTBody();
        const pager = el("div", "d-flex flex-wrap align-items-center gap-2");
        root.append(error, warning, bar, table, pager);

        function show_error(message) {
            error.textContent = message || "";
            error.classList.toggle("d-none", !message);
        }

        function show_warning(message) {
            warning.textContent = message || "";
            warning.classList.toggle("d-none", !message);
        }

        //
        // the URL
        //

        function read_url() {
            const params = new URLSearchParams(window.location.search);
            state.f = params.getAll("f");
            state.sort = params.get("sort") || options.defaultSort;
            state.desc = params.has("desc") ? params.get("desc") === "true" : options.defaultDesc;
            const limit = parseInt(params.get("limit"), 10);
            state.limit = options.pageSizes.indexOf(limit) >= 0 ? limit : options.defaultLimit;
            state.saved = params.get("saved");
        }

        function page_url(params) {
            const text = aceApi.query(params);
            return window.location.pathname + text;
        }

        function url_state() {
            const params = {f: state.f};
            if (state.sort !== options.defaultSort) {
                params.sort = state.sort;
            }
            if (state.desc !== options.defaultDesc) {
                params.desc = state.desc ? "true" : "false";
            }
            if (state.limit !== options.defaultLimit) {
                params.limit = state.limit;
            }
            if (state.saved) {
                params.saved = state.saved;
            }
            return page_url(params);
        }

        function write_url(replace) {
            const url = url_state();
            if (url === window.location.pathname + window.location.search) {
                return;
            }
            if (replace) {
                window.history.replaceState(null, "", url);
            } else {
                window.history.pushState(null, "", url);
            }
        }

        // a link that opens this page with these filters and nothing else
        function share_url(f) {
            return window.location.origin + page_url({f: f});
        }

        //
        // filters
        //

        function encode(filters) {
            if (filters.length === 0) {
                return Promise.resolve([]);
            }
            return aceApi.post("/filter-screens/" + encodeURIComponent(screen) + "/encode", {filters: filters})
                .then(function(result) { return result.f; });
        }

        // what the URL's f= values name; a filter that no longer exists is skipped and reported, and
        // the URL is rewritten without it, so the list API never sees it
        function decode_url_filters() {
            if (state.f.length === 0) {
                state.filters = [];
                show_warning("");
                return Promise.resolve();
            }
            return aceApi.get("/filter-screens/" + encodeURIComponent(screen) + "/decode" + aceApi.query({f: state.f}))
                .then(function(decoded) {
                    state.filters = decoded.filters;
                    if (decoded.warnings.length === 0) {
                        show_warning("");
                        return;
                    }
                    // each warning is the API's own sentence about one skipped filter
                    show_warning(decoded.warnings.join(" "));
                    return encode(state.filters).then(function(f) {
                        state.f = f;
                        write_url(true);
                    });
                });
        }

        // show a new filter list: the URL, the bar and the first page
        function set_filters(filters, saved_uuid) {
            return encode(filters).then(function(f) {
                state.filters = filters;
                state.f = f;
                state.saved = saved_uuid || null;
                show_warning("");
                write_url(false);
                render_bar();
                return load_first_page();
            });
        }

        function remove_value(index, value_index) {
            const filters = JSON.parse(JSON.stringify(state.filters));
            filters[index].values.splice(value_index, 1);
            if (filters[index].values.length === 0) {
                filters.splice(index, 1);
            }
            set_filters(filters, state.saved).catch(report);
        }

        function remove_entry(index) {
            const filters = state.filters.filter(function(_, i) { return i !== index; });
            set_filters(filters, state.saved).catch(report);
        }

        function report(err) {
            show_error(err.message);
        }

        //
        // saved filters (saved_filters.js)
        //

        function open_saved() {
            return state.saved_filters.find(function(saved) { return saved.uuid === state.saved; }) || null;
        }

        function dirty() {
            const saved = open_saved();
            return saved !== null && canonical(saved.filters) !== canonical(state.filters);
        }

        function load_saved_filters() {
            return aceApi.get("/saved-filters/" + aceApi.query({screen: screen}))
                .then(function(page) {
                    state.saved_filters = page.data;
                    render_bar();
                })
                .catch(report);
        }

        function hide_modal(id) {
            const modal = document.getElementById(id);
            if (modal) {
                bootstrap.Modal.getOrCreateInstance(modal).hide();
            }
        }

        const saved_filters = SavedFilters.create({
            screen: screen,
            onOpen: function(saved) {
                hide_modal("manage_filters_modal");
                set_filters(saved.filters, saved.uuid).catch(report);
            },
            onSaved: function(saved) {
                hide_modal("save_filter_modal");
                state.saved = saved.uuid;
                write_url(true);
                load_saved_filters();
            },
            onDeleted: function(filter_uuid) {
                if (state.saved === filter_uuid) {
                    state.saved = null;
                    write_url(true);
                }
                load_saved_filters();
            },
            onQuickFiltersSaved: function() {
                hide_modal("manage_filters_modal");
                load_saved_filters();
            },
            shareUrl: share_url,
        });
        // the saved_filter_modals macro's markup calls SAVED_FILTERS
        window.SAVED_FILTERS = saved_filters;

        //
        // the filter bar
        //

        function render_bar() {
            const controls = el("div", "d-flex flex-wrap align-items-center gap-1 mb-1");

            controls.appendChild(el("span", "me-1", "Filters"));
            controls.appendChild(button("btn-outline-dark", "Edit", "Add, change or remove filters", open_editor));

            const save_as = button("btn-outline-dark", "Save as…", "Save these filters under a name", function() {
                saved_filters.prepareSave(state.filters);
            });
            save_as.setAttribute("data-bs-toggle", "modal");
            save_as.setAttribute("data-bs-target", "#save_filter_modal");
            save_as.disabled = state.filters.length === 0;
            controls.appendChild(save_as);

            const saved = open_saved();
            const save = button("btn-outline-dark", "Save", saved ? "Overwrite \"" + saved.name + "\" with these filters" : null, function() {
                saved_filters.saveCurrent(state.saved, state.filters);
            });
            save.disabled = !dirty() || state.filters.length === 0;
            controls.appendChild(save);

            const manage = button("btn-outline-dark", "Manage…", "Rename, delete and order your saved filters", function() {
                saved_filters.openManage();
            });
            manage.setAttribute("data-bs-toggle", "modal");
            manage.setAttribute("data-bs-target", "#manage_filters_modal");
            controls.appendChild(manage);

            controls.appendChild(button("btn-outline-dark", "Reset", "Remove every filter", function() {
                set_filters([], null).catch(report);
            }));
            controls.appendChild(icon_button("btn-outline-dark", "bi-copy", "Copy a link to these filters", function() {
                copy_to_clipboard(share_url(state.f));
            }));

            if (saved) {
                const name = el("span", "ms-2 fw-semibold", saved.name);
                if (dirty()) {
                    const star = el("span", null, " *");
                    star.title = "unsaved changes";
                    name.appendChild(star);
                }
                controls.appendChild(name);
            }

            const quick = state.saved_filters.filter(function(item) {
                return item.quick_filter_order !== null && item.quick_filter_order !== undefined;
            });
            if (quick.length) {
                controls.appendChild(el("span", "text-muted mx-1", "|"));
                quick.forEach(function(item) {
                    const css = item.uuid === state.saved ? "btn-outline-primary active" : "btn-outline-primary";
                    controls.appendChild(button(css, item.name, item.description, function() {
                        set_filters(item.filters, item.uuid).catch(report);
                    }));
                });
            }

            const chips = el("div", "small");
            state.filters.forEach(function(entry, index) {
                if (!entry.values || entry.values.length === 0) {
                    return;
                }
                const chip = el("span", "me-3 text-nowrap");
                if (entry.inverted) {
                    chip.appendChild(el("span", "fw-semibold", "NOT "));
                }
                const name = el("span", "filter-list-chip", entry.name);
                name.title = "remove this filter";
                name.addEventListener("click", function() { remove_entry(index); });
                chip.appendChild(name);
                chip.appendChild(document.createTextNode(": "));
                entry.values.forEach(function(value, value_index) {
                    if (value_index) {
                        chip.appendChild(document.createTextNode(" | "));
                    }
                    const item = el("span", "filter-list-chip", value);
                    item.title = "remove this value";
                    item.addEventListener("click", function() { remove_value(index, value_index); });
                    chip.appendChild(item);
                });
                chips.appendChild(chip);
            });

            bar.replaceChildren(controls, chips);
        }

        //
        // the editor
        //

        const editor = (function() {
            const modal = el("div", "modal fade");
            modal.tabIndex = -1;
            modal.setAttribute("aria-hidden", "true");
            modal.innerHTML =
                '<div class="modal-dialog modal-lg"><div class="modal-content">' +
                '<div class="modal-header"><h1 class="modal-title fs-5">Edit Filters</h1>' +
                '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
                '<div class="modal-body">' +
                '<div class="alert alert-danger d-none filter-list-editor-error" role="alert"></div>' +
                '<div class="filter-list-editor-rows"></div>' +
                '<button type="button" class="btn btn-xs btn-outline-dark filter-list-editor-add">' +
                '<span class="bi bi-plus-lg"></span> Add a filter</button>' +
                '<div class="text-muted small mt-2">Rows naming the same filter are ORed; different filters are ANDed. ' +
                'NOT excludes what a row matches.</div>' +
                '</div>' +
                '<div class="modal-footer">' +
                '<button type="button" class="btn btn-outline-dark" data-bs-dismiss="modal">Cancel</button>' +
                '<button type="button" class="btn btn-outline-primary filter-list-editor-apply">Apply</button>' +
                '</div></div></div>';
            document.body.appendChild(modal);
            return {
                modal: modal,
                rows: modal.querySelector(".filter-list-editor-rows"),
                error: modal.querySelector(".filter-list-editor-error"),
            };
        })();

        function editor_error(message) {
            editor.error.textContent = message || "";
            editor.error.classList.toggle("d-none", !message);
        }

        function value_control(field, values) {
            const container = el("div", "flex-grow-1 filter-list-editor-value");
            if (field.kind === "multi") {
                field.options.forEach(function(option) {
                    const wrapper = el("div", "form-check form-check-inline");
                    const box = el("input", "form-check-input");
                    box.type = "checkbox";
                    box.value = option;
                    box.checked = values.indexOf(option) >= 0;
                    box.id = "flp_" + Math.random().toString(36).slice(2);
                    const label = el("label", "form-check-label", option);
                    label.htmlFor = box.id;
                    wrapper.append(box, label);
                    container.appendChild(wrapper);
                });
            } else if (field.kind === "bool") {
                const select = el("select", "form-select form-select-sm");
                field.options.forEach(function(option) {
                    const item = el("option", null, option);
                    item.value = option;
                    select.appendChild(item);
                });
                if (values.length) {
                    select.value = values[0];
                }
                container.appendChild(select);
            } else {
                const input = el("input", "form-control form-control-sm");
                input.type = "text";
                input.value = values.length ? values[0] : "";
                if (field.kind === "date_range") {
                    input.placeholder = DATE_RANGE_HINT;
                    input.title = "a relative time (-7d, @d) or a range '<start> - <end>' of relative times or MM-DD-YYYY HH:MM";
                }
                container.appendChild(input);
            }
            return container;
        }

        function row_values(row, field) {
            const container = row.querySelector(".filter-list-editor-value");
            if (field.kind === "multi") {
                return Array.from(container.querySelectorAll("input:checked")).map(function(box) { return box.value; });
            }
            const control = container.querySelector("input, select");
            const value = control.value.trim();
            return value ? [value] : [];
        }

        function add_row(name, inverted, values) {
            const fields = state.descriptor;
            const names = Object.keys(fields);
            const row = el("div", "d-flex align-items-center gap-2 mb-2 filter-list-editor-row");

            const select = el("select", "form-select form-select-sm w-auto");
            names.forEach(function(item) {
                const option = el("option", null, item);
                option.value = item;
                select.appendChild(option);
            });
            select.value = name || names[0];

            const not_wrapper = el("div", "form-check mb-0");
            const not = el("input", "form-check-input");
            not.type = "checkbox";
            not.checked = !!inverted;
            not.id = "flp_" + Math.random().toString(36).slice(2);
            const not_label = el("label", "form-check-label", "NOT");
            not_label.htmlFor = not.id;
            not_wrapper.append(not, not_label);

            let control = value_control(fields[select.value], values || []);
            select.addEventListener("change", function() {
                const next = value_control(fields[select.value], []);
                control.replaceWith(next);
                control = next;
            });

            const remove = icon_button("btn-outline-danger", "bi-trash3", "Remove this row", function() { row.remove(); });
            row.append(select, not_wrapper, control, remove);
            editor.rows.appendChild(row);
        }

        function open_editor() {
            editor_error("");
            editor.rows.replaceChildren();
            state.filters.forEach(function(entry) {
                const field = state.descriptor[entry.name];
                if (!field) {
                    return;
                }
                if (field.kind === "multi") {
                    add_row(entry.name, entry.inverted, entry.values);
                } else {
                    entry.values.forEach(function(value) { add_row(entry.name, entry.inverted, [value]); });
                }
            });
            if (state.filters.length === 0) {
                add_row(null, false, []);
            }
            bootstrap.Modal.getOrCreateInstance(editor.modal).show();
        }

        // the editor's rows as a filter list: rows naming the same filter with the same NOT are one
        // entry, so a value never needs a delimiter
        function editor_filters() {
            const filters = [];
            const by_key = {};
            editor.rows.querySelectorAll(".filter-list-editor-row").forEach(function(row) {
                const name = row.querySelector("select").value;
                const inverted = row.querySelector(".form-check-input").checked;
                const values = row_values(row, state.descriptor[name]);
                if (values.length === 0) {
                    return;
                }
                const key = JSON.stringify([name, inverted]);
                if (!by_key[key]) {
                    by_key[key] = {name: name, inverted: inverted, values: []};
                    filters.push(by_key[key]);
                }
                values.forEach(function(value) {
                    if (by_key[key].values.indexOf(value) < 0) {
                        by_key[key].values.push(value);
                    }
                });
            });
            return filters;
        }

        editor.modal.querySelector(".filter-list-editor-add").addEventListener("click", function() {
            add_row(null, false, []);
        });
        editor.modal.querySelector(".filter-list-editor-apply").addEventListener("click", function() {
            editor_error("");
            const filters = editor_filters();
            // encode first: it validates, and a filter the screen refuses stays in the dialog
            encode(filters)
                .then(function() {
                    bootstrap.Modal.getOrCreateInstance(editor.modal).hide();
                    return set_filters(filters, state.saved);
                })
                .catch(function(err) { editor_error(err.message); });
        });

        //
        // the list
        //

        function list_params(extra) {
            const params = {f: state.f, sort: state.sort, desc: state.desc ? "true" : "false", tz: options.tz};
            Object.keys(extra || {}).forEach(function(key) { params[key] = extra[key]; });
            return params;
        }

        function render_head() {
            const row = el("tr");
            columns.forEach(function(column) {
                const th = el("th", column.css || null);
                if (column.width) {
                    th.style.width = column.width;
                }
                if (column.title) {
                    th.title = column.title;
                }
                if (!column.sort) {
                    th.textContent = column.label;
                    row.appendChild(th);
                    return;
                }
                const link = el("a", "text-reset text-decoration-none filter-list-sort", column.label);
                link.href = "#";
                link.addEventListener("click", function(event) {
                    event.preventDefault();
                    if (state.sort === column.sort) {
                        state.desc = !state.desc;
                    } else {
                        state.sort = column.sort;
                        state.desc = column.sortDesc !== undefined ? column.sortDesc : true;
                    }
                    write_url(false);
                    render_head();
                    load_first_page();
                });
                th.appendChild(link);
                if (state.sort === column.sort) {
                    th.appendChild(el("span", "bi ms-1 " + (state.desc ? "bi-caret-down-fill" : "bi-caret-up-fill")));
                }
                row.appendChild(th);
            });
            thead.replaceChildren(row);
        }

        function message_row(text, css) {
            const row = el("tr");
            const cell = el("td", css || "text-muted", text);
            cell.colSpan = columns.length;
            row.appendChild(cell);
            tbody.replaceChildren(row);
        }

        function render_rows(rows) {
            if (rows.length === 0) {
                message_row(options.emptyText || "Nothing matches these filters.");
                return;
            }
            tbody.replaceChildren();
            rows.forEach(function(data) {
                const row = el("tr");
                columns.forEach(function(column) {
                    const cell = el("td", column.css || null);
                    const content = column.render(data);
                    if (content instanceof Node) {
                        cell.appendChild(content);
                    } else if (content !== null && content !== undefined) {
                        cell.textContent = String(content);
                    }
                    row.appendChild(cell);
                });
                tbody.appendChild(row);
            });
        }

        function load_page() {
            const generation = ++state.generation;
            show_error("");
            message_row("Loading…");
            const params = list_params({limit: state.limit, cursor: state.cursors[state.page] || undefined});
            return aceApi.get(options.api + "/" + aceApi.query(params))
                .then(function(page) {
                    if (generation !== state.generation) {
                        return;
                    }
                    state.cursors = state.cursors.slice(0, state.page + 1);
                    if (page.next_cursor) {
                        state.cursors.push(page.next_cursor);
                    }
                    render_rows(page.data);
                    render_pager(page.data.length);
                })
                .catch(function(err) {
                    if (generation !== state.generation) {
                        return;
                    }
                    message_row("");
                    render_pager(0);
                    show_error("Unable to load the list: " + err.message);
                });
        }

        function load_first_page() {
            state.cursors = [null];
            state.page = 0;
            return load_page();
        }

        //
        // the pager and the export menu
        //

        function render_pager(count) {
            const previous = button("btn-outline-secondary", "« Previous", null, function() {
                state.page -= 1;
                load_page();
            });
            previous.disabled = state.page === 0;
            const next = button("btn-outline-secondary", "Next »", null, function() {
                state.page += 1;
                load_page();
            });
            next.disabled = state.cursors.length <= state.page + 1;

            const first = state.page * state.limit + (count ? 1 : 0);
            const info = el("span", "text-muted small", count ? first + "–" + (first + count - 1) : "");

            const size = el("select", "form-select form-select-sm w-auto");
            size.title = "rows per page";
            options.pageSizes.forEach(function(value) {
                const option = el("option", null, value + " per page");
                option.value = value;
                size.appendChild(option);
            });
            size.value = String(state.limit);
            size.addEventListener("change", function() {
                state.limit = parseInt(size.value, 10);
                write_url(false);
                load_first_page();
            });

            pager.replaceChildren(previous, next, info, size, export_menu());
        }

        function export_menu() {
            const wrapper = el("div", "dropdown ms-auto");
            const toggle = button("btn-outline-dark dropdown-toggle", "Export");
            toggle.setAttribute("data-bs-toggle", "dropdown");
            toggle.setAttribute("aria-expanded", "false");
            const menu = el("ul", "dropdown-menu dropdown-menu-end");

            function item(text, href, title) {
                const li = el("li");
                const link = el("a", "dropdown-item", text);
                link.href = href;
                if (title) {
                    link.title = title;
                }
                li.appendChild(link);
                menu.appendChild(li);
                return link;
            }

            (options.exports || []).forEach(function(format) {
                item(format.toUpperCase(), aceApi.BASE + options.api + "/export/" + format + aceApi.query(list_params()),
                     "every row these filters match, in this order");
            });

            const copy = item("Copy API URL", "#", "the list API with these filters, for a script with an API key");
            copy.addEventListener("click", function(event) {
                event.preventDefault();
                copy_to_clipboard(window.location.origin + aceApi.BASE + options.api + "/" + aceApi.query(list_params()));
            });

            if (options.download) {
                menu.appendChild(el("li")).appendChild(el("hr", "dropdown-divider"));
                const params = {f: state.f, tz: options.tz};
                item("Download files", aceApi.BASE + options.api + options.download.path + aceApi.query(params),
                     options.download.hint);
            }

            wrapper.append(toggle, menu);
            return wrapper;
        }

        //
        // start
        //

        function render_from_url() {
            read_url();
            render_head();
            return decode_url_filters()
                .then(function() {
                    render_bar();
                    return load_first_page();
                })
                .catch(report);
        }

        window.addEventListener("popstate", render_from_url);

        aceApi.get("/filter-screens/" + encodeURIComponent(screen))
            .then(function(descriptor) {
                state.descriptor = {};
                descriptor.filters.forEach(function(field) {
                    if (field.kind) {
                        state.descriptor[field.name] = field;
                    }
                });
                load_saved_filters();
                return render_from_url();
            })
            .catch(report);

        return {
            reload: load_first_page,
            setFilters: function(filters) { return set_filters(filters, null); },
            shareUrl: share_url,
        };
    }

    return {create: create};
})();
