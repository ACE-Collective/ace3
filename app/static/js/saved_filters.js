// Saved filters for any list screen (saq/gui/filter_screens.py), through /api/v2/saved-filters.
//
// A page renders the modals with the saved_filter_modals macro
// (app/templates/saved_filters/_modals.html), loads ace_api.js and this file, and creates one
// instance named SAVED_FILTERS, which the macro's markup calls:
//
//     var SAVED_FILTERS = SavedFilters.create({
//         screen: "alerts",                // the saved_filters.screen the filters belong to
//         quickFilterNoun: "badge",        // what the page calls a quick filter (default "quick filter")
//         supportsIndicator: true,         // offer "show a count on the quick filter"
//         manageTipHtml: "...",            // optional trusted static text under the manage table
//         onOpen: function(saved) {},      // the analyst opened a saved filter
//         onSaved: function(saved, how) {},// a filter was saved; how.created tells Save as from Save
//         onDeleted: function(uuid) {},    // a filter was deleted (the manage table is redrawn first)
//         onQuickFiltersSaved: function() {},
//         shareUrl: function(f) {},        // the absolute page URL for share-link params f
//     });
//
// What the page shows is the page's business: this component never reads the page's filter
// editor. A save takes the filter list the page hands it, prepareSave(filters) for Save as and
// saveCurrent(uuid, filters) for Save, so what is saved is exactly what the page passed in.

var SavedFilters = (function() {
    "use strict";

    const PATH = "/saved-filters";

    function create(options) {
        const screen = options.screen;
        const noun = options.quickFilterNoun || "quick filter";
        const noop = function() {};
        const on_open = options.onOpen || noop;
        const on_saved = options.onSaved || noop;
        const on_deleted = options.onDeleted || noop;
        const on_quick_filters_saved = options.onQuickFiltersSaved || noop;

        // the filter list the pending Save as will persist (see prepareSave)
        let pending_filters = null;

        function screen_query() {
            return aceApi.query({screen: screen});
        }

        function report(err) {
            alert(err.message);
        }

        function element(id) {
            return document.getElementById(id);
        }

        //
        // Save as
        //

        // Called by every trigger that opens #save_filter_modal, on the trigger's own click: the
        // filters to save are taken then, so nothing the page does while the dialog is open
        // changes what is saved.
        function prepareSave(filters) {
            pending_filters = filters;
        }

        function saveAs() {
            if (!pending_filters || pending_filters.length === 0) {
                // an empty filter is a mistake, not a request to save "match everything"
                alert("A saved filter needs at least one filter row.");
                return false;
            }

            const body = {
                name: element("save_filter_name").value,
                description: element("save_filter_description").value || null,
                filters: pending_filters,
                quick_filter: element("save_filter_quick").checked,
            };
            const indicator = element("save_filter_indicator");
            if (indicator) {
                body.quick_filter_indicator = indicator.checked;
            }

            aceApi.post(PATH + "/" + screen_query(), body)
                .then(function(saved) { on_saved(saved, {created: true}); })
                .catch(report);

            return false; // the form is never submitted
        }

        //
        // Save
        //

        // Overwrites a named filter with the given filter list.
        function saveCurrent(filter_uuid, filters) {
            return aceApi.patch(PATH + "/" + encodeURIComponent(filter_uuid), {filters: filters})
                .then(function(saved) { on_saved(saved, {created: false}); })
                .catch(report);
        }

        //
        // Manage
        //

        function button(css, title, icon, text, onclick) {
            const result = document.createElement("button");
            result.type = "button";
            result.className = "btn btn-xs " + css;
            if (title) {
                result.title = title;
            }
            if (icon) {
                const span = document.createElement("span");
                span.className = "bi " + icon;
                result.appendChild(span);
            }
            if (text) {
                result.appendChild(document.createTextNode(text));
            }
            result.addEventListener("click", onclick);
            return result;
        }

        function cell(row, content, css) {
            const td = document.createElement("td");
            if (css) {
                td.className = css;
            }
            if (content instanceof Node) {
                td.appendChild(content);
            } else if (Array.isArray(content)) {
                content.forEach(function(node, index) {
                    if (index) {
                        td.appendChild(document.createTextNode(" "));
                    }
                    td.appendChild(node);
                });
            } else {
                td.textContent = content === null || content === undefined ? "" : String(content);
            }
            row.appendChild(td);
        }

        function capitalized(text) {
            return text.charAt(0).toUpperCase() + text.slice(1);
        }

        function render_manage(saved_filters) {
            const container = element("manage_filters_modal_body");
            container.replaceChildren();

            if (saved_filters.length === 0) {
                const empty = document.createElement("p");
                empty.className = "text-muted mb-0";
                empty.textContent = "You have no saved filters yet. Build a filter, then use Save as to keep it.";
                container.appendChild(empty);
                return;
            }

            const form = document.createElement("form");
            form.id = "quick_filter_order_form";
            form.addEventListener("submit", function(event) {
                event.preventDefault();
                saveQuickOrder();
            });

            const table = document.createElement("table");
            table.className = "table table-sm align-middle";
            table.id = "saved_filters_table";
            const head = table.createTHead().insertRow();
            [[capitalized(noun), "width:90px"], ["Order", "width:70px"], ["Name", ""], ["Description", ""], ["", "width:150px"]]
                .forEach(function(column) {
                    const th = document.createElement("th");
                    th.textContent = column[0];
                    if (column[1]) {
                        th.style.cssText = column[1];
                    }
                    head.appendChild(th);
                });

            const body = table.createTBody();
            saved_filters.forEach(function(saved) {
                const row = body.insertRow();
                row.dataset.filterUuid = saved.uuid;

                const pin = document.createElement("input");
                pin.type = "checkbox";
                pin.className = "form-check-input quick-filter-pin";
                pin.checked = saved.quick_filter_order !== null && saved.quick_filter_order !== undefined;
                pin.title = "Show this filter as a " + noun;
                cell(row, pin);

                cell(row, [
                    button("btn-outline-dark", "Move up", "bi-arrow-up", null, function() { move(this, -1); }),
                    button("btn-outline-dark", "Move down", "bi-arrow-down", null, function() { move(this, 1); }),
                ]);
                cell(row, saved.name);
                cell(row, saved.description, "text-muted small");
                cell(row, [
                    button("btn-outline-primary", null, null, "Open", function() { on_open(saved); }),
                    button("btn-outline-dark", "Copy a link to this filter", "bi-copy", null, function() { copyLink(saved.uuid); }),
                    button("btn-outline-danger", "Delete", "bi-trash3", null, function() { deleteFilter(saved.uuid, saved.name); }),
                ]);
            });
            form.appendChild(table);

            const hint = document.createElement("div");
            hint.className = "text-muted small mb-2";
            hint.textContent = "Checked filters appear as " + noun + "s on the filter bar, in the order shown here. ";
            if (options.manageTipHtml) {
                const tip = document.createElement("span");
                tip.innerHTML = options.manageTipHtml; // static text the page wrote, never data
                hint.appendChild(tip);
            }
            form.appendChild(hint);

            const submit = document.createElement("button");
            submit.type = "submit";
            submit.className = "btn btn-outline-primary btn-sm";
            submit.textContent = "Save " + noun + "s & order";
            form.appendChild(submit);

            container.appendChild(form);
        }

        function openManage() {
            element("manage_filters_modal_body").replaceChildren();
            return aceApi.get(PATH + "/" + screen_query())
                .then(function(page) { render_manage(page.data); })
                .catch(report);
        }

        function deleteFilter(filter_uuid, name) {
            if (!confirm('Delete the saved filter "' + name + '"?')) {
                return Promise.resolve();
            }

            return aceApi.del(PATH + "/" + encodeURIComponent(filter_uuid))
                .then(openManage)
                .then(function() { on_deleted(filter_uuid); })
                .catch(report);
        }

        // Reorder with up/down buttons rather than drag and drop: no library, and it is
        // reachable from the keyboard.
        function move(control, direction) {
            const row = control.closest("tr");
            const sibling = direction < 0 ? row.previousElementSibling : row.nextElementSibling;
            if (!sibling) {
                return;
            }
            if (direction < 0) {
                row.parentNode.insertBefore(row, sibling);
            } else {
                row.parentNode.insertBefore(sibling, row);
            }
        }

        function saveQuickOrder() {
            const filter_uuids = [];
            document.querySelectorAll("#saved_filters_table tbody tr").forEach(function(row) {
                if (row.querySelector(".quick-filter-pin").checked) {
                    filter_uuids.push(row.dataset.filterUuid);
                }
            });

            return aceApi.put(PATH + "/quick-filters" + screen_query(), {filter_uuids: filter_uuids})
                .then(function() { on_quick_filters_saved(); })
                .catch(report);
        }

        //
        // Share links
        //

        function encode(filters) {
            return aceApi.post("/filter-screens/" + encodeURIComponent(screen) + "/encode", {filters: filters})
                .then(function(result) { return result.f; });
        }

        // The link carries the filter itself, so it keeps working after the saved filter is
        // renamed, edited or deleted.
        function copyLink(filter_uuid) {
            return aceApi.get(PATH + "/" + encodeURIComponent(filter_uuid))
                .then(function(saved) { return encode(saved.filters); })
                .then(function(f) { return copy_to_clipboard(options.shareUrl(f)); })
                .catch(report);
        }

        // A fresh open is a fresh filter: Bootstrap only hides the dialog, so without this the
        // name from a save that failed would still be in the box next time it opens.
        const save_modal = element("save_filter_modal");
        if (save_modal) {
            save_modal.addEventListener("show.bs.modal", function() {
                element("save_filter_form").reset();
            });
        }

        return {
            screen: screen,
            prepareSave: prepareSave,
            saveAs: saveAs,
            saveCurrent: saveCurrent,
            openManage: openManage,
            deleteFilter: deleteFilter,
            move: move,
            saveQuickOrder: saveQuickOrder,
            copyLink: copyLink,
            encode: encode,
        };
    }

    return {create: create};
})();
