// The alert-list column chooser (analysis/_manage_column_chooser.html): drag rows to reorder,
// tick to show or hide. The list's DOM order and checkbox states ARE the preference; every
// change is read back from the DOM and saved through the v2 API (same origin, authenticated by
// the Flask session cookie), then `on_saved` runs so the page can re-render from it.
//
// Used by the manage alerts page (where on_saved refreshes the list) and by the preferences
// page (where nothing needs re-rendering). Keep it outside any Datastar morph region: the
// jQuery UI sortable binding would not survive a morph.
function init_column_chooser(list, on_saved) {
    if (!list) { return; }
    var url = list.dataset.preferenceUrl;
    var container = list.parentElement;
    var status = container.querySelector(".column-chooser-status");
    var reset = container.querySelector(".column-chooser-reset");

    function set_status(text, is_error) {
        if (!status) { return; }
        status.textContent = text;
        status.classList.toggle("text-danger", !!is_error);
        status.classList.toggle("text-muted", !is_error);
    }

    function read() {
        var order = [];
        var hidden = [];
        list.querySelectorAll("li[data-column-id]").forEach(function(item) {
            var id = item.dataset.columnId;
            order.push(id);
            var checkbox = item.querySelector("input[type=checkbox]");
            if (checkbox && !checkbox.checked) { hidden.push(id); }
        });
        return { order: order, hidden: hidden };
    }

    // re-arrange the existing rows to match a value the server returned (a reset, or the
    // normalized form of what was just saved)
    function render(value) {
        var items = {};
        list.querySelectorAll("li[data-column-id]").forEach(function(item) { items[item.dataset.columnId] = item; });
        value.order.forEach(function(id) {
            if (items[id]) { list.appendChild(items[id]); }
        });
        Object.keys(items).forEach(function(id) {
            var checkbox = items[id].querySelector("input[type=checkbox]");
            if (checkbox) { checkbox.checked = value.hidden.indexOf(id) === -1; }
        });
    }

    function request(method, body) {
        var options = { method: method, credentials: "same-origin", headers: { "Content-Type": "application/json" } };
        if (body !== undefined) { options.body = JSON.stringify(body); }
        set_status("Saving…");
        return fetch(url, options).then(function(response) {
            if (!response.ok) {
                return response.text().then(function(text) { throw new Error(text || response.statusText); });
            }
            return response.json();
        }).then(function(saved) {
            render(saved.value);
            set_status(saved.is_default ? "Default" : "Saved");
            if (on_saved) { on_saved(saved); }
            return saved;
        }).catch(function(error) {
            set_status("Not saved: " + error.message, true);
        });
    }

    function save() { return request("PUT", read()); }

    list.addEventListener("change", function(event) {
        if (event.target.matches("input[type=checkbox]")) { save(); }
    });

    $(list).sortable({
        handle: ".column-chooser-handle",
        axis: "y",
        containment: "parent",
        stop: function() { save(); },
    });

    if (reset) {
        reset.addEventListener("click", function() { request("DELETE"); });
    }
}
