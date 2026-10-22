// The API Keys card on the preferences page: the user's own keys, through /api/v2/users/me/apikeys
// (same origin, authenticated by the Flask session cookie). Anyone may list their keys; the
// create, edit and revoke controls exist only for a user holding user:self, and the server accepts
// only a scope within what the user holds -- so the picker offers just those permissions.
$(document).ready(function() {
    var card = document.getElementById("api_keys_card");
    if (!card) { return; }

    var api_url = card.dataset.apiUrl;
    var can_manage = card.dataset.canManage === "true";
    var list = $("#my_api_keys_list");
    var CUSTOM = "__custom__";

    var catalog = (function() {
        var el = document.getElementById("my_api_key_catalog_json");
        if (!el) { return []; }
        try { return JSON.parse(el.textContent); } catch (e) { return []; }
    })();

    function request(method, url, body) {
        var options = { method: method, credentials: "same-origin", headers: { "Content-Type": "application/json" } };
        if (body !== undefined) { options.body = JSON.stringify(body); }
        return fetch(url, options).then(function(response) {
            if (!response.ok) {
                return response.text().then(function(text) {
                    // FastAPI answers {"detail": ...}; show the reason, not the JSON
                    var message = text || response.statusText;
                    try {
                        var detail = JSON.parse(text).detail;
                        if (typeof detail === "string") { message = detail; }
                        else if (Array.isArray(detail)) { message = detail.map(function(d) { return d.msg; }).join("; "); }
                    } catch (e) { /* not JSON: the raw text is the message */ }
                    throw new Error(message);
                });
            }
            return response;
        });
    }

    function scope_text(key) {
        if (key.inherit_user_scope) { return "Full account access (set by an administrator)"; }
        return key.scope.map(function(s) { return s.major + ":" + s.minor; }).join(", ");
    }

    function render(keys) {
        list.empty();
        if (!keys.length) {
            list.append($("<tr></tr>").append($("<td colspan='4' class='text-muted'></td>").text("You have no API keys.")));
            return;
        }
        keys.forEach(function(key) {
            var row = $("<tr></tr>");
            row.append($("<td></td>").text(key.name));
            row.append($("<td></td>").text(scope_text(key)));
            row.append($("<td class='text-nowrap'></td>").text(key.created_at ? key.created_at.substring(0, 10) : ""));
            var actions = $("<td class='text-nowrap text-end'></td>");
            if (can_manage) {
                if (!key.inherit_user_scope) {
                    $("<button type='button' class='btn btn-sm btn-outline-secondary me-1'>Edit</button>")
                        .on("click", function() { open_editor(key); })
                        .appendTo(actions);
                }
                $("<button type='button' class='btn btn-sm btn-outline-danger'>Revoke</button>")
                    .on("click", function() { revoke(key); })
                    .appendTo(actions);
            }
            row.append(actions);
            list.append(row);
        });
    }

    function load() {
        request("GET", api_url)
            .then(function(response) { return response.json(); })
            .then(render)
            .catch(function(error) {
                list.empty().append($("<tr></tr>").append(
                    $("<td colspan='4' class='text-danger'></td>").text("Could not load your API keys: " + error.message)));
            });
    }

    function revoke(key) {
        if (!confirm("Revoke key '" + key.name + "'? Anything using it stops working. This cannot be undone.")) { return; }
        request("DELETE", api_url + "/" + key.id)
            .then(load)
            .catch(function(error) { alert("Not revoked: " + error.message); });
    }

    load();

    if (!can_manage) { return; }

    // ---- the editor: one modal for a new key and for changing an existing one ----

    var editing_key_id = null;
    var scope_list = $("#my_api_key_scope_list");
    var error_box = document.getElementById("my_api_key_error");

    function show_error(message) {
        error_box.textContent = message || "";
        error_box.classList.toggle("d-none", !message);
    }

    function add_scope_row(value) {
        var select = $("<select class='form-select form-select-sm w-auto'></select>");
        $("<option></option>").val("").text("— choose permission —").appendTo(select);
        var known = [];
        catalog.forEach(function(entry) {
            var key = entry.major + ":" + entry.minor;
            known.push(key);
            $("<option></option>").val(key).text(key).attr("title", entry.description || "").appendTo(select);
        });
        // a pattern already on the key that is not a held catalog entry (signature:*, or one an
        // administrator set) keeps its own option so it round-trips; the server decides if it stays
        if (value && known.indexOf(value) === -1) {
            $("<option></option>").val(value).text(value).appendTo(select);
        }
        $("<option></option>").val(CUSTOM).text("custom…").appendTo(select);
        select.val(value || "");

        // toggled with d-none: Bootstrap's display utilities are !important and defeat .hide()
        var custom = $("<input type='text' class='form-control form-control-sm w-auto d-none' placeholder='major:minor'>");
        select.on("change", function() {
            custom.toggleClass("d-none", select.val() !== CUSTOM);
            if (select.val() === CUSTOM) { custom.trigger("focus"); } else { custom.val(""); }
        });

        var remove = $("<button type='button' class='btn btn-sm btn-outline-danger'>Remove</button>")
            .on("click", function() { row.remove(); });
        var row = $("<li class='d-flex align-items-center gap-2 mb-2'></li>").append(select, custom, remove);
        scope_list.append(row);
    }

    function collect_scope() {
        var scope = [];
        scope_list.children().each(function() {
            var select = $(this).find("select");
            var value = select.val() === CUSTOM ? $(this).find("input").val().trim() : select.val();
            if (!value || value.indexOf(":") === -1) { return; } // an incomplete row is skipped
            var parts = value.split(":");
            scope.push({ major: parts[0], minor: parts.slice(1).join(":") });
        });
        return scope;
    }

    function open_editor(key) {
        editing_key_id = key ? key.id : null;
        $("#my_api_key_modal_label").text(key ? "Edit API key" : "New API key");
        $("#btn_save_my_api_key").text(key ? "Save" : "Create");
        $("#my_api_key_name").val(key ? key.name : "");
        scope_list.empty();
        (key ? key.scope : []).forEach(function(s) { add_scope_row(s.major + ":" + s.minor); });
        if (!scope_list.children().length) { add_scope_row(""); }
        show_error("");
        $("#my_api_key_modal").modal("show");
    }

    $("#btn_new_my_api_key").on("click", function() { open_editor(null); });
    $("#btn_my_api_key_add_scope").on("click", function() { add_scope_row(""); });

    $("#my_api_key_form").on("submit", function(event) {
        event.preventDefault();
        var body = { name: $("#my_api_key_name").val().trim(), scope: collect_scope() };
        if (!body.scope.length) {
            show_error("Add at least one permission.");
            return;
        }
        show_error("");
        var creating = editing_key_id === null;
        var call = creating
            ? request("POST", api_url, body).then(function(response) { return response.json(); })
            : request("PUT", api_url + "/" + editing_key_id, body);
        call.then(function(created) {
            $("#my_api_key_modal").modal("hide");
            if (creating) {
                $("#my_api_key_value").val(created.api_key);
                $("#my_api_key_reveal_modal").modal("show");
            } else {
                load();
            }
        }).catch(function(error) { show_error(error.message); });
    });

    $("#btn_copy_my_api_key").on("click", function() {
        var button = $(this);
        Promise.resolve(copy_to_clipboard($("#my_api_key_value").val())).then(function() {
            button.text("Copied!");
            setTimeout(function() { button.text("Copy"); }, 1500);
        }).catch(function() {
            // never leave the user believing a key was copied when it wasn't
            alert("Unable to copy to the clipboard. Select the key and copy it manually.");
        });
    });

    // the key is shown only while this modal is open: drop it from the page once it closes
    $("#my_api_key_reveal_modal").on("hidden.bs.modal", function() {
        $("#my_api_key_value").val("");
        load();
    });
});
