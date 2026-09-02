// User/role management calls the v2 API directly (same origin, authenticated by the Flask session
// cookie). Flask only renders this page.
var USERS_API = "/api/v2/users";

function api_request(method, url, body) {
    var options = {
        method: method,
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) {
        options.body = JSON.stringify(body);
    }
    return fetch(url, options).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) {
                throw new Error(text || response.statusText);
            });
        }
        return response;
    });
}

// the common case: mutate, then re-render the page from the server
function api_request_then_reload(method, url, body) {
    return api_request(method, url, body)
        .then(function() { window.location.reload(); })
        .catch(function(error) { alert(error.message); });
}

// The authoritative permission catalog, rendered into the page by the template.
var PERMISSION_CATALOG = (function() {
    var el = document.getElementById("permission_catalog_json");
    if (!el) { return []; }
    try { return JSON.parse(el.textContent); } catch (e) { return []; }
})();

var CUSTOM_PERMISSION = "__custom__";

// Wildcard grants are legitimate but are not catalog rows, so they get their own options.
var WILDCARD_PERMISSIONS = ["*:*"];

function permission_key(permission) {
    if (!permission.major && !permission.minor) { return ""; }
    return permission.major + ":" + permission.minor;
}

function build_permission_select(selected_key) {
    var select = $("<select class='form-select form-select-sm d-inline-block perm-select' style='width:auto; margin-left:8px;'></select>");
    var known = [];

    // a new row starts unselected rather than defaulting to a superuser grant
    $("<option></option>").val("").text("— choose permission —").appendTo(select);

    PERMISSION_CATALOG.forEach(function(entry) {
        var key = entry.major + ":" + entry.minor;
        known.push(key);
        $("<option></option>").val(key).text(key).attr("title", entry.description || "").appendTo(select);
    });
    WILDCARD_PERMISSIONS.forEach(function(key) {
        known.push(key);
        $("<option></option>").val(key).text(key).appendTo(select);
    });

    // an existing grant that is neither catalogued nor a listed wildcard (e.g. "observable:*")
    // still needs to round-trip, so surface it as its own option.
    if (selected_key && known.indexOf(selected_key) === -1) {
        $("<option></option>").val(selected_key).text(selected_key).appendTo(select);
        known.push(selected_key);
    }

    $("<option></option>").val(CUSTOM_PERMISSION).text("custom…").appendTo(select);

    if (selected_key && known.indexOf(selected_key) !== -1) {
        select.val(selected_key);
    }
    return select;
}

function collect_user_permissions() {
    // reads the permission rows in the add/edit user modal
    var permissions = [];
    $("#edit_user_permissions_list").children().each(function() {
        var row = $(this);
        var effect = row.find(".perm-effect").val();
        var selected = row.find(".perm-select").val();
        var value = (selected === CUSTOM_PERMISSION) ? row.find(".perm-custom").val().trim() : selected;

        if (!value || value.indexOf(":") === -1) {
            return; // skip incomplete rows
        }
        var parts = value.split(":");
        permissions.push({
            effect: effect,
            major: parts[0],
            minor: parts.slice(1).join(":"),
        });
    });
    return permissions;
}

function get_selected_user_ids() {
    // returns the list of user ids that are checked
    return $("input[name^='user_id_']:checked").map(function() {
        // Extract the integer ID from the name attribute, which is in the form "user_id_N"
        var match = this.name.match(/^user_id_(\d+)$/);
        return match ? parseInt(match[1], 10) : null; // Convert to integer or null if not found
    }).get().filter(function(id) { return id !== null; }); // Filter out null values
}

function get_selected_group_ids() {
    // returns the list of group ids that are checked
    return $("input[name^='group_id_']:checked").map(function() {
        var match = this.name.match(/^group_id_(\d+)$/);
        return match ? parseInt(match[1], 10) : null;
    }).get().filter(function(id) { return id !== null; });
}

function get_selected_user_permission_ids() {
    return $("input[name^='user_permission_']:checked").map(function() {
        var match = this.name.match(/^user_permission_(\d+)$/);
        return match ? parseInt(match[1], 10) : null;
    }).get().filter(function(id) { return id !== null; });
}

function get_selected_group_permission_ids() {
    return $("input[name^='group_permission_']:checked").map(function() {
        var match = this.name.match(/^group_permission_(\d+)$/);
        return match ? parseInt(match[1], 10) : null;
    }).get().filter(function(id) { return id !== null; });
}

function clear_edit_user_permissions() {
    $("#edit_user_permissions_list").children().remove();
}

function add_user_permission_elements(permission) {
    var li = $("<li class='mb-1 d-flex align-items-center'></li>").css("list-style-type", "none");
    var deleteButton = $("<button type='button' class='btn btn-xs btn-outline-danger ms-1'>delete</button>");
    deleteButton.attr("data-permission-id", permission.id);

    var effectSelect = $("<select class='form-select form-select-sm d-inline-block perm-effect' style='width:auto; margin-left:8px;'>" +
        "<option value='ALLOW'>ALLOW</option><option value='DENY'>DENY</option></select>");
    effectSelect.val((permission.effect || "ALLOW").toUpperCase());

    var key = permission_key(permission);
    var permSelect = build_permission_select(key);

    // Free-text fallback, shown only when "custom…" is selected. Note: no `d-inline-block` here --
    // that Bootstrap class is `display: inline-block !important` and would override the inline
    // `display: none` that .hide() sets, leaving the box permanently visible.
    var customInput = $("<input type='text' class='form-control form-control-sm perm-custom' " +
        "style='width:auto; margin-left:8px;' placeholder='major:minor'>").hide();

    permSelect.on("change", function() {
        if ($(this).val() === CUSTOM_PERMISSION) {
            customInput.show().trigger("focus");
        } else {
            // clear as well as hide, so a stale custom value can never reappear (or be
            // mistaken for what will be submitted) after switching to a catalog entry
            customInput.val("").hide();
        }
    });

    li.append(deleteButton).append(effectSelect).append(permSelect).append(customInput);
    $("#edit_user_permissions_list").append(li);

    deleteButton.on('click', function() {
        $(this).closest("li").remove();
    });
}

function submit_edit_user() {
    // submits the request to edit the selected users based on the form values

    // get the details of the selected users
    var selected_user_ids = get_selected_user_ids();

    // convert the form to a JSON object
    var json_submission = {};
    for (var i = 0; i < selected_user_ids.length; i++) {
        json_submission[selected_user_ids[i]] = {
            username: $("#edit_user_username").val(),
            password: $("#edit_user_password").val(),
            display_name: $("#edit_user_display_name").val(),
            email: $("#edit_user_email").val(),
            queue: $("#edit_user_queue").val(),
            timezone: $("#edit_user_timezone").val(),
            permissions: [],
            groups: [],
        };

        json_submission[selected_user_ids[i]].permissions = collect_user_permissions();

        // get the groups from the form
        var groups = [];
        $("input[name^='edit_user_group_']:checked").each(function() {
            var match = $(this).attr("name").match(/^edit_user_group_(\d+)$/);
            if (match) {
                groups.push(parseInt(match[1], 10));
            }
        });

        json_submission[selected_user_ids[i]].groups = groups;
    }

    api_request_then_reload("PATCH", USERS_API + "/", json_submission);
}

function submit_add_user() {
    // submits the request to add a new user based on the form values

    // username and email are required; the server enforces this too, but fail fast here
    if (!$("#edit_user_username").val().trim()) {
        alert("Username is required");
        return;
    }
    if (!$("#edit_user_email").val().trim()) {
        alert("Email is required");
        return;
    }

    // the API applies its own defaults, so send nothing rather than an empty string
    json_submission = {
        username: $("#edit_user_username").val().trim(),
        password: $("#edit_user_password").val() || null,
        display_name: $("#edit_user_display_name").val() || null,
        email: $("#edit_user_email").val().trim(),
        queue: $("#edit_user_queue").val() || "default",
        timezone: $("#edit_user_timezone").val() || "UTC",
        permissions: [],
        groups: [],
    };

    json_submission.permissions = collect_user_permissions();

    // get the groups from the form
    var groups = [];
    $("input[name^='edit_user_group_']:checked").each(function() {
        var match = $(this).attr("name").match(/^edit_user_group_(\d+)$/);
        if (match) {
            groups.push(parseInt(match[1], 10));
        }
    });

    json_submission.groups = groups;

    api_request_then_reload("POST", USERS_API + "/", json_submission);
}

function reset_edit_user_form() {
    $("#edit_user_username").val("");
    $("#edit_user_password").val("");
    $("#edit_user_display_name").val("");
    $("#edit_user_email").val("");
    $("#edit_user_queue").val("default");
    $("#edit_user_timezone").val("UTC");
    $("#edit_user_permissions").val("");
    $("#edit_user_groups").val("");

    $("#edit_user_username").prop("disabled", false);
    $("#edit_user_password").prop("disabled", false);
    $("#edit_user_display_name").prop("disabled", false);
    $("#edit_user_email").prop("disabled", false);

    clear_edit_user_permissions();
}


$(document).ready(function() {
    $("#btn_add_user").on('click', function() {
        // set the form to the defaults for a new user
        reset_edit_user_form();

        // set the modal title to "Add User"
        $("#edit_user_modal_label").text("Add User");

        // tells the server whether to add or edit the user
        $("#edit_or_add").val("add");
        
        // show the modal
        $("#edit_user_modal").modal("show");
    });

    $("#btn_edit_user_add_permission").on('click', function() {
        add_user_permission_elements({ id: null, effect: "ALLOW", major: "", minor: "" });
    });

    $("#btn_edit_user").on('click', function() {
        // get the details of the selected users
        var selected_user_ids = get_selected_user_ids();
        console.log(selected_user_ids);

        reset_edit_user_form();

        if (selected_user_ids.length == 0) {
            alert("Please select a user to edit");
            return;
        } else if (selected_user_ids.length > 1) {
            $("#edit_user_modal_label").text("Edit Multiple Users");
            // disable username, display name and email when editing multiple users
            $("#edit_user_username").prop("disabled", true);
            $("#edit_user_password").prop("disabled", true);
            $("#edit_user_display_name").prop("disabled", true);
            $("#edit_user_email").prop("disabled", true);

            // set the other fields to empty values
            $("#edit_user_queue").val("");
            $("#edit_user_timezone").val("");
            $("#edit_user_permissions").val("");
            $("input[name^='edit_user_group_']").prop("checked", false);
        } else {
            $("#edit_user_modal_label").text("Edit User");
            // get the details of the selected user
            var user_id = selected_user_ids[0];
            api_request("GET", USERS_API + "/details?user_ids=" + user_id)
                .then(response => response.json())
                .then(data => {
                    var user_details = data[user_id];

                    // set the form fields to the values from the server
                    $("#edit_user_username").val(user_details.username);
                    $("#edit_user_display_name").val(user_details.display_name);
                    $("#edit_user_email").val(user_details.email);
                    $("#edit_user_queue").val(user_details.queue);
                    $("#edit_user_timezone").val(user_details.timezone);

                    for (var i = 0; i < user_details.groups.length; i++) {
                        $("#edit_user_group_" + user_details.groups[i].id).prop("checked", true);
                    }

                    for (var i = 0; i < user_details.permissions.length; i++) {
                        add_user_permission_elements(user_details.permissions[i]);
                    }
                })
                .catch(error => {
                    console.error('There was a problem with the fetch operation:', error);
                });
        }

        // tells the server whether to add or edit the user
        $("#edit_or_add").val("edit");

        // show the modal
        $("#edit_user_modal").modal("show");
    });

    $("#btn_edit_user_apply").on('click', function() {
        var is_edit = $("#edit_or_add").val() == "edit";

        if (is_edit) {
            submit_edit_user();
        } else {
            submit_add_user();
        }

        // do not submit the form
        return false;
    });

    // focus the username field when the modal is shown
    $("#edit_user_modal").on("shown.bs.modal", function(e) {
        $("#edit_user_username").trigger("focus");
    });

    // focus the name field when the modal is shown
    $("#add_auth_group_modal").on("shown.bs.modal", function(e) {
        $("#add_auth_group_name").trigger("focus");
    });

    // we submit this manually in the submit_edit_user function
    $("#edit_user_form").on('submit', function(e) {
        e.preventDefault();
    });

    $("#btn_enable_user").on('click', function() {
        var selected_user_ids = get_selected_user_ids();
        console.log(selected_user_ids);

        var json_submission = {};
        for (var i = 0; i < selected_user_ids.length; i++) {
            json_submission[selected_user_ids[i]] = {
                enabled: true
            };
        }

        api_request_then_reload("PATCH", USERS_API + "/", json_submission);
    });

    $("#btn_disable_user").on('click', function() {
        var selected_user_ids = get_selected_user_ids();
        console.log(selected_user_ids);

        var json_submission = {};
        for (var i = 0; i < selected_user_ids.length; i++) {
            json_submission[selected_user_ids[i]] = {
                enabled: false
            };
        }

        api_request_then_reload("PATCH", USERS_API + "/", json_submission);
    });

    $("#btn_add_group").on('click', function() {
        $("#add_auth_group_name").val("");
        $("#add_auth_group_modal").modal("show");
    });

    // this form posts natively; block the submit when no name was entered so the user gets a
    // message instead of the server's error response
    $("#add_auth_group_form").on('submit', function(e) {
        e.preventDefault();
        var name = $("#add_auth_group_name").val().trim();
        if (!name) {
            alert("Enter a name for the permission group.");
            $("#add_auth_group_name").trigger("focus");
            return false;
        }
        api_request_then_reload("POST", USERS_API + "/groups", { name: name });
        return false;
    });

    $("#btn_remove_group").on('click', function() {
        var selected_group_ids = get_selected_group_ids();
        if (selected_group_ids.length == 0) {
            alert("Please select one or more groups to remove");
            return;
        }

        var json_submission = { groups: selected_group_ids };

        api_request_then_reload("POST", USERS_API + "/groups/delete", json_submission);
    });

    $("#btn_add_permissions").on('click', function() {
        // reset to an empty selection so the modal never carries a stale (or superuser) default
        $("#add_permission_effect").val("ALLOW");
        $("#add_permission_catalog").val("");
        $("#add_permission_major").val("");
        $("#add_permission_minor").val("");
        $("#add_permission_modal").modal("show");
    });

    // choosing a catalog entry fills the major/minor fields (which remain editable for wildcards)
    $("#add_permission_catalog").on('change', function() {
        var value = $(this).val();
        if (!value) { return; }
        var parts = value.split(":");
        $("#add_permission_major").val(parts[0]);
        $("#add_permission_minor").val(parts[1]);
    });

    $("#btn_execute_add_permission").on('click', function() {
        var effect = $("#add_permission_effect").val();
        var major = $("#add_permission_major").val().trim();
        var minor = $("#add_permission_minor").val().trim();
        var users = get_selected_user_ids();
        var groups = get_selected_group_ids();

        // the server enforces these too, but fail fast rather than silently granting nothing
        if (!major || !minor) {
            alert("Choose a permission from the catalog, or enter both a major and a minor.");
            return false;
        }
        if (users.length === 0 && groups.length === 0) {
            alert("Select at least one user or group to grant this permission to.");
            return false;
        }
        if (major === "*" && minor === "*" &&
            !confirm("Grant *:* (full administrative access) to the selected users/groups?")) {
            return false;
        }

        var json_submission = {
            effect: effect,
            major: major,
            minor: minor,
            users: users,
            groups: groups,
        };

        api_request_then_reload("POST", USERS_API + "/permissions", json_submission);
    });

    $("#btn_remove_permissions").on('click', function() {
        var users = get_selected_user_permission_ids();
        var groups = get_selected_group_permission_ids();

        var json_submission = {
            users: users,
            groups: groups,
        };

        api_request_then_reload("POST", USERS_API + "/permissions/delete", json_submission);
    });

    function username_for(user_id) {
        return $("input[name='user_id_" + user_id + "']").closest("tr").find("td:first").text().trim();
    }

    // ---- API key scope editor, shared by the new-key and edit-key modals ----
    // The scope picker reuses build_permission_select (the same catalog-driven widget as the
    // user-permission editor), so there is no second catalog fetch and no bespoke editor.
    function add_api_key_scope_row(list, key) {
        var li = $("<li class='mb-1 d-flex align-items-center'></li>").css("list-style-type", "none");
        var deleteButton = $("<button type='button' class='btn btn-xs btn-outline-danger ms-1'>delete</button>");
        var permSelect = build_permission_select(key || "");
        // no d-inline-block: it is display:inline-block !important and would defeat .hide()
        var customInput = $("<input type='text' class='form-control form-control-sm perm-custom' " +
            "style='width:auto; margin-left:8px;' placeholder='major:minor'>").hide();
        permSelect.on("change", function() {
            if ($(this).val() === CUSTOM_PERMISSION) { customInput.show().trigger("focus"); }
            else { customInput.val("").hide(); }
        });
        li.append(deleteButton).append(permSelect).append(customInput);
        $(list).append(li);
        deleteButton.on('click', function() { $(this).closest("li").remove(); });
    }

    function collect_api_key_scope(list) {
        var scope = [];
        $(list).children().each(function() {
            var row = $(this);
            var selected = row.find(".perm-select").val();
            var value = (selected === CUSTOM_PERMISSION) ? row.find(".perm-custom").val().trim() : selected;
            if (!value || value.indexOf(":") === -1) { return; } // skip incomplete rows
            var parts = value.split(":");
            scope.push({ major: parts[0], minor: parts.slice(1).join(":") });
        });
        return scope;
    }

    // prefix is "new_api_key" or "edit_api_key": the two modals share element naming
    function set_api_key_mode(prefix, mode) {
        if (mode === "inherit") { $("#" + prefix + "_scope_section").hide(); }
        else { $("#" + prefix + "_scope_section").show(); }
    }

    // read the form of either modal into the request body, or return null after alerting
    function collect_api_key_body(prefix) {
        var mode = $("input[name='" + prefix + "_mode']:checked").val();
        var body = { name: $("#" + prefix + "_name").val().trim() };
        if (mode === "inherit") {
            body.inherit = true;
            body.scope = [];
        } else {
            body.inherit = false;
            body.scope = collect_api_key_scope("#" + prefix + "_scope_list");
            if (body.scope.length === 0) {
                alert("Add at least one permission, or choose Full account access (inherit).");
                return null;
            }
        }
        return body;
    }

    ["new_api_key", "edit_api_key"].forEach(function(prefix) {
        $("input[name='" + prefix + "_mode']").on("change", function() {
            set_api_key_mode(prefix, $("input[name='" + prefix + "_mode']:checked").val());
        });
        $("#btn_" + prefix + "_add_scope").on('click', function() {
            add_api_key_scope_row("#" + prefix + "_scope_list", "");
        });
    });

    // ---- New API key: name + inherit-or-scope, revealed exactly once ----

    var new_api_key_user_id = null;

    $("#btn_new_api_key").on('click', function() {
        var selected_user_ids = get_selected_user_ids();
        if (selected_user_ids.length != 1) {
            alert("Select exactly one user to create an API key for.");
            return;
        }
        new_api_key_user_id = selected_user_ids[0];
        $("#new_api_key_username").text(username_for(new_api_key_user_id));
        $("#new_api_key_name").val("");
        $("#new_api_key_scope_list").children().remove();
        $("#new_api_key_mode_restricted").prop("checked", true);
        set_api_key_mode("new_api_key", "restricted");
        add_api_key_scope_row("#new_api_key_scope_list", "");
        $("#new_api_key_modal").modal("show");
    });

    $("#new_api_key_form").on('submit', function(e) {
        e.preventDefault();
        if (new_api_key_user_id === null) { return; }
        var body = collect_api_key_body("new_api_key");
        if (body === null) { return; }
        var name = $("#new_api_key_username").text();
        api_request("POST", USERS_API + "/" + new_api_key_user_id + "/apikeys", body)
            .then(response => response.json())
            .then(data => {
                $("#new_api_key_modal").modal("hide");
                $("#api_key_username").text(name);
                $("#api_key_value").val(data.api_key);
                $("#api_key_modal").modal("show");
            })
            .catch(error => alert(error.message));
    });

    // the key is only shown while this modal is open; reload once it closes so the table updates
    $("#api_key_modal").on("hidden.bs.modal", function() {
        window.location.reload();
    });

    $("#btn_copy_api_key").on('click', function() {
        var button = $(this);
        Promise.resolve(copy_to_clipboard($("#api_key_value").val())).then(function() {
            button.text("Copied!");
            setTimeout(function() { button.text("Copy"); }, 1500);
        }).catch(function() {
            // never leave the analyst believing a key was copied when it wasn't
            alert("Unable to copy to the clipboard. Select the key and copy it manually.");
        });
    });

    // ---- Manage keys: list a user's keys, edit their scope, or revoke them individually ----
    var edit_api_key = null; // { id, user_id } of the key open in the edit modal
    var returning_to_key_list = false; // the list closed only to open the editor; no page reload

    function open_edit_api_key(user_id, key) {
        edit_api_key = { id: key.id, user_id: user_id };
        $("#edit_api_key_username").text(username_for(user_id));
        $("#edit_api_key_name").val(key.name);
        $("#edit_api_key_scope_list").children().remove();
        if (key.inherit_user_scope) {
            $("#edit_api_key_mode_inherit").prop("checked", true);
            set_api_key_mode("edit_api_key", "inherit");
        } else {
            $("#edit_api_key_mode_restricted").prop("checked", true);
            set_api_key_mode("edit_api_key", "restricted");
            key.scope.forEach(function(s) {
                add_api_key_scope_row("#edit_api_key_scope_list", s.major + ":" + s.minor);
            });
        }
        if ($("#edit_api_key_scope_list").children().length === 0) {
            add_api_key_scope_row("#edit_api_key_scope_list", "");
        }
        // Bootstrap does not stack modals (the list would paint over the editor and swallow its
        // clicks), so hand off: close the list, open the editor, and come back when it closes.
        returning_to_key_list = true;
        $("#manage_api_keys_modal").one("hidden.bs.modal", function() {
            $("#edit_api_key_modal").modal("show");
        });
        $("#manage_api_keys_modal").modal("hide");
    }

    $("#edit_api_key_form").on('submit', function(e) {
        e.preventDefault();
        if (edit_api_key === null) { return; }
        var body = collect_api_key_body("edit_api_key");
        if (body === null) { return; }
        api_request("PUT", USERS_API + "/apikeys/" + edit_api_key.id, body)
            .then(function() { $("#edit_api_key_modal").modal("hide"); })
            .catch(function(error) { alert(error.message); });
    });

    // saved or cancelled, return to the key list with fresh data
    $("#edit_api_key_modal").on("hidden.bs.modal", function() {
        if (edit_api_key === null) { return; }
        var user_id = edit_api_key.user_id;
        edit_api_key = null;
        load_api_keys(user_id);
        $("#manage_api_keys_modal").modal("show");
    });

    function render_api_keys(user_id, keys) {
        var tbody = $("#manage_api_keys_list");
        tbody.empty();
        if (!keys.length) {
            tbody.append("<tr><td colspan='3' class='text-muted'>No API keys.</td></tr>");
            return;
        }
        keys.forEach(function(k) {
            var scope = k.inherit_user_scope ? "inherit (full account)" :
                (k.scope.map(function(s){ return s.major + ":" + s.minor; }).join(", ") || "(no scope — denies all)");
            var tr = $("<tr></tr>");
            tr.append($("<td></td>").text(k.name));
            tr.append($("<td></td>").text(scope));
            var edit = $("<button type='button' class='btn btn-xs btn-outline-dark me-1'>edit</button>");
            edit.on('click', function() { open_edit_api_key(user_id, k); });
            var revoke = $("<button type='button' class='btn btn-xs btn-outline-danger'>revoke</button>");
            revoke.on('click', function() {
                if (!confirm("Revoke key '" + k.name + "'? This cannot be undone.")) { return; }
                api_request("DELETE", USERS_API + "/apikeys/" + k.id)
                    .then(function() { load_api_keys(user_id); })
                    .catch(function(error) { alert(error.message); });
            });
            tr.append($("<td class='text-nowrap'></td>").append(edit).append(revoke));
            tbody.append(tr);
        });
    }

    function load_api_keys(user_id) {
        api_request("GET", USERS_API + "/" + user_id + "/apikeys")
            .then(response => response.json())
            .then(keys => render_api_keys(user_id, keys))
            .catch(error => alert(error.message));
    }

    $("#btn_manage_api_keys").on('click', function() {
        var selected_user_ids = get_selected_user_ids();
        if (selected_user_ids.length != 1) {
            alert("Select exactly one user to manage API keys for.");
            return;
        }
        var user_id = selected_user_ids[0];
        $("#manage_api_keys_username").text(username_for(user_id));
        load_api_keys(user_id);
        $("#manage_api_keys_modal").modal("show");
    });

    // reload when the manage modal closes so the table's key counts reflect any revokes
    $("#manage_api_keys_modal").on("hidden.bs.modal", function() {
        if (returning_to_key_list) { returning_to_key_list = false; return; }
        window.location.reload();
    });

    $("#master_user_checkbox").on('change', function(e) {
        // check (or uncheck) all the user checkboxes at once
        $("input[name^='user_id_']").prop('checked', $("#master_user_checkbox").prop('checked'));
    });

    // set the initial state of the hide disabled users checkbox based on the cookie storage
    $("#hide_disabled_users").prop('checked', true);
    if ($.cookie("hide_disabled_users") == 'false') {
        $("#hide_disabled_users").prop('checked', false);
    }

    // when the hide disabled users checkbox is changed, show or hide the disabled users
    $("#hide_disabled_users").on('change', function(e) {
        // Save the value of the checkbox to a cookie (expires in 30 days)
        $.cookie("hide_disabled_users", $(this).prop('checked'), { expires: 30 });

        // reload the page
        window.location.reload();
    });
});