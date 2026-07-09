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

    fetch("/ace/admin/users/edit", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(json_submission),
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            window.location.reload();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
    });
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

    json_submission = {
        username: $("#edit_user_username").val(),
        password: $("#edit_user_password").val(),
        display_name: $("#edit_user_display_name").val(),
        email: $("#edit_user_email").val(),
        queue: $("#edit_user_queue").val(),
        timezone: $("#edit_user_timezone").val(),
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

    fetch("/ace/admin/users/add", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(json_submission),
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            window.location.reload();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
    });
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
            fetch(`/ace/admin/users/details?user_ids=${user_id}`)
                .then(response => {
                    if (!response.ok) {
                        response.text().then(text => {
                            alert(text);
                        });
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
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

        fetch("/ace/admin/users/edit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(json_submission),
        }).then(response => {
            if (!response.ok) {
                response.text().then(text => {
                    alert(text);
                });
            } else {
                window.location.reload();
            }
        }).catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
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

        fetch("/ace/admin/users/edit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(json_submission),
        }).then(response => {
            if (!response.ok) {
                response.text().then(text => {
                    alert(text);
                });
            } else {
                window.location.reload();
            }
        }).catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
    });

    $("#btn_add_group").on('click', function() {
        $("#add_auth_group_name").val("");
        $("#add_auth_group_modal").modal("show");
    });

    // this form posts natively; block the submit when no name was entered so the user gets a
    // message instead of the server's error response
    $("#add_auth_group_form").on('submit', function(e) {
        if (!$("#add_auth_group_name").val().trim()) {
            e.preventDefault();
            alert("Enter a name for the permission group.");
            $("#add_auth_group_name").trigger("focus");
            return false;
        }
    });

    $("#btn_remove_group").on('click', function() {
        var selected_group_ids = get_selected_group_ids();
        if (selected_group_ids.length == 0) {
            alert("Please select one or more groups to remove");
            return;
        }

        var json_submission = { groups: selected_group_ids };

        fetch("/ace/admin/groups/delete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(json_submission),
        }).then(response => {
            if (!response.ok) {
                response.text().then(text => {
                    alert(text);
                });
            } else {
                window.location.reload();
            }
        }).catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
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

        fetch("/ace/admin/permissions/add", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(json_submission),
        }).then(response => {
            if (!response.ok) {
                response.text().then(text => {
                    alert(text);
                });
            } else {
                window.location.reload();
            }
        }).catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
    });

    $("#btn_remove_permissions").on('click', function() {
        var users = get_selected_user_permission_ids();
        var groups = get_selected_group_permission_ids();

        var json_submission = {
            users: users,
            groups: groups,
        };

        fetch("/ace/admin/permissions/delete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(json_submission),
        }).then(response => {
            if (!response.ok) {
                response.text().then(text => {
                    alert(text);
                });
            } else {
                window.location.reload();
            }
        }).catch(error => {
            console.error('There was a problem with the fetch operation:', error);
        });
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