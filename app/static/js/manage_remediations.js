const R_PAGE_OFFSET_START = "start";
const R_PAGE_OFFSET_BACKWARD = "backward";
const R_PAGE_OFFSET_FORWARD = "forward";
const R_PAGE_OFFSET_END = "end";

const ACTION_CANCEL = "cancel";
const ACTION_RETRY = "retry";
const ACTION_RESTORE = "restore";
const ACTION_DELETE = "delete";

// the currently selected remediation for history
var current_remediation_history_id = null;
var current_remediation_selected_row = null;

function set_current_remediation_history_id(remediation_id) {
    current_remediation_history_id = remediation_id;

    // clear the background color of the previously selected row
    if (current_remediation_selected_row != null) {
        current_remediation_selected_row.children().css("background-color", "");
    }

    // find the row in the remediation table that contains the remediation id
    var row = $("#remediations_table tr[remediation_id='" + remediation_id + "']");
    if (row.length > 0) {
        current_remediation_selected_row = row;
        // change background color to indicate selection
        row.children().css("background-color", "#cfe2ff");
    }
}

// remediation pagination functions
// ---------------------------------------------------------------------------

function setup_remediation_pagination() {
    $("#btn_r_page_start").click(function(e) {
        set_r_page_offset(R_PAGE_OFFSET_START);
    });

    $("#btn_r_page_backward").click(function(e) {
        set_r_page_offset(R_PAGE_OFFSET_BACKWARD);
    });

    $("#btn_r_page_forward").click(function(e) {
        set_r_page_offset(R_PAGE_OFFSET_FORWARD);
    });

    $("#btn_r_page_end").click(function(e) {
        set_r_page_offset(R_PAGE_OFFSET_END);
    });

    $("#btn_r_page_size_edit").click(function(e) {
        show_r_page_size_edit_modal();
    });

    $("#r_page_size_edit_modal").on("shown.bs.modal", function(e) {
        $("#r_page_size").focus().select();
    });

    $("#btn_r_page_size_edit_apply").click(function(e) {
        apply_r_page_size();
    });

    $("#r_page_size").keypress(function(e) {
        if (e.which === 13) {
            apply_r_page_size();
        }
    });
}

function show_r_page_size_edit_modal() {
    $("#r_page_size_edit_modal").modal("show");
}

function hide_r_page_size_edit_modal() {
    $("#r_page_size_edit_modal").modal("hide");
}

function apply_r_page_size() {
    var size = $("#r_page_size").val();
    if (size != "") {
        set_r_page_size(size);
    }

    hide_r_page_size_edit_modal();
}

function set_r_page_size(size) {
    fetch("/ace/remediation/remediations/page", {
        method: "POST",
        body: JSON.stringify({ size: size }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_remediations();
        }
    });
}

function set_r_page_offset(direction) {
    fetch("/ace/remediation/remediations/page", {
        method: "POST",
        body: JSON.stringify({ direction: direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_remediations();
        }
    });
}
    
function update_r_page_count() {
    fetch("/ace/remediation/remediations/page", {
        method: "GET",
    }).then(response => response.json()).then(data => {
        $("#r_page_count").text((data.offset + 1) + " - " + Math.min(data.offset + data.size, data.total) + " of " + data.total);
    });
}

function set_r_sort_filter(sort_filter) {
    fetch("/ace/remediation/remediations/sort", {
        method: "POST",
        body: JSON.stringify({ sort_filter: sort_filter }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_remediations();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error setting remediation sort filter: " + error);
    });
}

function set_r_sort_direction(sort_direction) {
    fetch("/ace/remediation/remediations/sort", {
        method: "POST",
        body: JSON.stringify({ sort_direction: sort_direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {   
        if (response.ok) {
            load_remediations();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error setting remediation sort filter: " + error);
    });
}

// remediation history pagination functions
// ---------------------------------------------------------------------------

function setup_remediation_history_pagination() {
    $("#btn_rh_page_start").click(function(e) {
        set_rh_page_offset(R_PAGE_OFFSET_START);
    });

    $("#btn_rh_page_backward").click(function(e) {
        set_rh_page_offset(R_PAGE_OFFSET_BACKWARD);
    });

    $("#btn_rh_page_forward").click(function(e) {
        set_rh_page_offset(R_PAGE_OFFSET_FORWARD);
    });

    $("#btn_rh_page_end").click(function(e) {
        set_rh_page_offset(R_PAGE_OFFSET_END);
    });

    $("#btn_rh_page_size_edit").click(function(e) {
        show_rh_page_size_edit_modal();
    });

    $("#rh_page_size_edit_modal").on("shown.bs.modal", function(e) {
        $("#rh_page_size").focus().select();
    });

    $("#btn_rh_page_size_edit_apply").click(function(e) {
        apply_rh_page_size();
    });

    $("#rh_page_size").keypress(function(e) {
        if (e.which === 13) {
            apply_rh_page_size();
        }
    });
}

function show_rh_page_size_edit_modal() {
    $("#rh_page_size_edit_modal").modal("show");
}

function hide_rh_page_size_edit_modal() {
    $("#rh_page_size_edit_modal").modal("hide");
}

function apply_rh_page_size() {
    var size = $("#rh_page_size").val();
    if (size != "") {
        set_rh_page_size(size);
    }

    hide_rh_page_size_edit_modal();
}

function set_rh_page_size(size) {
    if (current_remediation_history_id == null) {
        return;
    }

    fetch("/ace/remediation/history/" + current_remediation_history_id + "/page", {
        method: "POST",
        body: JSON.stringify({ size: size }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_remediation_history();
        }
    });
}

function set_rh_page_offset(direction) {
    if (current_remediation_history_id == null) {
        return;
    }

    fetch("/ace/remediation/history/" + current_remediation_history_id + "/page", {
        method: "POST",
        body: JSON.stringify({ direction: direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_remediation_history();
        }
    });
}
    
function update_rh_page_count() {
    if (current_remediation_history_id == null) {
        return;
    }

    fetch("/ace/remediation/history/" + current_remediation_history_id + "/page", {
        method: "GET",
    }).then(response => response.json()).then(data => {
        $("#rh_page_count").text((data.offset + 1) + " - " + Math.min(data.offset + data.size, data.total) + " of " + data.total);
    });
}

// filters
// ---------------------------------------------------------------------------

function get_r_filter_values() {
    return {
        r_filter_id: $("#r_filter_id").val(),
        r_filter_remediator: $("#r_filter_remediator").val(),
        r_filter_type: $("#r_filter_type").val(),
        r_filter_value: $("#r_filter_value").val(),
        r_filter_analyst: $("#r_filter_analyst").val(),
        r_filter_action: $("#r_filter_action").val(),
        r_filter_status: $("#r_filter_status").val(),
        r_filter_result: $("#r_filter_result").val(),
    };
}

function clear_r_filters() {
    $("#r_filter_id").val("");
    $("#r_filter_remediator").val("");
    $("#r_filter_type").val("");
    $("#r_filter_value").val("");
    $("#r_filter_analyst").val("");
    $("#r_filter_action").val("");
    $("#r_filter_status").val("");
    $("#r_filter_result").val("");

    load_remediations();
}

function load_remediations() {

    // remember the current filter values
    var filter_values = get_r_filter_values();

    fetch("/ace/remediation/remediations", {
        method: "POST",
        body: JSON.stringify({ filter_values: filter_values }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                $("#remediations_panel").html("<p>Error loading remediations: " + text + "</p>");
                console.error('There was a problem with the fetch operation:', text);
            });
        } else {
            response.text().then(text => {
                $("#remediations_panel").html(text);
                update_r_page_count();
                setup_remediation_event_handlers();
                update_control_panel_buttons();

                if (currently_editing_filter_id != null) {
                    $("#" + currently_editing_filter_id).trigger("focus")[0]?.setSelectionRange($("#" + currently_editing_filter_id).val().length, $("#" + currently_editing_filter_id).val().length);
                    currently_editing_filter_id = null;
                }
            });
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        $("#remediations_panel").html("<p>Error loading remediations: " + error + "</p>");
    });
}

var currently_editing_filter_id = null;

function setup_remediation_event_handlers() {

    // remediation selection
    $("#remediation_select_all").change(function(e) {
        $("input[name^='remediation_id_']").prop('checked', $(this).prop('checked'));
        update_control_panel_buttons();
    });

    // when a remediation checkbox is changed, update the control panel buttons
    $("input[name^='remediation_id_']").change(function(e) {
        update_control_panel_buttons();
    });

    $("button[name^='btn_view_history_']").click(function(e) {
        load_remediation_history($(this).attr("remediation_id"));
    });

    $("[id^='th_r_sort_direction']").click(function(e) {
        set_r_sort_direction($(this).attr("sort_direction"));
    });

    $("[id^='th_r_sort_filter']").click(function(e) {
        set_r_sort_filter($(this).attr("sort_filter"));
    });

    $("[id^='r_filter_']").keypress(function(e) {
        if (e.which === 13) {
            currently_editing_filter_id = $(this).attr("id");
            load_remediations();
        }
    });

    $("#btn_clear_filters").click(function(e) {
        clear_r_filters();
    });

    $("#btn_apply_filters").click(function(e) {
        load_remediations();
    });
}

function load_remediation_history(remediation_id = null) {
    if (remediation_id != null) {
        set_current_remediation_history_id(remediation_id);
    }

    fetch("/ace/remediation/history/" + current_remediation_history_id, {
        method: "GET",
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            response.text().then(text => {
                $("#remediation_history_panel").html(text);
                update_rh_page_count();
            });
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert(error);
    });
}

// add/mass remediation functions
// ---------------------------------------------------------------------------

function show_add_remediation_modal() {
    $("#add_remediation_modal").modal("show");
}

function hide_add_remediation_modal() {
    $("#add_remediation_modal").modal("hide");
}

function show_mass_remediation_modal() {
    $("#mass_remediation_modal").modal("show");
}

function hide_mass_remediation_modal() {
    $("#mass_remediation_modal").modal("hide");
}

function execute_add_remediation() {
    var observable_type = $("#add_remediation_observable_type").val();
    var observable_value = $("#add_remediation_observable_value").val();

    if (observable_type == "") {
        alert("Please select an observable type");
        return;
    }

    if (observable_value == "") {
        alert("Please enter an observable value");
        return;
    }

    fetch("/ace/remediation/remediations", {
        method: "PUT",
        body: JSON.stringify({ observable_type: observable_type, observable_value: observable_value }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            response.json().then(data => {
                if (data.count == 0) {
                    alert("Warning: no remediations were added.");
                }
            });

            load_remediations();
            hide_add_remediation_modal();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error adding remediation: " + error);
    });
}

function execute_mass_remediation() {
    var observable_type = $("#mass_remediation_observable_type").val();
    var observable_values = $("#mass_remediation_observable_value").val();

    if (observable_type == "") {
        alert("Please select an observable type");
        return;
    }

    if (observable_values == "") {
        alert("Please paste observable values (one per line)");
        return;
    }

    fetch("/ace/remediation/mass_remediate", {
        method: "POST",
        body: JSON.stringify({ observable_type: observable_type, observable_values: observable_values }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            response.json().then(data => {
                if (data.count == 0) {
                    alert("Warning: no remediations were added.");
                }
            });

            load_remediations();
            hide_mass_remediation_modal();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error adding remediation: " + error);
    });
}

function get_selected_remediation_ids() {
    return $("input[name^='remediation_id_']:checked").map(function() {
        return $(this).attr("remediation_id");
    }).get();
}

function get_http_verb_for_action(action) {
    if (action == ACTION_DELETE) {
        return "DELETE";
    } else {
        return "PATCH";
    }
}

function action_selected_remediations(action, confirm_message = null) {
    var selected_remediation_ids = get_selected_remediation_ids();
    if (selected_remediation_ids.length == 0) {
        return;
    }

    if (confirm_message) {
        if (! confirm(confirm_message)) {
            return;
        }
    }

    fetch("/ace/remediation/remediations", {
        method: get_http_verb_for_action(action),
        body: JSON.stringify({ remediation_ids: selected_remediation_ids, action: action }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            load_remediations();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert(error);
    });

}

function delete_selected_remediations() {
    action_selected_remediations(ACTION_DELETE, "Are you sure you want to delete the selected remediations?");
}

function cancel_selected_remediations() {
    action_selected_remediations(ACTION_CANCEL)
}

function retry_selected_remediations() {
    action_selected_remediations(ACTION_RETRY)
}

function restore_selected_remediations() {
    action_selected_remediations(ACTION_RESTORE)
}

function update_control_panel_buttons() {
    var selected_remediation_ids = get_selected_remediation_ids();
    if (selected_remediation_ids.length > 0) {
        $("#btn_delete").prop("disabled", false);
        $("#btn_restore").prop("disabled", false);
        $("#btn_cancel").prop("disabled", false);
        $("#btn_retry").prop("disabled", false);
    } else {
        $("#btn_delete").prop("disabled", true);
        $("#btn_restore").prop("disabled", true);
        $("#btn_cancel").prop("disabled", true);
        $("#btn_retry").prop("disabled", true);
    }
}

// setup handler
// ---------------------------------------------------------------------------

$(document).ready(function() {

    // control panel buttons
    $("#btn_refresh").click(function(e) {
        load_remediations();
    });

    $("#btn_add_remediation").click(function(e) {
        show_add_remediation_modal();
    });

    $("#btn_mass_remediation").click(function(e) {
        show_mass_remediation_modal();
    });

    $("#btn_restore").click(function(e) {
        restore_selected_remediations();
    });

    $("#btn_retry").click(function(e) {
        retry_selected_remediations();
    });

    $("#btn_cancel").click(function(e) {
        cancel_selected_remediations();
    });

    $("#btn_delete").click(function(e) {
        delete_selected_remediations();
    });

    setup_remediation_pagination();
    setup_remediation_history_pagination();

    $("#add_remediation_modal").on("shown.bs.modal", function(e) {
        $("#add_remediation_observable_type").trigger("focus");
    });

    $("#add_remediation_observable_value").keypress(function(e) {
        if (e.which === 13) {
            execute_add_remediation();
        }
    });

    $("#btn_execute_add_remediation").click(function(e) {
        execute_add_remediation();
    });

    $("#mass_remediation_modal").on("shown.bs.modal", function(e) {
        $("#mass_remediation_observable_type").trigger("focus");
    });

    $("#btn_execute_mass_remediation").click(function(e) {
        execute_mass_remediation();
    });

    load_remediations();
});