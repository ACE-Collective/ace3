const FC_PAGE_OFFSET_START = "start";
const FC_PAGE_OFFSET_BACKWARD = "backward";
const FC_PAGE_OFFSET_FORWARD = "forward";
const FC_PAGE_OFFSET_END = "end";

const ACTION_CANCEL = "cancel";
const ACTION_RETRY = "retry";
const ACTION_DELETE = "delete";

// the currently selected collection for history
var current_collection_history_id = null;
var current_collection_selected_row = null;

function set_current_collection_history_id(collection_id) {
    current_collection_history_id = collection_id;

    // clear the background color of the previously selected row
    if (current_collection_selected_row != null) {
        current_collection_selected_row.children().css("background-color", "");
    }

    // find the row in the collection table that contains the collection id
    var row = $("#collections_table tr[collection_id='" + collection_id + "']");
    if (row.length > 0) {
        current_collection_selected_row = row;
        // change background color to indicate selection
        row.children().css("background-color", "#cfe2ff");
    }
}

// collection pagination functions
// ---------------------------------------------------------------------------

function setup_collection_pagination() {
    $("#btn_fc_page_start").click(function(e) {
        set_fc_page_offset(FC_PAGE_OFFSET_START);
    });

    $("#btn_fc_page_backward").click(function(e) {
        set_fc_page_offset(FC_PAGE_OFFSET_BACKWARD);
    });

    $("#btn_fc_page_forward").click(function(e) {
        set_fc_page_offset(FC_PAGE_OFFSET_FORWARD);
    });

    $("#btn_fc_page_end").click(function(e) {
        set_fc_page_offset(FC_PAGE_OFFSET_END);
    });

    $("#btn_fc_page_size_edit").click(function(e) {
        show_fc_page_size_edit_modal();
    });

    $("#fc_page_size_edit_modal").on("shown.bs.modal", function(e) {
        $("#fc_page_size").focus().select();
    });

    $("#btn_fc_page_size_edit_apply").click(function(e) {
        apply_fc_page_size();
    });

    $("#fc_page_size").keypress(function(e) {
        if (e.which === 13) {
            apply_fc_page_size();
        }
    });
}

function show_fc_page_size_edit_modal() {
    $("#fc_page_size_edit_modal").modal("show");
}

function hide_fc_page_size_edit_modal() {
    $("#fc_page_size_edit_modal").modal("hide");
}

function apply_fc_page_size() {
    var size = $("#fc_page_size").val();
    if (size != "") {
        set_fc_page_size(size);
    }

    hide_fc_page_size_edit_modal();
}

function set_fc_page_size(size) {
    fetch("/ace/file_collection/collections/page", {
        method: "POST",
        body: JSON.stringify({ size: size }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collections();
        }
    });
}

function set_fc_page_offset(direction) {
    fetch("/ace/file_collection/collections/page", {
        method: "POST",
        body: JSON.stringify({ direction: direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collections();
        }
    });
}

function update_fc_page_count() {
    // Use embedded pagination data from template to avoid extra API call
    var paginationData = $("#fc_pagination_data");
    if (paginationData.length > 0) {
        var offset = parseInt(paginationData.data("offset"));
        var size = parseInt(paginationData.data("size"));
        var total = parseInt(paginationData.data("total"));
        var endRange = Math.min(offset + size, total);
        // Handle edge case where total is 0
        var startRange = total > 0 ? offset + 1 : 0;
        $("#fc_page_count").text(startRange + " - " + endRange + " of " + total);
    } else {
        // Fallback to API call if embedded data not available
        fetch("/ace/file_collection/collections/page", {
            method: "GET",
        }).then(response => response.json()).then(data => {
            $("#fc_page_count").text((data.offset + 1) + " - " + Math.min(data.offset + data.size, data.total) + " of " + data.total);
        });
    }
}

function set_fc_sort_filter(sort_filter) {
    fetch("/ace/file_collection/collections/sort", {
        method: "POST",
        body: JSON.stringify({ sort_filter: sort_filter }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collections();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error setting collection sort filter: " + error);
    });
}

function set_fc_sort_direction(sort_direction) {
    fetch("/ace/file_collection/collections/sort", {
        method: "POST",
        body: JSON.stringify({ sort_direction: sort_direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collections();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Error setting collection sort filter: " + error);
    });
}

// collection history pagination functions
// ---------------------------------------------------------------------------

function setup_collection_history_pagination() {
    $("#btn_fch_page_start").click(function(e) {
        set_fch_page_offset(FC_PAGE_OFFSET_START);
    });

    $("#btn_fch_page_backward").click(function(e) {
        set_fch_page_offset(FC_PAGE_OFFSET_BACKWARD);
    });

    $("#btn_fch_page_forward").click(function(e) {
        set_fch_page_offset(FC_PAGE_OFFSET_FORWARD);
    });

    $("#btn_fch_page_end").click(function(e) {
        set_fch_page_offset(FC_PAGE_OFFSET_END);
    });

    $("#btn_fch_page_size_edit").click(function(e) {
        show_fch_page_size_edit_modal();
    });

    $("#fch_page_size_edit_modal").on("shown.bs.modal", function(e) {
        $("#fch_page_size").focus().select();
    });

    $("#btn_fch_page_size_edit_apply").click(function(e) {
        apply_fch_page_size();
    });

    $("#fch_page_size").keypress(function(e) {
        if (e.which === 13) {
            apply_fch_page_size();
        }
    });
}

function show_fch_page_size_edit_modal() {
    $("#fch_page_size_edit_modal").modal("show");
}

function hide_fch_page_size_edit_modal() {
    $("#fch_page_size_edit_modal").modal("hide");
}

function apply_fch_page_size() {
    var size = $("#fch_page_size").val();
    if (size != "") {
        set_fch_page_size(size);
    }

    hide_fch_page_size_edit_modal();
}

function set_fch_page_size(size) {
    if (current_collection_history_id == null) {
        return;
    }

    fetch("/ace/file_collection/history/" + current_collection_history_id + "/page", {
        method: "POST",
        body: JSON.stringify({ size: size }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collection_history();
        }
    });
}

function set_fch_page_offset(direction) {
    if (current_collection_history_id == null) {
        return;
    }

    fetch("/ace/file_collection/history/" + current_collection_history_id + "/page", {
        method: "POST",
        body: JSON.stringify({ direction: direction }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (response.ok) {
            load_collection_history();
        }
    });
}

function update_fch_page_count() {
    if (current_collection_history_id == null) {
        return;
    }

    fetch("/ace/file_collection/history/" + current_collection_history_id + "/page", {
        method: "GET",
    }).then(response => response.json()).then(data => {
        $("#fch_page_count").text((data.offset + 1) + " - " + Math.min(data.offset + data.size, data.total) + " of " + data.total);
    });
}

// filters
// ---------------------------------------------------------------------------

function get_fc_filter_values() {
    return {
        fc_filter_id: $("#fc_filter_id").val(),
        fc_filter_collector: $("#fc_filter_collector").val(),
        fc_filter_type: $("#fc_filter_type").val(),
        fc_filter_value: $("#fc_filter_value").val(),
        fc_filter_status: $("#fc_filter_status").val(),
        fc_filter_result: $("#fc_filter_result").val(),
    };
}

function clear_fc_filters() {
    $("#fc_filter_id").val("");
    $("#fc_filter_collector").val("");
    $("#fc_filter_type").val("");
    $("#fc_filter_value").val("");
    $("#fc_filter_status").val("");
    $("#fc_filter_result").val("");

    load_collections();
}

function load_collections() {

    // remember the current filter values
    var filter_values = get_fc_filter_values();

    fetch("/ace/file_collection/collections", {
        method: "POST",
        body: JSON.stringify({ filter_values: filter_values }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                $("#collections_panel").html("<p>Error loading collections: " + text + "</p>");
                console.error('There was a problem with the fetch operation:', text);
            });
        } else {
            response.text().then(text => {
                $("#collections_panel").html(text);
                update_fc_page_count();
                setup_collection_event_handlers();
                update_control_panel_buttons();

                if (currently_editing_filter_id != null) {
                    $("#" + currently_editing_filter_id).trigger("focus")[0]?.setSelectionRange($("#" + currently_editing_filter_id).val().length, $("#" + currently_editing_filter_id).val().length);
                    currently_editing_filter_id = null;
                }
            });
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        $("#collections_panel").html("<p>Error loading collections: " + error + "</p>");
    });
}

var currently_editing_filter_id = null;

function setup_collection_event_handlers() {

    // collection selection
    $("#collection_select_all").change(function(e) {
        $("input[name^='collection_id_']").prop('checked', $(this).prop('checked'));
        update_control_panel_buttons();
    });

    // when a collection checkbox is changed, update the control panel buttons
    $("input[name^='collection_id_']").change(function(e) {
        update_control_panel_buttons();
    });

    $("button[name^='btn_view_history_']").click(function(e) {
        load_collection_history($(this).attr("collection_id"));
    });

    $("[id^='th_fc_sort_direction']").click(function(e) {
        set_fc_sort_direction($(this).attr("sort_direction"));
    });

    $("[id^='th_fc_sort_filter']").click(function(e) {
        set_fc_sort_filter($(this).attr("sort_filter"));
    });

    $("[id^='fc_filter_']").keypress(function(e) {
        if (e.which === 13) {
            currently_editing_filter_id = $(this).attr("id");
            load_collections();
        }
    });

    $("#btn_clear_filters").click(function(e) {
        clear_fc_filters();
    });

    $("#btn_apply_filters").click(function(e) {
        load_collections();
    });
}

function load_collection_history(collection_id = null) {
    if (collection_id != null) {
        set_current_collection_history_id(collection_id);
    }

    fetch("/ace/file_collection/history/" + current_collection_history_id, {
        method: "GET",
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            response.text().then(text => {
                $("#collection_history_panel").html(text);
                update_fch_page_count();
            });
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert(error);
    });
}

// action functions
// ---------------------------------------------------------------------------

function get_selected_collection_ids() {
    return $("input[name^='collection_id_']:checked").map(function() {
        return $(this).attr("collection_id");
    }).get();
}

function get_http_verb_for_action(action) {
    if (action == ACTION_DELETE) {
        return "DELETE";
    } else {
        return "PATCH";
    }
}

function action_selected_collections(action, confirm_message = null) {
    var selected_collection_ids = get_selected_collection_ids();
    if (selected_collection_ids.length == 0) {
        return;
    }

    if (confirm_message) {
        if (! confirm(confirm_message)) {
            return;
        }
    }

    fetch("/ace/file_collection/collections", {
        method: get_http_verb_for_action(action),
        body: JSON.stringify({ collection_ids: selected_collection_ids, action: action }),
        headers: {
            "Content-Type": "application/json",
        },
    }).then(response => {
        if (!response.ok) {
            response.text().then(text => {
                alert(text);
            });
        } else {
            load_collections();
        }
    }).catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert(error);
    });

}

function delete_selected_collections() {
    action_selected_collections(ACTION_DELETE, "Are you sure you want to delete the selected file collections?");
}

function cancel_selected_collections() {
    action_selected_collections(ACTION_CANCEL)
}

function retry_selected_collections() {
    action_selected_collections(ACTION_RETRY)
}

function update_control_panel_buttons() {
    var selected_collection_ids = get_selected_collection_ids();
    if (selected_collection_ids.length > 0) {
        $("#btn_delete").prop("disabled", false);
        $("#btn_cancel").prop("disabled", false);
        $("#btn_retry").prop("disabled", false);
    } else {
        $("#btn_delete").prop("disabled", true);
        $("#btn_cancel").prop("disabled", true);
        $("#btn_retry").prop("disabled", true);
    }
}

// setup handler
// ---------------------------------------------------------------------------

$(document).ready(function() {

    // control panel buttons
    $("#btn_refresh").click(function(e) {
        load_collections();
    });

    $("#btn_retry").click(function(e) {
        retry_selected_collections();
    });

    $("#btn_cancel").click(function(e) {
        cancel_selected_collections();
    });

    $("#btn_delete").click(function(e) {
        delete_selected_collections();
    });

    setup_collection_pagination();
    setup_collection_history_pagination();

    load_collections();
});
