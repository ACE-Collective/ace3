// alert management
function get_all_checked_alerts() {
    // returns the list of all checked alert IDs
    var result = Array(); $("input[name^='detail_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^detail_/, ""));
        } 
    });

    return result;
}

function get_all_checked_alerts_dispositions() {
    // returns the list of all checked alert dispositions
    var result = Array(); $("input[name^='detail_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.attr("disposition"));
        }
    });

    return result;
}

function setup_daterange_pickers() {
    // :not([data-relative]) keeps the picker off inputs in relative mode -- attaching it
    // there would overwrite the analyst's token with a concrete date range.
    $('.daterange:not([data-relative])').each(function(index) {
        if ($(this).val() == '') {
            $(this).val(
                moment().subtract(6, "days").startOf('day').format("MM-DD-YYYY HH:mm") + ' - ' +
                moment().format("MM-DD-YYYY HH:mm"));
        }
    });

    $('.daterange:not([data-relative])').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(6, 'days').startOf('day'),
        endDate: moment(),
        ranges: {
           'Today': [moment().startOf('day'), moment().endOf('day')],
           'Yesterday': [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'Last 60 Days': [moment().subtract(59, 'days').startOf('day'), moment()],
           'This Month': [moment().startOf('month').startOf('day'), moment()],
           'Last Month': [moment().subtract(1, 'month').startOf('month').startOf('day'), moment().subtract(1, 'month').endOf('month').endOf('day')]
        }
    });
}

function search_alerts() {
    // get the search query
    let search_query = $("#alert-search").val();
    (function() {
        fetch('search', { credentials: 'same-origin', method: 'POST', body: new URLSearchParams({ search: search_query }) })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// Shows the "Show more" button under each comment block whose content overflows the
// collapsed height. Layout measurement only -- the click handling and expanded state
// live in Datastar attributes on the elements themselves ($_openComments signal).
// Idempotent: runs at page load and again after every Datastar morph brings in new rows.
function init_comment_toggles() {
    $(".comments-collapsible").each(function() {
        if (this.scrollHeight > this.clientHeight + 1 || $(this).hasClass("expanded")) {
            $(this).nextAll(".comments-toggle").first().show();
        }
    });
}

// Re-injects the expanded observable rows after a Datastar morph: they are
// client-injected, so the morph removes them (the server response does not contain
// them). Content comes from the expanded_alert_observables registry maintained by
// toggle_alert_observables() in ace.js; entries whose alert left the list are dropped.
function restore_alert_observables() {
    expanded_alert_observables.forEach(function(html, alert_uuid) {
        var row = $("#alert_row_" + alert_uuid);
        if (row.length == 0) {
            expanded_alert_observables.delete(alert_uuid);
            return;
        }
        if (row.next(".alert-observables-row").length == 0) {
            row.after('<tr class="alert-observables-row" data-ignore><td colspan="' + row.children("td").length + '">' + html + '</td></tr>');
        }
        // the morphed-in expand button renders collapsed -- point it back up
        row.find("span.bi-chevron-down").removeClass("bi-chevron-down").addClass("bi-chevron-up");
    });
}

// re-apply the client-side row state after a Datastar request morphs in fresh rows
document.addEventListener("datastar-fetch", function(evt) {
    if (evt.detail && evt.detail.type === "finished") {
        init_comment_toggles();
        restore_alert_observables();
    }
});

// the auto-refresh interval on #manage_page skips polling while the tab is hidden, so
// trigger an immediate catch-up refresh when the tab becomes visible again (the modal
// gate lives in the data-on:ace-refresh expression)
document.addEventListener("visibilitychange", function() {
    if (!document.hidden) {
        var manage_page = document.getElementById("manage_page");
        if (manage_page) {
            manage_page.dispatchEvent(new CustomEvent("ace-refresh"));
        }
    }
});

$(document).ready(function() {

    document.getElementById("event_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("alert_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("ownership_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("disposition_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("contain_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("remediation_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");

    init_comment_toggles();

    // Snapshot the editor before anything can touch it, then restore it whenever the modal
    // is dismissed without applying.
    if (document.getElementById('filter_modal_body')) {
        filter_editor_html = document.getElementById('filter_modal_body').innerHTML;

        $('#filter_modal').on('hidden.bs.modal', function() {
            // A "Save as..." handoff must NOT reset: if that save comes back 400 these rows
            // are the only copy of the analyst's work, and reopening Edit is how they get
            // it back.
            if (editor_handoff) { editor_handoff = false; return; }
            reset_filter_editor();
        });
    }

    // A fresh open is a fresh filter. Nothing else clears this form -- Bootstrap only hides
    // the div, and a successful save is the only path that reloads the page -- so without
    // this the name from a save that 409'd is still sitting in the box, focused, next time
    // it opens. reset() rather than clearing by id so a field added here later cannot be
    // forgotten, which is the very bug this fixes.
    $('#save_filter_modal').on('show.bs.modal', function () {
        document.getElementById('save_filter_form').reset();
    });

    // Triggered when the modal is shown
    $('#disposition_modal').on('shown.bs.modal', function(e) {
        // Get all of the checked alerts dispositions and see if they are the same.
        all_alert_dispositions = get_all_checked_alerts_dispositions();
        const allEqual = arr => arr.every( v => v === arr[0] )
        if (allEqual(all_alert_dispositions)) {
            // Send a click to the radio button so that the hide/show save to event action happens. Just
            // setting the radio "checked" property to "true" will not work for this.
            $("#option_" + all_alert_dispositions[0]).click();
        }
        else {
            // If all the dispositions do not match, clear every radio button selection and hide the save to event button.
            $('input:radio[name=disposition]').each(function () { $(this).prop('checked', false); });
            hideSaveToEventButton();
        }
    });

    $("#btn-disposition").click(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            // XXX do this on the disposition button
            alert("You must select one or more alerts to disposition.");
            return;
        }

        // add a hidden field to the form
        $("#disposition-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');

        // and then allow the form to follow through
    });

    $("#btn-review").click(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            e.preventDefault();
            alert("You must select one or more alerts to review.");
            return;
        }

        // when marking a disposition incorrect a corrected disposition and comment are required
        if ($("input[name='review_result']:checked").val() == "INCORRECT") {
            if (!$("input[name='corrected_disposition']:checked").val()) {
                e.preventDefault();
                alert("You must select the correct disposition.");
                return;
            }
            if (!$("#review-form textarea[name='comment']").val().trim()) {
                e.preventDefault();
                alert("A review comment is required when marking a disposition incorrect.");
                return;
            }
        }

        // add a hidden field to the form
        $("#review-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');

        // and then allow the form to follow through
    });

    $("#btn-save-to-event").click(function(e) {
        let all_alert_uuids = get_all_checked_alerts();
        let disposition = $("input[name='disposition']:checked").val()
        let disposition_comment = $("textarea[name='comment']").val()

        // Inject the alert uuids, disposition, and comment to the event form. This way alerts that are going to be added to an
        // event are NOT dispositioned prior to being added to the event. This caused an issue with the analysis module
        // that changes the analysis mode to "event", but it also lets analysts back out of the modal if they realize
        // they don't want to disposition the alerts or add them to an event after all.
        if (all_alert_uuids.length > 0) {
            $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');
            $("#event-form").append('<input type="hidden" name="disposition" value="' + disposition + '" />');
            $("#event-form").append('<input type="hidden" name="disposition_comment" value="' + disposition_comment + '" />');
        }
    });

    $("#btn-add-to-event").click(function(e) {
        let all_alert_uuids = get_all_checked_alerts();
        let disposition = $("input[name='disposition']:checked").val()
        let disposition_comment = $("textarea[name='comment']").val()

        // Inject the alert uuids, disposition, and comment to the event form. This way alerts that are going to be added to an
        // event are NOT dispositioned prior to being added to the event. This caused an issue with the analysis module
        // that changes the analysis mode to "event", but it also lets analysts back out of the modal if they realize
        // they don't want to disposition the alerts or add them to an event after all.
        if (all_alert_uuids.length > 0) {
            $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />');
            $("#event-form").append('<input type="hidden" name="disposition" value="' + disposition + '" />');
            $("#event-form").append('<input type="hidden" name="disposition_comment" value="' + disposition_comment + '" />');
        }
    });

    $("#btn-disposition-and-remediate").click(function(e) {
        // set the disposition of selected alerts
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to disposition.");
            return;
        }
        disposition = $("input[name='disposition']:checked").val();
        comment = $("textarea[name='comment']").val();
        (function() {
            const params = new URLSearchParams({
                alert_uuids: all_alert_uuids.join(','),
                disposition: disposition,
                disposition_comment: comment
            });
            fetch('set_disposition', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: params,
                credentials: 'same-origin'
            })
            .then(function(resp) {
                if (!resp.ok) {
                    return resp.text().then(function(t){ throw new Error(t || resp.statusText); });
                }
                return resp.text();
            })
            .then(function(){
                show_remediation_targets(get_all_checked_alerts());
            })
            .catch(function(err){
                alert('Failed to set disposition: ' + err.message);
            });
        })();
    });

    $("#btn-realHours").click(function(e) {
        $("#frm-sla_hours").append('<input type="hidden" name="SLA_real-hours" value="1">').submit();
    });

    $("#btn-BusinessHours").click(function(e) {
        $("#frm-sla_hours").append('<input type="hidden" name="SLA_business-hours" value="1">').submit();
    });

    $("#btn-submit-comment").click(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to disposition.");
            return;
        }

        $("#comment-form").append('<input type="hidden" name="uuids" value="' + all_alert_uuids.join(",") + '" />');
        $("#comment-form").append('<input type="hidden" name="redirect" value="management" />');
        $("#comment-form").submit();
    });

    $("#btn-submit-tags").click(function(e) {
        $("#tag-form").submit();
    });

    $("#btn-submit-tags-remove").click(function(e) {
        $("#tag-remove-form").submit();
    });

    $("#tag-form").submit(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to add tags to.");
            e.preventDefault();
            return;
        }

        $("#tag-form").append('<input type="hidden" name="uuids" value="' + all_alert_uuids.join(",") + '" />');
        $("#tag-form").append('<input type="hidden" name="redirect" value="management" />');
    });

    $("#tag-remove-form").submit(function(e) {
        // compile a list of all the alerts that are checked
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to add tags to.");
            e.preventDefault();
            return;
        }

        $("#tag-remove-form").append('<input type="hidden" name="uuids" value="' + all_alert_uuids.join(",") + '" />');
        $("#tag-remove-form").append('<input type="hidden" name="redirect" value="management" />');
    });

    // --- Add Observable modal handlers ---

    // Reset directive selection when add observable modal opens
    $('#add_observable_modal').on('show.bs.modal', function () {
        $("#add_observable_directives_multiselect").val([]);
        $("#add_observable_directives_text").val("");
        $("#add_observable_directives_multiselect_container").show();
        $("#add_observable_directives_text_container").hide();
        // Reset type and value
        $("#add_observable_type").val("");
        var add_observable_input = document.getElementById("add_observable_value");
        if (add_observable_input) {
            add_observable_input.parentNode.removeChild(add_observable_input);
        }
        $("#add_observable_value_content").empty().append(
            '<input type="text" class="form-control" id="add_observable_value" name="add_observable_value" value="" placeholder="Enter Value"/>'
        );
        $("#add_observable_time").val("");
    });

    // Handle observable type changes (directive toggle, conversation dual-inputs)
    $("#add_observable_type").change(function (e) {
        const observable_type = $("#add_observable_type option:selected").text();
        var add_observable_input = document.getElementById("add_observable_value");
        var directives_multiselect = $("#add_observable_directives_multiselect");
        var directives_multiselect_container = $("#add_observable_directives_multiselect_container");
        var directives_text_container = $("#add_observable_directives_text_container");

        directives_multiselect.val([]);
        $("#add_observable_directives_text").val("");

        if (['email_address', 'user'].includes(observable_type)) {
            directives_multiselect_container.hide();
            directives_text_container.show();
        } else {
            directives_text_container.hide();
            directives_multiselect_container.show();
        }

        if (observable_type === 'file') {
            directives_multiselect.val(['sandbox']);
        }

        if (!['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation'].includes(observable_type)) {
            add_observable_input.parentNode.removeChild(add_observable_input);
            $("#add_observable_value_content").append(
                '<input type="text" class="form-control" id="add_observable_value" name="add_observable_value" value="" placeholder="Enter Value"/>'
            );
        } else {
            add_observable_input.parentNode.removeChild(add_observable_input);
            let placeholder_src = JSON.parse(window.localStorage.getItem("placeholder_src"));
            let placeholder_dst = JSON.parse(window.localStorage.getItem("placeholder_dst"));
            $("#add_observable_value_content").append(
                '<span id="add_observable_value">' +
                '<input class="form-control" type="text" name="add_observable_value_A" id="add_observable_value_A" value="" placeholder="' + placeholder_src[observable_type] + '"> to ' +
                '<input class="form-control" type="text" name="add_observable_value_B" id="add_observable_value_B" value="" placeholder="' + placeholder_dst[observable_type] + '">' +
                '</span>'
            );
        }
    });

    // Submit add observable form via fetch to FastAPI endpoint
    $("#add-observable-form").submit(function(e) {
        e.preventDefault();

        var all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to add observables to.");
            return;
        }

        var o_type = $("#add_observable_type").val();
        if (!o_type) {
            alert("You must select an observable type.");
            return;
        }

        // Build observable value (handle conversation types)
        var o_value;
        if (['email_conversation', 'email_delivery'].includes(o_type)) {
            var a = $("#add_observable_value_A").val();
            var b = $("#add_observable_value_B").val();
            o_value = a + '|' + b;
        } else if (o_type === 'ipv4_conversation') {
            o_value = $("#add_observable_value_A").val() + '_' + $("#add_observable_value_B").val();
        } else if (o_type === 'ipv4_full_conversation') {
            o_value = $("#add_observable_value_A").val() + ':' + $("#add_observable_value_B").val();
        } else {
            o_value = $("#add_observable_value").val();
        }

        if (!o_value) {
            alert("You must enter an observable value.");
            return;
        }

        // Collect directives
        var directives = $("#add_observable_directives_multiselect").val() || [];
        var directives_text = $("#add_observable_directives_text").val();
        if (directives_text) {
            directives = directives_text.split(',').map(function(d) { return d.trim(); }).filter(function(d) { return d !== ''; });
        }

        var payload = {
            alert_uuids: all_alert_uuids,
            observable_type: o_type,
            observable_value: o_value,
            observable_time: $("#add_observable_time").val() || null,
            directives: directives
        };

        // Close the modal
        $("#add_observable_modal").modal("hide");

        fetch('/api/v2/alerts/bulk-add-observable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            credentials: 'same-origin'
        })
        .then(function(resp) {
            if (!resp.ok) {
                return resp.json().then(function(data) {
                    throw new Error(data.detail || resp.statusText);
                });
            }
            return resp.json();
        })
        .then(function(data) {
            if (data.failed_count > 0) {
                var msg = 'Added observable to ' + data.success_count + ' alert(s). Failed on ' + data.failed_count + ' alert(s).';
                if (data.failed_details && Object.keys(data.failed_details).length > 0) {
                    msg += '\n\nFailure details:';
                    for (var uuid in data.failed_details) {
                        msg += '\n  ' + uuid + ': ' + data.failed_details[uuid];
                    }
                }
                alert(msg);
            }
            window.location.replace('/ace/manage');
        })
        .catch(function(err) {
            alert('Failed to add observable: ' + err.message);
        });
    });

    // --- End Add Observable modal handlers ---

    $("#alert-search-btn").click(function(e) {
        search_alerts();
    });

    $("#alert-search").on("keyup", function(e) {
        if (e.which === 13) {
            search_alerts();
        }
    });

    $("#alert-search").on("focus", function(e) {
        $(this).select();
    });
});

$(document).ready(function() {
    $('input[name="event_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="alert_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="ownership_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="disposition_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="contain_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="remediation_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    setup_daterange_pickers();

    $("#btn-take-ownership").click(function(e) {
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            alert("You must select one or more alerts to disposition.");
            return;
        }

        (function() {
            const params = new URLSearchParams();
            all_alert_uuids.forEach(function(uuid){ params.append('alert_uuids', uuid); });
            fetch('set_owner', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: params,
                credentials: 'same-origin'
            })
            .then(function(resp){
                if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
                window.location.replace('/ace/manage');
            })
            .catch(function(err){
                alert(err.message);
            });
        })();
    });

    $("#btn-assign-ownership").click(function(e) {
        all_alert_uuids = get_all_checked_alerts();
        if (all_alert_uuids.length == 0) {
            // XXX do this on the disposition button
            alert("You must select one or more alerts to assign to a user.");
            return;
        }

        // add a hidden field to the form and then submit
        $("#assign-ownership-form").append('<input type="hidden" name="alert_uuids" value="' + all_alert_uuids.join(",") + '" />').submit();
    });

    $('#btn-limit').click(function(e) {
        result = prompt("How many alerts should be displayed at once?", 50);
    });
});

function new_alert_observable_type_changed(index) {
  var type_input = document.getElementById("observables_types_" + index);
  var value_input = document.getElementById("observables_values_" + index);
  if (type_input.value == 'file') {
    if (value_input.type != 'file') {
      value_input.parentNode.removeChild(value_input);
      $('#new_alert_observable_value_' + index).append('<input class="form-control" type="file" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
    }
  } else if (value_input.type != 'text') {
    value_input.parentNode.removeChild(value_input);
    $('#new_alert_observable_value_' + index).append('<input class="form-control" type="text" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
  }
}

function new_alert_remove_observable(index) {
  var element = document.getElementById("new_alert_observable_" + index);
  element.parentNode.removeChild(element);
}

// gets called when the user clicks on an observable link
function observable_link_clicked(observable_id) {
    $("#frm-filter").append('<input type="checkbox" name="observable_' + observable_id + '" CHECKED>').submit();
}

// gets called when the user clicks on a tag link
function tag_link_clicked(tag_id) {
    $("#frm-filter").append('<input type="checkbox" name="tag_' + tag_id + '" CHECKED>').submit();
}

// reset all filters
function reset_filters() {
    (function() {
        fetch('reset_filters', { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// Applies one of the analyst's own saved filters as their persistent selection.
function select_filter(badge) {
    select_filter_by_uuid(badge.dataset.filterUuid);
}

function select_filter_by_uuid(filter_uuid) {
    (function() {
        fetch('select_filter/' + encodeURIComponent(filter_uuid), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// Discards a temporary filter and restores what the analyst was using before it. Navigates
// to a BARE /manage so a refresh cannot re-apply a share link they just dismissed.
function revert_temp_filter() {
    (function() {
        fetch('revert_temp_filter', { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

function compute_filter_settings() {
    filter_settings = [];
    filters = document.getElementsByName("filter_name");
    for (i = 0; i < filters.length; i++) {

        filter_name = filters[i].value;
        var filter_include = $("#" + filters[i].id.replace("filter_", "filter_include_"));
        filter_inverted = filter_include.val() != "include";
        filter_inputs = $("[name='" + filters[i].id + "_value_" + filter_name + "']");

        // is there already a filter with the same name and inverted value?
        var filter = null;
        for (index = 0; index < filter_settings.length; index++)
            if (filter_settings[index]["name"] == filter_name && filter_settings[index]["inverted"] == filter_inverted)
                filter = filter_settings[index];

        if (filter == null) {
            filter = {
                "name": filter_name,
                "inverted": filter_inverted,
                "values": []
            };
            filter_settings.push(filter);
        }

        if (filter_inputs.length == 1) {
            val = filter_inputs.val();
            if (Array.isArray(val)) {
                filter["values"] = filter["values"].concat(val);
            } else {
                filter["values"].push(val);
            }
        } else {
            val = [];
            filter_inputs.each(function(index) {
                val.push($(this).val());
            });
            filter["values"].push(val);
        }
    }

    return filter_settings;
}

// Applies the filter modal's contents to what the analyst is LOOKING at. It never writes
// to a saved filter -- persisting is always an explicit Save or Save as.
function apply_filter() {
    filter_settings = compute_filter_settings();
    (function() {
        // POST, not GET: a mutating GET with a JSON payload let any prefetch or link
        // scanner rewrite the analyst's filters.
        const body = new URLSearchParams({ filters: JSON.stringify(filter_settings) });
        fetch('set_filters', { method: 'POST', credentials: 'same-origin', body: body })
        .then(function(resp){
            // Surface a bad value instead of reloading into a broken page. An unparseable
            // date used to reach the session and then 500 /manage on every load until
            // someone reset the filters by hand.
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert(err.message);
        });
    })();

    return false; // prevents form from submitting
}

// removes a filter
function remove_filter(name, index) {
    (function() {
        const params = new URLSearchParams({ name: name, index: index });
        fetch('remove_filter?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// removes all filters of type name
function remove_filter_category(name) {
    (function() {
        const params = new URLSearchParams({ name: name });
        fetch('remove_filter_category?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// sets the sort order
function set_sort_filter(name) {
    (function() {
        const params = new URLSearchParams({ name: name });
        fetch('set_sort_filter?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// sets page offset
function set_page_offset(offset) {
    (function() {
        const params = new URLSearchParams({ offset: offset });
        fetch('set_page_offset?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// sets page size
function set_page_size(current_size) {
    limit = prompt("Page size", String(current_size));
    if (limit == null) return;
    err = function() {
        alert("error: enter an integer value between 1 and 1000");
    };

    try {
        limit = parseInt(limit);
    } catch (e) {
        alert(e);
        return;
    }

    if (limit < 1 || limit > 1000) {
        err();
        return;
    }

    (function() {
        const params = new URLSearchParams({ size: limit });
        fetch('set_page_size?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// hides/shows correct filter value input based on filter name selection
function on_filter_changed(filter_name) {
    filters = document.getElementsByName(filter_name.id + "_value_container");
    for (i = 0; i < filters.length; i++) {
        if (filters[i].id == filter_name.id + "_value_container_" + filter_name.value) {
            filters[i].style.display = "block";
        } else {
            filters[i].style.display = "none";
        }
    }
}

function removeElement(id) {
    var elem = document.getElementById(id);
    return elem.parentNode.removeChild(elem);
}

function removeElements(id_starts_with) {
    $('[id^="' + id_starts_with + '"]').remove();
}

// hides/shows correct input options
function toggle_options(input, options_id) {
    if (input.value.length > 1) {
        input.setAttribute('list', options_id)
    } else {
        input.setAttribute('list', null)
    }
}

function new_filter_option() {
  (function() {
    fetch('new_filter_option', { credentials: 'same-origin' })
    .then(function(resp){
      if (!resp.ok) { throw new Error(resp.statusText); }
      return resp.text();
    })
    .then(function(data){
      $('#filter_modal_body').append(data);
      setup_daterange_pickers()
    })
    .catch(function(err){
      alert('DOH: ' + err.message);
    });
  })();
}


// Switches one date filter row between the daterangepicker and a free-text relative token.
// The input's name and value shape are identical either way, so the DOM->JSON serializer
// (compute_filter_settings) needs no special case.
function toggle_date_mode(select) {
    var input = $(select).closest('.input-group').find('input');
    var hint = $(select).closest('.input-group').next('.relative-date-hint');

    if (select.value === 'relative') {
        if (input.data('daterangepicker')) { input.data('daterangepicker').remove(); }
        input.attr('data-relative', '1').removeClass('daterange').val('-24h');
        update_relative_date_hint(input[0]);
    } else {
        input.removeAttr('data-relative').addClass('daterange').val('');
        hint.text('');
        setup_daterange_pickers();
    }
}

// Shows what a relative token currently resolves to, so "-24h" is never opaque. Purely
// advisory -- the server is what actually parses the token.
function update_relative_date_hint(input) {
    var el = $(input);
    if (!el.attr('data-relative')) { return; }

    var hint = el.closest('.input-group').next('.relative-date-hint');
    var value = el.val().trim();
    if (value === '') { hint.text(''); return; }

    const params = new URLSearchParams({ value: value });
    fetch('resolve_date_range?' + params.toString(), { credentials: 'same-origin' })
    .then(function(resp){ return resp.ok ? resp.json() : { text: '' }; })
    .then(function(data){ hint.text(data.text || 'not a valid time range'); })
    .catch(function(){ hint.text(''); });
}

function toggle_include_exclude(filter_row_unique_id) {
    var button = $("#filter_include_" + filter_row_unique_id);
    var span = button.children()[0];
    if (button.val() == "include") {
        button.html('<span class="bi bi-dash-circle"></span> Exclude');
        button.val("exclude");
    } else {
        button.html('<span class="bi bi-plus-circle"></span> Include');
        button.val("include");
    }
}

// The share URL is self-describing and rendered server-side, so copying it needs no round
// trip. The link keeps working after this filter is edited or deleted.
function copy_filter_link(button) {
    copy_to_clipboard(button.dataset.shareUrl);
}

function copy_saved_filter_link(filter_uuid) {
    (function() {
        fetch('saved_filter_link/' + encodeURIComponent(filter_uuid), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            return resp.json();
        })
        .then(function(data){ copy_to_clipboard(data.url); })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

//
// saved filter management
//

function load_saved_filters_modal() {
    (function() {
        fetch('saved_filters_modal_body', { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            return resp.text();
        })
        .then(function(html){ document.getElementById('manage_filters_modal_body').innerHTML = html; })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

// What the pending save will persist. null means "save whatever is in effect" -- the
// temp-banner "Save a copy" path, which must never read the editor's DOM, since that DOM
// can still hold rows the analyst abandoned with Cancel.
var save_filter_payload = null;

// True while #filter_modal is being dismissed to hand off to #save_filter_modal, as opposed
// to being cancelled.
var editor_handoff = false;

// The server-rendered editor body, kept so Cancel can put it back. #filter_modal_body is
// rendered from effective_filters and only ever grows (new_filter_option appends), and the
// page reloads after every apply -- so this snapshot is always the applied filter.
var filter_editor_html = null;

// Called inline by every trigger that opens #save_filter_modal. It has to run on the
// trigger's own click rather than on the modal's show event: Bootstrap's dismiss/toggle
// chaining fires hidden.bs.modal on #filter_modal BEFORE show.bs.modal on
// #save_filter_modal, so a show-time snapshot would race the editor reset below.
function prepare_save(source) {
    editor_handoff = (source === 'editor');
    save_filter_payload = editor_handoff ? JSON.stringify(compute_filter_settings()) : null;
}

// Puts the editor back to the filter that is actually in effect, discarding rows the
// analyst built but never applied.
function reset_filter_editor() {
    if (filter_editor_html === null) { return; }

    // tear the pickers down before dropping their inputs, or they leak their popup divs
    // onto the body -- the same teardown toggle_date_mode() does
    $('#filter_modal_body .daterange').each(function() {
        if ($(this).data('daterangepicker')) { $(this).data('daterangepicker').remove(); }
    });

    document.getElementById('filter_modal_body').innerHTML = filter_editor_html;
    setup_daterange_pickers();
}

function save_filter_as() {
    const body = new URLSearchParams();
    body.append('name', document.getElementById('save_filter_name').value);
    body.append('description', document.getElementById('save_filter_description').value);
    if (document.getElementById('save_filter_quick').checked) { body.append('quick_filter', 'on'); }
    if (document.getElementById('save_filter_indicator').checked) { body.append('quick_filter_indicator', 'on'); }
    // Omitting the field is meaningful: it tells the server to save whatever is in effect,
    // which is the "Save a copy" path. See prepare_save().
    if (save_filter_payload !== null) { body.append('filters', save_filter_payload); }

    (function() {
        fetch('saved_filters', { method: 'POST', credentials: 'same-origin', body: body })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){ alert(err.message); });
    })();

    return false; // prevents form from submitting
}

// Overwrites the named filter currently selected with what is on screen. Reachable only
// from the Edit modal's footer, and it never dismisses that modal -- so it reads the editor
// unconditionally and needs no handoff snapshot.
function save_current_filter(filter_uuid) {
    const body = new URLSearchParams({ save_current: 'on',
                                       filters: JSON.stringify(compute_filter_settings()) });
    (function() {
        fetch('saved_filters/' + encodeURIComponent(filter_uuid), { method: 'POST', credentials: 'same-origin', body: body })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){ alert(err.message); });
    })();
}

function delete_saved_filter(filter_uuid, name) {
    if (!confirm('Delete the saved filter "' + name + '"?')) { return; }
    (function() {
        fetch('saved_filters/' + encodeURIComponent(filter_uuid) + '/delete',
              { method: 'POST', credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            load_saved_filters_modal();
        })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

// Reorder with up/down buttons rather than drag-and-drop: no library, and it is reachable
// from the keyboard.
function move_saved_filter(button, direction) {
    var row = button.closest('tr');
    var sibling = direction < 0 ? row.previousElementSibling : row.nextElementSibling;
    if (!sibling) { return; }
    if (direction < 0) { row.parentNode.insertBefore(row, sibling); }
    else { row.parentNode.insertBefore(sibling, row); }
}

function save_quick_filter_order() {
    const body = new URLSearchParams();
    document.querySelectorAll('#saved_filters_table tbody tr').forEach(function(row){
        if (row.querySelector('.quick-filter-pin').checked) {
            body.append('filter_uuids', row.dataset.filterUuid);
        }
    });

    (function() {
        fetch('saved_filters/quick', { method: 'POST', credentials: 'same-origin', body: body })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){ alert(err.message); });
    })();

    return false; // prevents form from submitting
}
