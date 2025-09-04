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
    $('.daterange').each(function(index) {
        if ($(this).val() == '') {
            $(this).val(
                moment().subtract(6, "days").startOf('day').format("MM-DD-YYYY HH:mm") + ' - ' +
                moment().format("MM-DD-YYYY HH:mm"));
        }
    });

    $('.daterange').daterangepicker({
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

$(document).ready(function() {

    document.getElementById("event_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("alert_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("ownership_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("disposition_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("contain_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("remediation_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");

    $("#master_checkbox").change(function(e) {
        $("input[name^='detail_']").prop('checked', $("#master_checkbox").prop('checked'));
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

// special filtering capabilities per Mandy's request

function set_special_filter_24_hours() {
    (function() {
        const params = new URLSearchParams({ hours: 24 });
        fetch('reset_filters_special?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

function set_special_filter_7_days() {
    (function() {
        const params = new URLSearchParams({ hours: 7 * 24 });
        fetch('reset_filters_special?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
}

// adds a filter
function add_filter(name, values) {
    (function() {
        const params = new URLSearchParams({ filter: JSON.stringify({ name: name, values: values }) });
        fetch('add_filter?' + params.toString(), { credentials: 'same-origin' })
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

// adds selected filter from filter modal
function apply_filter() {
    filter_settings = compute_filter_settings();
    (function() {
        const params = new URLSearchParams({ filters: JSON.stringify(filter_settings) });
        fetch('set_filters?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            window.location.replace('/ace/manage');
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
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

// gets called when the user clicks on the right triangle button next to each alert
// this loads the observable information for the alerts and allows the user to select one for filtering
function load_alert_observables(alert_uuid) {
    // have we already loaded this?
    var existing_dom_element = $("#alert_observables_" + alert_uuid);
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
        return;
    }

    (function() {
        const params = new URLSearchParams({ alert_uuid: alert_uuid });
        fetch('observables?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            return resp.text();
        })
        .then(function(data){
            $('#alert_row_' + alert_uuid).after('<tr id="alert_observables_' + alert_uuid + '"><td colspan="6">' + data);
        })
        .catch(function(err){
            alert('DOH: ' + err.message);
        });
    })();
    
}

function toggle_chevron(alert_row_id) {
    let button_state = document.getElementById(alert_row_id).className;
    if (button_state == "bi bi-chevron-down") {
        document.getElementById(alert_row_id).className = "bi bi-chevron-up";
    } else {
        document.getElementById(alert_row_id).className = "bi bi-chevron-down";
    }
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

function copy_filter_link(url) {
    var filter_settings = compute_filter_settings();
    copy_to_clipboard("https://" + window.location.host + url + "?redirect=1&filters=" + encodeURIComponent(JSON.stringify(filter_settings)));
}
