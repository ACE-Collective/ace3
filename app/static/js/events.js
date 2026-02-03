$(document).ready(function() {
    $(".related-observable").click(function (e) {
        // Get the checked/unchecked state
        const checked_state = $(e.target).is(":checked");

        // Get the id of the related observable
        const related_id = $(e.target).attr('data-related-id');

        // Loop over each observable to find the ones with the same data-related value and set their checked state
        // to the same as the observable that was just clicked.
        $("input[name^='observable_']").each(function() {
            const $this = $(this);
            if ($this.attr('data-related-id') === related_id) {
                $this.prop("checked", checked_state);
            }
        });
    });
});

function get_all_checked_events() {
    // returns the list of all checked event IDs
    var result = Array();
    $("input[name^='event_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^event_/, ""));
        }
    });

    return result;
}

function get_current_event_id() {
    // assumes you're on a single event page & returns the ID of that event
    let current_event = $('.event-container')[0];
    if (current_event) {
        return current_event.id;
    }
    return '';
}

function export_events_to_csv() {
    // makes request to export selected events to CSV
    // and downloads .csv from response
    let checked_events = get_all_checked_events();

    (function() {
        const params = new URLSearchParams();
        // mimic jQuery default array serialization: checked_events[]
        checked_events.forEach(function(id){ params.append('checked_events[]', id); });
        fetch('export_events_to_csv?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            return resp.text();
        })
        .then(function(text){
            let blob = new Blob([text], { type: 'text/csv' });
            let link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = 'export.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        })
        .catch(function(err){
            alert('ERROR: ' + err.message);
        });
    })();
}

function get_all_checked_observables() {
    // returns the list of all checked observable IDs
    var result = Array();
    $("input[name^='observable_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^observable_/, ""));
        }
    });

    return result;
}

function get_all_unchecked_observables() {
    // returns the list of all unchecked observable IDs
    var result = Array();
    $("input[name^='observable_']").each(function(index) {
        var $this = $(this);
        if (!$this.is(":checked")){
            result.push($this.prop("name").replace(/^observable_/, ""));
        }
    });

    return result;
}

function toggle_all_low_faqueue_hit_observables(low_hits) {
    $("td[id^='faqueue_hits_']").each(function(index) {
        var $this = $(this);
        if (parseInt($this.text()) < parseInt(low_hits)){

            // Strip off the observable ID number
            var id = $this.prop("id").replace(/^faqueue_hits_/, "")

            // Toggle the checkbox
            var corresponding_checkbox = $("#observable_"+id);
            var current_checkbox_state = corresponding_checkbox.prop("checked");
            corresponding_checkbox.prop("checked", !current_checkbox_state);
        }
    });
}

function toggle_max_hit_observables_visible() {
    let max_hit_observables = $( ".max-hit-observable" );
    let toggle_max_hits_text = $( "#toggle_max_hit_observables_visible" );
    if (max_hit_observables.is(":visible")) {
        max_hit_observables.hide();
        toggle_max_hits_text.text("Show Max Hits");
    }
    else {
        max_hit_observables.show();
        toggle_max_hits_text.text("Hide Max Hits");
    }

}

function set_observable_detection_status() {
    var checked = get_all_checked_observables();
    var unchecked = get_all_unchecked_observables();

    var data_obj = {enabled: checked, disabled: unchecked};

    (function() {
        fetch('set_observables_detection_status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data_obj),
            credentials: 'same-origin'
        })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

function close_event() {
    if (! confirm("Did you review the observables?")) {
        return;
    }

    set_observable_detection_status();

    (function() {
        fetch('close_event', { method: 'POST', credentials: 'same-origin' })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } })
        .then(function(){ alert('Event is closed. Uploading data to TIP in the background.'); })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

function update_event_status_message(message) {
    $("#event_closure_status").text(message);
}

function add_indicators_to_event_in_tip(event_id) {
    (function() {
        const params = new URLSearchParams({ event_id: event_id });
        fetch('add_indicators_to_event_in_tip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
            body: params,
            credentials: 'same-origin'
        })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } })
        .then(function(){ alert('Uploading data to TIP in the background.'); })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

function create_event_in_tip(event_id) {
    (function() {
        const params = new URLSearchParams({ event_id: event_id });
        fetch('create_event_in_tip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
            body: params,
            credentials: 'same-origin'
        })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } })
        .then(function(){ alert('Created event in TIP'); })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

function load_event_alerts(event_id) {
    // have we already loaded this?
    var existing_dom_element = $("#event_alerts_" + event_id);
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
        return;
    }

    (function() {
        const params = new URLSearchParams({ event_id: event_id });
        fetch('manage_event_details?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } return resp.text(); })
        .then(function(html){ $('#event_row_' + event_id).after(html); })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

function get_all_checked_event_mappings() {
    // returns the list of all checked event_alet mappings
    var result = Array();
    $("input[name^='detail_']").each(function(index) {
        var $this = $(this);
        if ($this.is(":checked")){
            result.push($this.prop("name").replace(/^detail_/, ""));
        } 
    });

    return result;
}

function edit_event(event_id) {
    // have we already loaded this?
    var existing_dom_element = $("#new_event_dialog");
    if (existing_dom_element.length != 0) {
        existing_dom_element.remove();
    }

    $.ajax({
        dataType: "html",
        url: 'edit_event_modal',
        data: { event_id: event_id },
        success: function(data, textStatus, jqXHR) {
            $('#edit_event_body_container').html(data);
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
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH: " + textStatus);
        }
    });

    $("#edit_event_modal").modal("show");
}

function add_filter(tag) {
    // Adds a tag filter to events page for a single given tag
    let filter_form = $('#frm-filter');
    let tag_filter_form_input = $('#filter_event_tag');
    tag_filter_form_input.empty();
    tag_filter_form_input.append(`<option value="${tag}" SELECTED> ${tag} </option>`);
    filter_form.submit();
}

// This function is called from the "Send event to.." modal dialog
$(document).on('click', '#btn-send-event-to-send', function() {
    // append the selected host to the formData
    var selectedHost = $("#event-selected-host").val()
  
    data = {
      "remote_host": selectedHost,
      "event_uuid": $("input[name=event_uuid]").val(),
    }
    
    // send a request to the API
    (function() {
      fetch('send_event_to', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
        credentials: 'same-origin'
      })
      .then(function(resp){
        return resp.text().then(function(text){
          if (!resp.ok) { throw new Error(text || resp.statusText); }
          return text;
        });
      })
      .then(function(text){
        alert('Sending event to ' + selectedHost + ' at ' + text);
      })
      .catch(function(err){
        alert('DOH: ' + err.message);
      })
      .finally(function(){
        $('#send-event-to-modal').modal('hide');
      });
    })();
  });

$(document).ready(function() {
    $('input[name="event_daterange"]').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(6, 'days').startOf('day'),
        endDate: moment(),
        ranges: {
           'Today': [moment().startOf('day'), moment().endOf('day')],
           'Yesterday': [moment().subtract(1, 'days').startOf('day'), moment().subtract(1, 'days').endOf('day')],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'This Month': [moment().startOf('month').startOf('day'), moment()],
           'Last Month': [moment().subtract(1, 'month').startOf('month').startOf('day'), moment().subtract(1, 'month').endOf('month').endOf('day')]
        }
    });

    $("#btn-remove-alerts").click(function(e) {
        // compile a list of all the alerts that are checked
        mappings = get_all_checked_event_mappings();
        if (mappings.length == 0) {
            alert("You must select one or more alerts to remove.");
            return;
        }

        // add mappings to the form and submit
        $("#remove-alerts-form").append('<input type="hidden" name="event_mappings" value="' + mappings.join(",") + '" />').submit();
    });

    $("#btn-reset-filters").click(function(e) {
        $("#frm-filter").append('<input type="hidden" name="reset-filters" value="1">').submit();
    });

    // add event handlers to the column headers to trigger column sorting
    $("span[id^='sort_by_']").each(function(index) {
        var $this = $(this);
        $this.click(function(e) {
            sort_field = this.id.replace(/^sort_by_/, "");
            $("#frm-filter").append('<input type="hidden" name="sort_field" value="' + sort_field + '">');
            $("#frm-filter").submit();
        });
    });

    $(".event-cell").click(function () {
        let checked_events = (get_all_checked_events().length > 0)
        if(checked_events){
            $('#btn-export-events').show();
            $('#btn-show-add-event-tags').show();
        } else {
            $('#btn-export-events').hide();
            $('#btn-show-add-event-tags').hide();
        }
    });

    $("#master_checkbox").click(function () {
        $(".eventCheckbox").prop('checked', $(this).prop('checked'));
    });

    $("#btn-submit-event-tags").click(function(e) {
        $("#event-tag-form").submit();
    });

    $("#btn-create-event").click(function(e) {
        // Pre-select "New Event" radio option
        $("#option_NEW").prop("checked", true);
        // Show the new event dialog fields
        $("#new_event_dialog").show();
        // Show the save button
        $("#btn-add-to-event").show();
        // Clear any previous event name/comment
        $("#event_name").val("");
        $("#event_comment").val("");
        // Add hidden field to redirect back to events page after creation
        if ($("#event-form input[name='redirect_to']").length === 0) {
            $("#event-form").append('<input type="hidden" name="redirect_to" value="events_manage" />');
        }
    });

    // Clean up redirect_to field when event modal is closed
    $("#event_modal").on("hidden.bs.modal", function() {
        $("#event-form input[name='redirect_to']").remove();
    });

    $("#event-tag-form").submit(function(e) {
        let event_form = $("#event-tag-form");
        let current_page = $("#btn-show-add-event-tags").data("page");

        if (current_page === 'management') {
            let event_ids = get_all_checked_events();
            event_form.append('<input type="hidden" name="ids" value="' + event_ids.join(",") + '" />');
            event_form.append('<input type="hidden" name="redirect" value="management" />');
        }
        else {
            let event_id = get_current_event_id();
            event_form.append('<input type="hidden" name="ids" value="' + event_id + '" />');
            event_form.append('<input type="hidden" name="redirect" value="analysis" />');
        }
    });
});
