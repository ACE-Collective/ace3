// Alert Correlation Engine
//

function escape_html(unsafe) {
    if (unsafe === null)
        return 'null';

    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function copy_to_clipboard(str) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val(str).select();
    document.execCommand("copy");
    $temp.remove();
}

function hideSaveToEventButton() {
  document.getElementById("btn-save-to-event").style.display = 'none';
}

function showSaveToEventButton() {
  document.getElementById("btn-save-to-event").style.display = 'inline';
}

function showEventSaveButton() {
  document.getElementById("btn-add-to-event").style.display = "inline";
}

function toggleNewEventDialog() {
  if (document.getElementById("option_NEW").checked) {
    document.getElementById("new_event_dialog").style.display = 'block';
  }
  else {
    document.getElementById("new_event_dialog").style.display = 'none';
  }
}

function toggleNewCampaignInput() {
  if (document.getElementById("campaign_id").value == 'NEW') {
    document.getElementById("new_campaign").style.display = 'block';
  }
  else {
    document.getElementById("new_campaign").style.display = 'none';
  }
}

function new_malware_option() {
  var index = new Date().valueOf();
  (function() {
    const params = new URLSearchParams({ index: index });
    fetch('new_malware_option?' + params.toString(), { credentials: 'same-origin' })
      .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } return resp.text(); })
      .then(function(html){ $('#new_event_dialog').append(html); })
      .catch(function(err){ alert('DOH: ' + err.message); });
  })();
}

// This function is called from the "Send to.." modal dialog
$(document).on('click', '#btn-send-to-send', function() {
  // append the selected host to the formData
  var selectedHost = $("#selected-host").val()
  sendToDatastore.formData["hostname"] = selectedHost;

  // send a request to the API
  (function() {
      var params = new URLSearchParams();
      Object.keys(sendToDatastore.formData || {}).forEach(function(key){
        var value = sendToDatastore.formData[key];
        if (Array.isArray(value)) {
          value.forEach(function(v){ params.append(key + '[]', v); });
        } else if (value !== undefined && value !== null) {
          params.append(key, value);
        }
      });
      fetch(sendToDatastore.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        body: params,
        credentials: 'same-origin'
      })
      .then(function(resp){
        return resp.text().then(function(text){
          if (!resp.ok) { throw new Error(text || resp.statusText); }
          return text;
        });
      })
      .then(function(text){
        alert('Sending file to ' + selectedHost + ' at ' + text);
      })
      .catch(function(err){
        alert('DOH: ' + err.message);
      })
      .finally(function(){
        $('#send-to-modal').modal('hide');
      });
  })();
});

// This function is called from the "Send alert to.." modal dialog
$(document).on('click', '#btn-send-alert-to-send', function() {
  // append the selected host to the formData
  var selectedHost = $("#alert-selected-host").val()

  data = {
    "remote_host": selectedHost,
    "alert_uuid": $("input[name=alert_uuid]").val(),
  }
  
  // send a request to the API
  (function() {
    fetch('send_alert_to', {
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
      alert('Sending alert to ' + selectedHost + ' at ' + text);
    })
    .catch(function(err){
      alert('DOH: ' + err.message);
    })
    .finally(function(){
      $('#send-alert-to-modal').modal('hide');
    });
  })();
});

function remove_malware_option(index) {
  var element = document.getElementById("malware_option_" + index);
  element.parentNode.removeChild(element);
}

function malware_selection_changed(index) {
  var element = document.getElementById("malware_selection_" + index);
  if (element.value == 'NEW') {
    document.getElementById("new_malware_info_" + index).style.display = 'block';
  }
  else {
    document.getElementById("new_malware_info_" + index).style.display = 'none';
  }
}

let placeholder_src = {
    "email_conversation": "Sender@example.com",
    "email_delivery": "<Message-ID>",
    "ipv4_conversation": "ex. 1.1.1.1",
    "ipv4_full_conversation": "ex. 1.1.1.1:1010",
    "file_location": "hostname"
};
let placeholder_dst = {
    "email_conversation": "Recipient@example.com",
    "email_delivery": "Recipient@example.com",
    "ipv4_conversation": "ex. 2.2.2.2",
    "ipv4_full_conversation": "ex. 2.2.2.2:2020",
    "file_location": "full path"
};

window.localStorage.setItem('placeholder_src', JSON.stringify(placeholder_src));
window.localStorage.setItem('placeholder_dst', JSON.stringify(placeholder_dst));

function toggle_chevron(element_id) {
    let element_class = document.getElementById(element_id).className;
    if (element_class == "bi bi-chevron-right") {
        document.getElementById(element_id).className = "bi bi-chevron-down";
    } else {
        document.getElementById(element_id).className = "bi bi-chevron-right";
    }
}

function toggle(element_id) {
    $("[id='"+element_id+"']").toggle()
}

function toggle_checkboxes(cb, name) {
    $("[name='"+name+"']").prop("checked", cb.checked)
}

// maek call to /alert_uuid/event_name_candidate to grab the correct event_name for selected alert
// then on succsessful return, fill in the event name field in the modal
function grab_and_fill_event_name(alert_uuid) {
    (function() {
        const params = new URLSearchParams({ alert_uuid: alert_uuid });
        fetch(`${alert_uuid}/event_name_candidate?` + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } return resp.text(); })
        .then(function(text){ document.getElementById('event_name').value = text; })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

// selects the best choice of event name from a list of alert uuids selected on /manage view
// grabs list of all checked alerts
// iterates through list to find the oldest alert with status == "Complete"
function select_event_name_candidate_from_manage_view() {
    let earliest_alert_uuid = "";
    let checked_alert_uuids = get_all_checked_alerts();

    // initialize base variable
    let earliest_date = Date()

    // compare all alert dates to find earliest alert
    checked_alert_uuids.forEach(function (checked_alert_uuid) {

        // only consider alert event name candidates that have finished analyzing
        let alert_analysis_status = document.getElementById(`alert_status_${checked_alert_uuid}`).innerHTML
        if (alert_analysis_status !== "Completed") return;

        let checked_alert_date = new Date(document.getElementById(`alert_date_${checked_alert_uuid}`).title);
        // base case -- set first 'earliest_date' with first date we check
        // do this instead of initializing earliest_date with .now() to avoid browser TZ conflicts
        if (earliest_alert_uuid === "") {
            earliest_date = checked_alert_date
            earliest_alert_uuid = checked_alert_uuid;
        }
        // subsequent comparisons
        else {
            if (checked_alert_date < earliest_date) {
                earliest_date = checked_alert_date
                earliest_alert_uuid = checked_alert_uuid;
            }
        }
    });

    return earliest_alert_uuid;
}

// Selects and grabs event_name_candidate from single or list of alerts (based on current path)
// and autofills the Name field in Add to Event modal
function autofill_event_name() {
    let earliest_alert_uuid = "";
    let path = window.location.pathname

    if (path.includes('/manage')) {
        earliest_alert_uuid = select_event_name_candidate_from_manage_view();
    }
    else if (path.includes('/analysis')) {
        earliest_alert_uuid = $("#alert_uuid").prop("value");
    }

    // name field should be empty if we couldn't grab the right uuid
    if (earliest_alert_uuid === "") {
        document.getElementById('event_name').value = ""
    }
    else {
        grab_and_fill_event_name(earliest_alert_uuid);
    }
}

// Load more closed events in 'Add to Event' modal
// Calls to load_more_events endpoint, which returns next x number of closed events to display
function loadMoreClosedEvents() {
  var event_tab = document.getElementById("closed-events");
  var count = event_tab.childElementCount
  (function() {
    const params = new URLSearchParams({ count: count - 1 });
    fetch('load_more_events?' + params.toString(), { credentials: 'same-origin' })
      .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } return resp.text(); })
      .then(function(html){
        $('#closed-events').append(html);
        var load_button = document.getElementById('load-more-events-btn');
        if (load_button && load_button.parentNode) {
          load_button.parentNode.removeChild(load_button);
        }
      })
      .catch(function(err){ alert('DOH: ' + err.message); });
  })();
}
