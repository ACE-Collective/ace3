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

/**
 * Renders JSON data as a collapsible tree structure in the specified container.
 * All nested objects/arrays start collapsed by default, showing only top-level keys.
 *
 * @param {any} data - The JSON data to render (object, array, or primitive)
 * @param {HTMLElement|string} container - The container element or its ID
 * @param {Object} options - Optional configuration
 * @param {boolean} options.collapsed - Whether to start collapsed (default: true)
 * @param {string} options.emptyMessage - Message to show when data is empty (default: 'No data available')
 */
function renderJsonTree(data, container, options) {
    options = options || {};
    var startCollapsed = options.collapsed !== false;
    var emptyMessage = options.emptyMessage || 'No data available';

    var targetElement = typeof container === 'string'
        ? document.getElementById(container)
        : container;

    if (!targetElement) {
        console.error('renderJsonTree: container not found');
        return;
    }

    function renderValue(value) {
        if (value === null) {
            return '<span style="color: #999;">null</span>';
        } else if (typeof value === 'boolean') {
            return '<span style="color: #0d6efd;">' + value + '</span>';
        } else if (typeof value === 'number') {
            return '<span style="color: #198754;">' + value + '</span>';
        } else if (typeof value === 'string') {
            return '<span style="color: #6c757d;">"' + escape_html(value) + '"</span>';
        }
        return escape_html(String(value));
    }

    function isExpandable(value) {
        return value !== null && typeof value === 'object';
    }

    function renderNode(key, value, collapsed) {
        var li = document.createElement('li');
        li.style.listStyleType = 'none';
        li.style.marginTop = '2px';

        if (isExpandable(value)) {
            var isArray = Array.isArray(value);
            var childCount = isArray ? value.length : Object.keys(value).length;
            var bracket = isArray ? '[' : '{';
            var closeBracket = isArray ? ']' : '}';

            var toggle = document.createElement('i');
            toggle.className = collapsed ? 'bi bi-chevron-right' : 'bi bi-chevron-down';
            toggle.style.cursor = 'pointer';
            toggle.style.marginRight = '4px';
            toggle.style.fontSize = '0.8em';

            var keySpan = document.createElement('span');
            keySpan.style.fontWeight = 'bold';
            keySpan.style.color = '#0d6efd';
            keySpan.style.cursor = 'pointer';
            keySpan.textContent = key !== null ? key + ': ' : '';

            var preview = document.createElement('span');
            preview.style.color = '#999';
            preview.textContent = bracket + childCount + ' item' + (childCount !== 1 ? 's' : '') + closeBracket;

            var childUl = document.createElement('ul');
            childUl.style.marginLeft = '20px';
            childUl.style.paddingLeft = '0';
            childUl.style.display = collapsed ? 'none' : 'block';

            if (isArray) {
                value.forEach(function(item, index) {
                    childUl.appendChild(renderNode(index, item, true));
                });
            } else {
                Object.keys(value).forEach(function(k) {
                    childUl.appendChild(renderNode(k, value[k], true));
                });
            }

            function toggleNode() {
                if (childUl.style.display === 'none') {
                    childUl.style.display = 'block';
                    toggle.className = 'bi bi-chevron-down';
                } else {
                    childUl.style.display = 'none';
                    toggle.className = 'bi bi-chevron-right';
                }
            }

            toggle.addEventListener('click', toggleNode);
            keySpan.addEventListener('click', toggleNode);

            li.appendChild(toggle);
            li.appendChild(keySpan);
            li.appendChild(preview);
            li.appendChild(childUl);
        } else {
            var bullet = document.createElement('span');
            bullet.innerHTML = '&bull; ';
            bullet.style.marginRight = '4px';
            bullet.style.color = '#999';

            var keySpan = document.createElement('span');
            keySpan.style.fontWeight = 'bold';
            keySpan.style.color = '#0d6efd';
            keySpan.textContent = key !== null ? key + ': ' : '';

            var valueSpan = document.createElement('span');
            valueSpan.innerHTML = renderValue(value);

            li.appendChild(bullet);
            li.appendChild(keySpan);
            li.appendChild(valueSpan);
        }

        return li;
    }

    // Check for empty data
    var isEmpty = data === null || data === undefined ||
        (Array.isArray(data) && data.length === 0) ||
        (typeof data === 'object' && Object.keys(data).length === 0);

    if (isEmpty) {
        targetElement.innerHTML = '<em>' + escape_html(emptyMessage) + '</em>';
        return;
    }

    var ul = document.createElement('ul');
    ul.style.paddingLeft = '0';
    ul.style.marginBottom = '0';

    if (Array.isArray(data)) {
        data.forEach(function(item, index) {
            ul.appendChild(renderNode('Event ' + (index + 1), item, startCollapsed));
        });
    } else if (typeof data === 'object' && data !== null) {
        Object.keys(data).forEach(function(key) {
            ul.appendChild(renderNode(key, data[key], startCollapsed));
        });
    } else {
        var li = document.createElement('li');
        li.innerHTML = renderValue(data);
        ul.appendChild(li);
    }

    targetElement.appendChild(ul);
}
