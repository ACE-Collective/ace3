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

// Legacy fallback for browsers/contexts without the async Clipboard API.
//
// The temp input is appended INSIDE the open modal (when there is one) rather than to <body>:
// Bootstrap's modal focus trap steals focus back from any element outside the modal, which clears
// the selection before execCommand runs. execCommand still returns true in that case, so it fails
// silently and copies nothing.
function _copy_to_clipboard_fallback(str) {
    var host = document.querySelector(".modal.show") || document.body;
    var temp = document.createElement("input");
    temp.value = str;
    temp.setAttribute("readonly", "");
    temp.style.position = "absolute";
    temp.style.left = "-9999px";
    host.appendChild(temp);
    temp.select();

    var copied = false;
    try {
        // guard against the silent-success case above
        copied = document.execCommand("copy") && window.getSelection().toString().length > 0;
    } catch (e) {
        copied = false;
    }
    temp.remove();
    return copied;
}

// Returns a Promise that resolves when the text is on the clipboard, and rejects if it could not
// be copied. Callers that don't care may ignore the return value.
function copy_to_clipboard(str) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(str).catch(function() {
            return _copy_to_clipboard_fallback(str)
                ? Promise.resolve()
                : Promise.reject(new Error("unable to copy to clipboard"));
        });
    }
    return _copy_to_clipboard_fallback(str)
        ? Promise.resolve()
        : Promise.reject(new Error("unable to copy to clipboard"));
}

// Expanded observable content keyed by alert uuid. Pages that morph the alert table
// (the manage alerts page) re-inject the expansion rows from this after each refresh,
// because the morph removes client-injected rows that are not in the server response --
// see restore_alert_observables() in manage_alerts.js.
const expanded_alert_observables = new Map();

// Expands or collapses the observable list under an alert row. Shared by every page that renders a
// table of alerts: the manage alerts page, the event page, and the event list expandable row.
//
// The row is located by traversing up from the button rather than by element id: on the event list
// an alert mapped to two expanded events appears twice in the same DOM, so ids are not unique.
function toggle_alert_observables(button, alert_uuid, observables_url) {
    const row = $(button).closest("tr");
    const icon = $(button).find("span.bi");
    const existing = row.next(".alert-observables-row");

    if (existing.length != 0) {
        existing.remove();
        expanded_alert_observables.delete(alert_uuid);
        icon.removeClass("bi-chevron-up").addClass("bi-chevron-down");
        return;
    }

    const params = new URLSearchParams({ alert_uuid: alert_uuid });
    fetch(observables_url + "?" + params.toString(), { credentials: "same-origin" })
    .then(function(resp){
        if (!resp.ok) { throw new Error(resp.statusText); }
        return resp.text();
    })
    .then(function(data){
        // data-ignore stops Datastar from processing the fetched observable HTML
        row.after('<tr class="alert-observables-row" data-ignore><td colspan="' + row.children("td").length + '">' + data + '</td></tr>');
        expanded_alert_observables.set(alert_uuid, data);
        icon.removeClass("bi-chevron-down").addClass("bi-chevron-up");
    })
    .catch(function(err){
        alert('DOH: ' + err.message);
    });
}

// Pivots the alert list to a TEMPORARY filter, leaving whatever filter the analyst was
// already using untouched and one click away. This is the whole point of the temporary
// filter: clicking an observable from an alert used to overwrite their filter set outright,
// losing however long they had spent building it.
//
// With overlay set, the filters are laid over the one in effect instead of replacing it --
// see overlay_temporary_filter() in app/analysis/views/session/filters.py.
//
// Lives in ace.js because the templates that call it render under more than one blueprint,
// so the urls have to be passed in.
function apply_temp_filter(filters, label, apply_url, manage_url, overlay) {
    const body = new URLSearchParams({ filters: JSON.stringify(filters), label: label });
    if (overlay) {
        body.set("overlay", "on");
    }
    fetch(apply_url, { method: "POST", credentials: "same-origin", body: body })
    .then(function(resp){
        if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
        window.location.replace(manage_url);
    })
    .catch(function(err){
        alert(err.message);
    });
}

// A click in the observable list under an alert row. On the alert management page it is
// overlaid on the filter in effect: the analyst is working that list and wants the part of
// it that shares this observable. The event pages render the same list with no filter of
// their own to narrow, so there it replaces the filter like a pivot from inside an alert.
// A page opts in with a data-pivot-overlay attribute around its alert table.
function add_observable_filter(element, observable_type, observable_value, apply_url, manage_url) {
    const overlay = $(element).closest("[data-pivot-overlay]").length > 0;
    apply_temp_filter(
        [{ name: "Observable", inverted: false, values: [[observable_type, observable_value]] }],
        "Observable " + observable_type + ":" + observable_value,
        apply_url, manage_url, overlay);
}

// API keys are display-once (revealed at creation, never recoverable), so there is no nav-bar
// "Copy API Key" action. A user manages their own keys on Preferences (with user:self); an admin
// manages anyone's on Admin > Users.

// Puts a small yellow dot on the browser tab's favicon when the current user has alerts
// waiting in their default queue -- the same open-or-mine-in-my-queue alerts the "Reset"
// filter on the alert management page shows. Only that page's favicon link carries the
// poll URL (see base.html), so this is a no-op everywhere else in the GUI -- an analyst
// investigating an alert or looking at events won't trigger any polling.
$(document).ready(function() {
    var favicon = document.getElementById("favicon");
    var count_url = favicon ? favicon.getAttribute("data-reset-filter-count-url") : null;
    if (!favicon || !count_url) {
        return;
    }

    // follows the alert management page's auto-refresh cadence; the server substitutes
    // 30s when that refresh is disabled (see the FAVICON_POLL_SECONDS context processor)
    var POLL_INTERVAL_MS = (parseInt(favicon.getAttribute("data-poll-seconds"), 10) || 30) * 1000;

    var plain_href = favicon.getAttribute("href");
    var plain_type = favicon.getAttribute("type");
    var dot_href = null;
    var dot_shown = false; // whether the dot is actually applied to the favicon right now
    var dot_wanted = false; // the most recently polled desired state

    function apply_dot_favicon(data_url) {
        dot_href = data_url;
        favicon.setAttribute("type", "image/png");
        favicon.setAttribute("href", dot_href);
    }

    // Draws the plain favicon onto a canvas, adds a dot in the corner, and hands the
    // resulting PNG data URL to callback. The SVG favicon can't have a dot appended to its
    // markup here since it's loaded from a separate static file, so this rasterizes it.
    function build_dot_favicon(callback) {
        var img = new Image();
        img.onload = function() {
            var size = 64;
            var canvas = document.createElement("canvas");
            canvas.width = size;
            canvas.height = size;
            var ctx = canvas.getContext("2d");
            ctx.drawImage(img, 0, 0, size, size);
            ctx.beginPath();
            ctx.arc(size - 11, 11, 11, 0, 2 * Math.PI);
            ctx.fillStyle = "#ffc107";
            ctx.fill();
            ctx.lineWidth = 2;
            ctx.strokeStyle = "#ffffff";
            ctx.stroke();
            callback(canvas.toDataURL("image/png"));
        };
        img.onerror = function() { callback(null); };
        img.src = plain_href;
    }

    function show_dot(show) {
        dot_wanted = show;
        if (show === dot_shown) {
            return;
        }

        if (!show) {
            dot_shown = false;
            favicon.setAttribute("type", plain_type);
            favicon.setAttribute("href", plain_href);
            return;
        }

        if (dot_href) {
            dot_shown = true;
            apply_dot_favicon(dot_href);
            return;
        }

        build_dot_favicon(function(data_url) {
            // dot_shown is only flipped once the dot is actually applied, so a failed
            // rasterization (data_url null) leaves it false and the next poll retries
            // instead of assuming the dot is already showing
            if (data_url && dot_wanted && !dot_shown) {
                dot_shown = true;
                apply_dot_favicon(data_url);
            }
        });
    }

    function poll() {
        // an expired session is a 401 from the API, which clears the dot rather than leaving
        // it stale
        fetch(count_url, { credentials: "same-origin" })
            .then(function(resp) {
                if (!resp.ok) {
                    show_dot(false);
                    return null;
                }
                return resp.json();
            })
            .then(function(data) {
                if (data) {
                    show_dot(data.count > 0);
                }
            })
            .catch(function() { show_dot(false); });
    }

    poll();
    setInterval(poll, POLL_INTERVAL_MS);
});


// the button is currently commented out of the disposition modal, but the disposition
// radio onclick handlers still call these
function hideSaveToEventButton() {
  const button = document.getElementById("btn-save-to-event");
  if (button) {
    button.style.display = 'none';
  }
}

function showSaveToEventButton() {
  const button = document.getElementById("btn-save-to-event");
  if (button) {
    button.style.display = 'inline';
  }
}

// shows or hides the corrected-disposition section of the review modal based on the review result
function toggle_review_incorrect(show) {
  const section = document.getElementById("review_incorrect_section");
  if (section) {
    section.style.display = show ? 'flex' : 'none';
  }
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

function toggle(element_id) {
    $("[id='"+element_id+"']").toggle()
}

function toggle_checkboxes(cb, name) {
    $("[name='"+name+"']").prop("checked", cb.checked)
}

// Load more closed events in 'Add to Event' modal
// Calls to load_more_events endpoint, which returns next x number of closed events to display
function loadMoreClosedEvents(button) {
  const event_tab = document.getElementById("closed-events");
  // the container holds one div per event plus the "Show more..." button
  const params = new URLSearchParams({ count: event_tab.childElementCount - 1 });
  const url = button.dataset.url;

  // drop the stale button first so the appended fragment's button is the only one
  button.remove();

  fetch(url + '?' + params.toString(), { credentials: 'same-origin' })
    .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } return resp.text(); })
    .then(function(html){ $('#closed-events').append(html); })
    .catch(function(err){ alert('DOH: ' + err.message); });
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
 * @param {boolean} options.useArrayIndexAsKey - When the top-level value is an array, label items by their numeric index ("0", "1"...) instead of "Event N". Default false to preserve the splunk events label.
 */
function renderJsonTree(data, container, options) {
    options = options || {};
    var startCollapsed = options.collapsed !== false;
    var emptyMessage = options.emptyMessage || 'No data available';
    var useArrayIndexAsKey = options.useArrayIndexAsKey === true;

    var targetElement = typeof container === 'string'
        ? document.getElementById(container)
        : container;

    if (!targetElement) {
        console.error('renderJsonTree: container not found');
        return;
    }

    function renderValue(value) {
        if (value === null) {
            return '<span class="json-muted">null</span>';
        } else if (typeof value === 'boolean') {
            return '<span class="json-boolean">' + value + '</span>';
        } else if (typeof value === 'number') {
            return '<span class="json-number">' + value + '</span>';
        } else if (typeof value === 'string') {
            return '<span class="json-string">"' + escape_html(value) + '"</span>';
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
            keySpan.className = 'json-key';
            keySpan.style.cursor = 'pointer';
            keySpan.textContent = key !== null ? key + ': ' : '';

            var preview = document.createElement('span');
            preview.className = 'json-muted';
            preview.textContent = bracket + childCount + ' item' + (childCount !== 1 ? 's' : '') + closeBracket;

            var childUl = document.createElement('ul');
            childUl.style.marginLeft = '20px';
            childUl.style.paddingLeft = '0';
            // hidden="until-found" rather than display: none, so find-in-page still searches a
            // collapsed node and opens it on a match
            if (collapsed) {
                childUl.setAttribute('hidden', 'until-found');
            }

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
                if (childUl.hasAttribute('hidden')) {
                    childUl.removeAttribute('hidden');
                    toggle.className = 'bi bi-chevron-down';
                } else {
                    childUl.setAttribute('hidden', 'until-found');
                    toggle.className = 'bi bi-chevron-right';
                }
            }

            toggle.addEventListener('click', toggleNode);
            keySpan.addEventListener('click', toggleNode);
            // find-in-page opens the node itself; only the chevron has to follow. The event
            // bubbles, so one from a node nested inside this one is not for this one.
            childUl.addEventListener('beforematch', function(event) {
                if (event.target === childUl) {
                    toggle.className = 'bi bi-chevron-down';
                }
            });

            li.appendChild(toggle);
            li.appendChild(keySpan);
            li.appendChild(preview);
            li.appendChild(childUl);
        } else {
            var bullet = document.createElement('span');
            bullet.innerHTML = '&bull; ';
            bullet.style.marginRight = '4px';
            bullet.className = 'json-muted';

            var keySpan = document.createElement('span');
            keySpan.className = 'json-key';
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
            var label = useArrayIndexAsKey ? String(index) : ('Event ' + (index + 1));
            ul.appendChild(renderNode(label, item, startCollapsed));
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

// A message in the same banner a flashed message gets, for a page that reports something without
// reloading (see #flash_messages in base.html).
function show_flash_message(text) {
    const banner = document.createElement("div");
    banner.className = "alert alert-warning alert-dismissible fade show";
    banner.setAttribute("role", "alert");
    const close = document.createElement("button");
    close.type = "button";
    close.className = "btn-close";
    close.setAttribute("data-bs-dismiss", "alert");
    close.setAttribute("aria-label", "Close");
    banner.appendChild(close);
    banner.appendChild(document.createTextNode(text));
    document.getElementById("flash_messages").appendChild(banner);
}

// The take_owned form value ("alert_uuid:owner_id,...", see selection_guard.js) as the
// {alert_uuid: owner_id} map PUT /api/v2/alerts/owner takes.
function take_owned_map(take_owned) {
    const result = {};
    (take_owned || "").split(",").forEach(function(pair) {
        const parts = pair.trim().split(":");
        if (parts.length === 2 && parts[0] && /^\d+$/.test(parts[1])) {
            result[parts[0]] = parseInt(parts[1], 10);
        }
    });
    return result;
}

// The Assign Ownership dialog (base.html), for a page that describes the alerts it assigns.
//   alerts()        the alerts to assign, described for SelectionGuard (selection_guard.js)
//   on_deselect     as SelectionGuard.render takes it, or null where there is no selection
//   done(result)    runs with the result of PUT /api/v2/alerts/owner
// Assigning goes through the same rule as taking: an alert another analyst owns is left alone
// unless the guard's checkbox for that analyst is ticked. Alerts the assignee already owns need
// no confirmation, so the guard is drawn again whenever the assignee changes.
function setup_assign_ownership_dialog(alerts, on_deselect, done) {
    const modal = document.getElementById("assign_ownership_modal");
    const select = document.getElementById("assign_ownership_user");
    const guard = document.getElementById("assign_ownership_selection_guard");
    const button = document.getElementById("btn-assign-ownership");

    function owner_id() {
        return select.value === "" ? null : Number(select.value);
    }

    function render() {
        SelectionGuard.render(guard, alerts(), {
            action: "assign",
            new_owner_id: owner_id(),
            new_owner_name: select.options[select.selectedIndex].text,
            submit: button,
            on_deselect: on_deselect,
        });
    }

    $(modal).on("show.bs.modal", render);
    select.addEventListener("change", render);
    button.addEventListener("click", function() {
        aceApi.put("/alerts/owner", {
            alert_uuids: alerts().map(function(alert) { return alert.uuid; }),
            owner_id: owner_id(),
            take_owned: take_owned_map(SelectionGuard.take_owned(guard)),
        })
        .then(done)
        .catch(function(err) { alert(err.message); });
    });
}


// The GUI theme (docs/USER_PREFERENCES.md). The choice is applied at once through
// aceApplyTheme() (core.html) and then stored; if the store fails the previous theme comes
// back, so what the analyst sees is always what the next page load will render. Plain fetch
// rather than aceApi: ace_api.js is not loaded on every page.
function save_theme(mode) {
    var previous = document.documentElement.getAttribute("data-ace-theme");
    window.aceApplyTheme(mode);
    sync_theme_controls(mode);
    return fetch("/api/v2/users/me/preferences/theme", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mode }),
    }).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) { throw new Error(text || response.statusText); });
        }
    }).catch(function(error) {
        window.aceApplyTheme(previous);
        sync_theme_controls(previous);
        throw error;
    });
}

// mark the current theme in the navbar menu and the preferences page radios, if present
function sync_theme_controls(mode) {
    document.querySelectorAll("#theme-switcher [data-theme-mode]").forEach(function(item) {
        var current = item.getAttribute("data-theme-mode") === mode;
        item.classList.toggle("active", current);
        item.setAttribute("aria-pressed", current ? "true" : "false");
    });
    document.querySelectorAll("input[name=theme_mode]").forEach(function(radio) {
        radio.checked = radio.value === mode;
    });
}

$(document).ready(function() {
    var menu = document.getElementById("theme-switcher");
    if (!menu) {
        return;
    }
    menu.addEventListener("click", function(event) {
        var item = event.target.closest("[data-theme-mode]");
        if (!item) {
            return;
        }
        save_theme(item.getAttribute("data-theme-mode")).catch(function(error) {
            alert("Theme not saved: " + error.message);
        });
    });
});
