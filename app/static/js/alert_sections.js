// The alert page's collapsible sections (templates/analysis/_alert_section.html). A collapsed
// section's body is hidden="until-found" rather than display: none, so the browser's find-in-page
// still searches it and opens it on a match. The pin in each header saves how that section starts
// for this analyst (the alert_sections preference).

var ALERT_SECTIONS_PREFERENCE_URL = "/api/v2/users/me/preferences/alert_sections";

// a section's own parts, not those of a section nested in its body
function alert_section_body(section) {
    return section.querySelector(":scope > .alert-section-body");
}

function alert_section_header(section, selector) {
    return section.querySelector(":scope > .card-header " + selector);
}

// opens or closes a section for this page view only
function set_alert_section_open(section, open) {
    var body = alert_section_body(section);
    if (open) {
        body.removeAttribute("hidden");
    } else {
        body.setAttribute("hidden", "until-found");
    }
    render_alert_section_toggle(section, open);
}

function render_alert_section_toggle(section, open) {
    var toggle = alert_section_header(section, ".alert-section-toggle");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    var icon = toggle.querySelector(".bi");
    icon.classList.toggle("bi-chevron-down", open);
    icon.classList.toggle("bi-chevron-right", !open);
}

function render_alert_section_default(section, starts_open) {
    section.setAttribute("data-starts-open", starts_open ? "true" : "false");
    var pin = alert_section_header(section, ".alert-section-default");
    pin.setAttribute("aria-pressed", starts_open ? "true" : "false");
    var icon = pin.querySelector(".bi");
    icon.classList.toggle("bi-pin-angle-fill", starts_open);
    icon.classList.toggle("bi-pin-angle", !starts_open);
    pin.querySelector(".alert-section-default-label").textContent = starts_open ? "Open by default" : "Collapsed by default";
}

function alert_section_response_ok(response) {
    if (!response.ok) {
        return response.text().then(function(text) { throw new Error(text || response.statusText); });
    }
    return response;
}

// Stores this analyst's choice for one section. The stored choices are read first rather than
// taken from this page, because another tab may have changed another section since it loaded.
function save_alert_section_default(section_id, starts_open) {
    return fetch(ALERT_SECTIONS_PREFERENCE_URL, { credentials: "same-origin" })
        .then(alert_section_response_ok)
        .then(function(response) { return response.json(); })
        .then(function(preference) {
            var sections = preference.value.sections;
            sections[section_id] = starts_open;
            return fetch(ALERT_SECTIONS_PREFERENCE_URL, {
                method: "PUT",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sections: sections }),
            }).then(alert_section_response_ok);
        });
}

// listened for on the document, so this script can load in <head> and covers sections an
// integration's template adds
document.addEventListener("click", function(event) {
    var toggle = event.target.closest(".alert-section-toggle");
    if (toggle) {
        var toggled = toggle.closest(".alert-section");
        set_alert_section_open(toggled, alert_section_body(toggled).hasAttribute("hidden"));
        return;
    }

    var pin = event.target.closest(".alert-section-default");
    if (!pin) {
        return;
    }
    var section = pin.closest(".alert-section");
    var previous = section.getAttribute("data-starts-open") === "true";
    var was_open = !alert_section_body(section).hasAttribute("hidden");
    // shown at once and applied to this view too, then put back if the save fails
    render_alert_section_default(section, !previous);
    set_alert_section_open(section, !previous);
    pin.disabled = true;
    save_alert_section_default(section.getAttribute("data-section-id"), !previous).catch(function(error) {
        render_alert_section_default(section, previous);
        set_alert_section_open(section, was_open);
        var title = alert_section_header(section, ".alert-section-toggle").textContent.trim();
        show_flash_message("Could not save how " + title + " starts: " + error.message);
    }).finally(function() {
        pin.disabled = false;
    });
});

// Find-in-page is about to reveal a match inside a collapsed section. The browser removes the
// hidden attribute itself, so only the toggle has to follow. Captured rather than bubbled, so
// it is seen whether or not the event bubbles.
document.addEventListener("beforematch", function(event) {
    var body = event.target;
    if (body.classList && body.classList.contains("alert-section-body")) {
        render_alert_section_toggle(body.closest(".alert-section"), true);
    }
}, true);
