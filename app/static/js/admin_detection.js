// Observable detections — add, delete, and adjust expiration.
//
// These call the v2 API directly (same origin, authenticated by the Flask session cookie). Flask
// only renders the page.

var DETECTION_API = "/api/v2/detection";

function detection_request(method, url, body) {
    var options = {
        method: method,
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) {
        options.body = JSON.stringify(body);
    }

    return fetch(url, options).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) {
                throw new Error(detection_error_message(text, response));
            });
        }
        return response;
    });
}

// The API reports validation and conflict failures as a FastAPI {"detail": "..."} body. Surface
// that sentence rather than the raw JSON — "1.2.3 is not a valid value for observable type ipv4"
// is actionable, the envelope around it is not.
function detection_error_message(text, response) {
    try {
        var parsed = JSON.parse(text);
        if (parsed && typeof parsed.detail === "string") {
            return parsed.detail;
        }
    } catch (e) {
        // not JSON; fall through to the raw text
    }
    return text || response.statusText;
}

// The picker emits "YYYY-MM-DD HH:MM:SS"; the API takes ISO 8601.
function to_iso(value) {
    return value.replace(" ", "T");
}

$(document).ready(function() {
    // Same jQuery UI datetimepicker configuration the alert page uses for observable expiration
    // (see saq_analysis.js). Emits "YYYY-MM-DD HH:MM:SS".
    $(".obs-expires-input").datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    $("#add_detection_form").on("submit", function(event) {
        event.preventDefault();

        var value = $("#add_detection_value").val().trim();
        if (!value) {
            alert("Enter an observable value");
            return;
        }

        var body = {
            type: $("#add_detection_type").val(),
            value: value,
        };

        var expires = $("#add_detection_expires").val().trim();
        if (expires) {
            body.expires_on = to_iso(expires);
        }

        var context = $("#add_detection_context").val().trim();
        if (context) {
            body.detection_context = context;
        }

        detection_request("POST", DETECTION_API + "/", body).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error adding detection: " + error.message);
        });
    });

    $(".btn-delete-detection").on("click", function() {
        var row = $(this).closest("tr");
        var value = row.find(".obs-value code").text();
        if (!confirm("Delete the detection for " + value + "?")) {
            return;
        }

        detection_request("DELETE", DETECTION_API + "/" + row.data("detection-id")).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error deleting detection: " + error.message);
        });
    });

    $(".btn-set-expiration").on("click", function() {
        var row = $(this).closest("tr");
        var value = row.find(".obs-expires-input").val().trim();
        if (!value) {
            alert("Enter an expiration as YYYY-MM-DD HH:MM:SS");
            return;
        }

        detection_request("PATCH", DETECTION_API + "/" + row.data("detection-id") + "/expiration", {
            expires_on: to_iso(value),
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error setting expiration: " + error.message);
        });
    });

    $(".btn-clear-expiration").on("click", function() {
        var row = $(this).closest("tr");
        detection_request("PATCH", DETECTION_API + "/" + row.data("detection-id") + "/expiration", {
            expires_on: null,
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error clearing expiration: " + error.message);
        });
    });
});
