// Observable detection settings — toggle for_detection and adjust expiration per row.
//
// These call the v2 API directly (same origin, authenticated by the Flask session cookie). Flask
// only renders the page.

var DETECTION_API = "/api/v2/detection";

function patch_json(url, body) {
    return fetch(url, {
        method: "PATCH",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    }).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) { throw new Error(text || response.statusText); });
        }
        return response;
    });
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

    $(".btn-toggle-detection").on("click", function() {
        var row = $(this).closest("tr");
        var observable_id = row.data("observable-id");
        var currently_enabled = $(this).data("enabled") === true || $(this).data("enabled") === "true";

        patch_json(DETECTION_API + "/" + observable_id + "/detection", {
            enabled: !currently_enabled,
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error updating detection: " + error.message);
        });
    });

    $(".btn-set-expiration").on("click", function() {
        var row = $(this).closest("tr");
        var observable_id = row.data("observable-id");
        var value = row.find(".obs-expires-input").val().trim();
        if (!value) {
            alert("Enter an expiration as YYYY-MM-DD HH:MM:SS");
            return;
        }
        // the picker emits "YYYY-MM-DD HH:MM:SS"; the API takes ISO 8601
        patch_json(DETECTION_API + "/" + observable_id + "/expiration", {
            expires_on: value.replace(" ", "T"),
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error setting expiration: " + error.message);
        });
    });

    $(".btn-clear-expiration").on("click", function() {
        var row = $(this).closest("tr");
        var observable_id = row.data("observable-id");
        patch_json(DETECTION_API + "/" + observable_id + "/expiration", {
            expires_on: null,
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error clearing expiration: " + error.message);
        });
    });
});
