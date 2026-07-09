// Observable detection settings — toggle for_detection and adjust expiration per row.

function post_form(url, params) {
    var body = new URLSearchParams(params);
    return fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
    }).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) { throw new Error(text || response.statusText); });
        }
        return response;
    });
}

$(document).ready(function() {
    // Same jQuery UI datetimepicker configuration the alert page uses for observable expiration
    // (see saq_analysis.js). Emits "YYYY-MM-DD HH:MM:SS", which is what the server parses.
    $(".obs-expires-input").datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    $(".btn-toggle-detection").on("click", function() {
        var row = $(this).closest("tr");
        var observable_id = row.data("observable-id");
        // currently enabled? then we are disabling.
        var currently_enabled = $(this).data("enabled") === true || $(this).data("enabled") === "true";
        var new_enabled = !currently_enabled;

        post_form("/ace/admin/detection/toggle", {
            observable_id: observable_id,
            enabled: new_enabled ? "true" : "false",
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
        post_form("/ace/admin/detection/expiration", {
            observable_id: observable_id,
            expires_on: value,
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error setting expiration: " + error.message);
        });
    });

    $(".btn-clear-expiration").on("click", function() {
        var row = $(this).closest("tr");
        var observable_id = row.data("observable-id");
        post_form("/ace/admin/detection/expiration", {
            observable_id: observable_id,
            never_expire: "true",
        }).then(function() {
            window.location.reload();
        }).catch(function(error) {
            alert("Error clearing expiration: " + error.message);
        });
    });
});
