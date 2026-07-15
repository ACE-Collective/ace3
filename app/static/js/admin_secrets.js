// Encrypted secrets management — set/overwrite and delete named secrets.
//
// These call the v2 API directly (same origin, authenticated by the Flask session cookie). Flask
// only renders the page. The API is write-only: values are sent up, never read back.

var SECRETS_API = "/api/v2/secrets";

function send_json(url, method, body) {
    var opts = {
        method: method,
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) {
        opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) { throw new Error(text || response.statusText); });
        }
        return response;
    });
}

function set_secret(key, value) {
    if (!key) {
        alert("Enter a secret name.");
        return;
    }
    if (!value) {
        alert("Enter a value to set.");
        return;
    }
    send_json(SECRETS_API + "/" + encodeURIComponent(key), "PUT", { value: value })
        .then(function() { window.location.reload(); })
        .catch(function(error) { alert("Error setting secret: " + error.message); });
}

$(document).ready(function() {
    $("#add-secret-form").on("submit", function(event) {
        event.preventDefault();
        set_secret($("#new-secret-key").val().trim(), $("#new-secret-value").val());
    });

    $(".btn-set-secret").on("click", function() {
        var row = $(this).closest("tr");
        set_secret(row.data("secret-key"), row.find(".secret-value-input").val());
    });

    $(".btn-delete-secret").on("click", function() {
        var row = $(this).closest("tr");
        var key = row.data("secret-key");
        if (!confirm("Delete the stored value for \"" + key + "\"? This cannot be undone.")) {
            return;
        }
        send_json(SECRETS_API + "/" + encodeURIComponent(key), "DELETE")
            .then(function() { window.location.reload(); })
            .catch(function(error) { alert("Error deleting secret: " + error.message); });
    });
});
