// The preferences page. The profile form saves through PATCH /api/v2/users/me (same origin,
// authenticated by the Flask session cookie); the column chooser is init_column_chooser() from
// manage_columns.js with nothing to re-render; the theme radios go through save_theme() (ace.js).
$(document).ready(function() {
    var form = document.getElementById("profile_form");
    var status = document.getElementById("profile_status");

    function set_status(text, is_error) {
        status.textContent = text;
        status.classList.toggle("text-danger", !!is_error);
        status.classList.toggle("text-muted", !is_error);
    }

    form.addEventListener("submit", function(event) {
        event.preventDefault();
        var body = {
            display_name: form.elements.display_name.value,
            timezone: form.elements.timezone.value,
            queue: form.elements.queue.value,
        };
        set_status("Saving…");
        fetch(form.dataset.apiUrl, {
            method: "PATCH",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        }).then(function(response) {
            if (!response.ok) {
                return response.text().then(function(text) { throw new Error(text || response.statusText); });
            }
            return response.json();
        }).then(function(user) {
            set_status("Saved");
            // the navbar shows the display name; keep it current without a reload
            var dropdown = document.getElementById("user-dropdown");
            if (dropdown) { dropdown.textContent = user.display_name + " (" + user.username + ")"; }
        }).catch(function(error) {
            set_status("Not saved: " + error.message, true);
        });
    });

    var theme_status = document.getElementById("theme_status");
    document.getElementById("theme_form").addEventListener("change", function(event) {
        theme_status.textContent = "Saving…";
        theme_status.classList.remove("text-danger");
        save_theme(event.target.value).then(function() {
            theme_status.textContent = "Saved";
        }).catch(function(error) {
            theme_status.textContent = "Not saved: " + error.message;
            theme_status.classList.add("text-danger");
        });
    });

    init_column_chooser(document.querySelector(".column-chooser"), null);
});
