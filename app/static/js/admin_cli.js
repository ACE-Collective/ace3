// Admin -> CLI: run an ACE CLI command on one or more nodes and follow its output.
//
// These call the v2 API directly (same origin, authenticated by the Flask session cookie). Flask
// only renders the page. Output is always inserted as text, never as HTML.

var CLI_API = "/api/v2/cli";
var POLL_MS = 1500;
var FINISHED = ["completed", "timed_out", "failed", "abandoned"];
var STATUS_CLASS = {
    pending: "secondary",
    running: "info",
    completed: "success",
    timed_out: "warning",
    failed: "danger",
    abandoned: "dark",
};

var history_cursor = null;

function api(url, method, body) {
    var opts = { method: method || "GET", credentials: "same-origin", headers: {} };
    if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
    }
    return fetch(url, opts).then(function(response) {
        return response.text().then(function(text) {
            var data = null;
            try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
            if (!response.ok) {
                var detail = data && data.detail !== undefined ? data.detail : (text || response.statusText);
                throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
            }
            return data;
        });
    });
}

function status_badge(execution) {
    var label = execution.status.replace("_", " ");
    if (execution.status === "completed") {
        label += " (exit " + execution.exit_code + ")";
    }
    return $("<span>").addClass("badge text-bg-" + (STATUS_CLASS[execution.status] || "secondary")).text(label);
}

function render_execution(execution) {
    var card = $("#cli-execution-" + execution.id);
    if (card.length === 0) {
        card = $("<div>").addClass("card mb-2").attr("id", "cli-execution-" + execution.id);
        var header = $("<div>").addClass("card-header d-flex flex-wrap gap-2 align-items-center");
        header.append($("<strong>").addClass("cli-node-name"));
        header.append($("<code>").addClass("cli-command"));
        header.append($("<span>").addClass("cli-status ms-auto"));
        card.append(header);
        card.append($("<div>").addClass("card-body p-2").append($("<pre>").addClass("cli-output")));
        $("#cli-results").prepend(card);
    }

    card.find(".cli-node-name").text(execution.node_name);
    card.find(".cli-command").text("ace " + execution.command);
    card.find(".cli-status").empty().append(status_badge(execution));

    var text = execution.output || "";
    if (execution.output_truncated) {
        text += "\n[output truncated]";
    }
    if (execution.error) {
        text += (text ? "\n" : "") + "[" + execution.error + "]";
    }
    var pre = card.find(".cli-output");
    var at_bottom = pre[0].scrollHeight - pre[0].scrollTop - pre[0].clientHeight < 20;
    pre.text(text || (FINISHED.indexOf(execution.status) >= 0 ? "(no output)" : "waiting for output..."));
    if (at_bottom) {
        pre[0].scrollTop = pre[0].scrollHeight;
    }
}

function follow(execution_id) {
    api(CLI_API + "/executions/" + execution_id).then(function(execution) {
        render_execution(execution);
        if (FINISHED.indexOf(execution.status) < 0) {
            setTimeout(function() { follow(execution_id); }, POLL_MS);
        } else {
            refresh_history();
        }
    }).catch(function(error) {
        // keep following through a transient failure: the run itself is unaffected
        setTimeout(function() { follow(execution_id); }, POLL_MS * 4);
        console.error("unable to read cli execution " + execution_id + ": " + error.message);
    });
}

function history_row(execution) {
    var row = $("<tr>").data("execution-id", execution.id);
    row.append($("<td>").text(execution.id));
    row.append($("<td>").text(new Date(execution.created_at).toLocaleString()));
    row.append($("<td>").text(execution.username));
    row.append($("<td>").text(execution.node_name));
    row.append($("<td>").addClass("cli-history-command").text(execution.command));
    row.append($("<td>").append(status_badge(execution)));
    row.append($("<td>").text(execution.exit_code === null ? "" : execution.exit_code));
    return row;
}

function load_history(cursor) {
    var url = CLI_API + "/executions?limit=25" + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "");
    return api(url).then(function(page) {
        var body = $("#cli-history tbody");
        if (!cursor) {
            body.empty();
        }
        page.data.forEach(function(execution) { body.append(history_row(execution)); });
        history_cursor = page.next_cursor;
        $("#cli-history-more").toggleClass("d-none", !history_cursor);
    }).catch(function(error) { console.error("unable to load cli history: " + error.message); });
}

function refresh_history() {
    load_history(null);
}

function selected_node_ids() {
    return $(".cli-node:checked").map(function() { return parseInt(this.value, 10); }).get();
}

$(document).ready(function() {
    $("#cli-form").on("submit", function(event) {
        event.preventDefault();
        var command = $("#cli-command").val().trim();
        if (!command) {
            alert("Enter a command.");
            return;
        }
        var node_ids = selected_node_ids();
        if (node_ids.length === 0) {
            alert("Select at least one node.");
            return;
        }
        if (node_ids.length > 1 && !confirm("Run \"ace " + command + "\" on " + node_ids.length + " nodes?")) {
            return;
        }

        var button = $("#cli-run").prop("disabled", true);
        api(CLI_API + "/executions", "POST", {
            command: command,
            node_ids: node_ids,
            timeout_seconds: parseInt($("#cli-timeout").val(), 10),
        }).then(function(page) {
            page.data.forEach(function(execution) {
                render_execution(execution);
                follow(execution.id);
            });
            refresh_history();
        }).catch(function(error) {
            alert("Unable to run the command: " + error.message);
        }).finally(function() {
            button.prop("disabled", false);
        });
    });

    $("#cli-select-all").on("click", function() { $(".cli-node").prop("checked", true); });
    $("#cli-select-primary").on("click", function() {
        $(".cli-node").each(function() { $(this).prop("checked", $(this).data("primary") === true); });
    });

    $("#cli-history").on("click", "tbody tr", function() {
        follow($(this).data("execution-id"));
        window.scrollTo({ top: 0, behavior: "smooth" });
    });
    $("#cli-history-more").on("click", function() { load_history(history_cursor); });

    refresh_history();
});
