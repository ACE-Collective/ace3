// The remediation dialog of the alert pages (base.html): the remediation targets of the selected
// alerts, from /api/v2/remediation, and the Remediate / Restore / Stop / Clear actions on the
// targets ticked in it.

function toggle_all_remediation_targets() {
    var checked = $("input[name='all_remediation_targets']").prop("checked");
    $("input[name='remediation_target']").prop("checked", checked);
}

function remediation_cell(row, text) {
    const cell = document.createElement("td");
    cell.textContent = text || "";
    row.appendChild(cell);
}

// builds the targets table; each checkbox carries its target and the id of the target's latest
// remediation, which Stop and Clear act on
function render_remediation_targets(targets) {
    const table = document.createElement("table");
    table.className = "table table-striped";

    const header = document.createElement("tr");
    const all = document.createElement("th");
    all.width = 20;
    const all_box = document.createElement("input");
    all_box.type = "checkbox";
    all_box.name = "all_remediation_targets";
    all_box.onchange = toggle_all_remediation_targets;
    all.appendChild(all_box);
    header.appendChild(all);
    ["Type", "Value", "Remediator", "Action", "Status", "Result"].forEach(function(title) {
        const th = document.createElement("th");
        th.textContent = title;
        header.appendChild(th);
    });
    table.appendChild(header);

    targets.forEach(function(target) {
        const row = document.createElement("tr");
        const select = document.createElement("td");
        const box = document.createElement("input");
        box.type = "checkbox";
        box.name = "remediation_target";
        box.dataset.remediator = target.remediator;
        box.dataset.observableType = target.observable_type;
        box.dataset.observableValue = target.observable_value;
        if (target.current) {
            box.dataset.currentId = target.current.id;
        }
        select.appendChild(box);
        row.appendChild(select);

        remediation_cell(row, target.observable_type);
        remediation_cell(row, target.observable_value);
        remediation_cell(row, target.remediator_display_name || target.remediator);
        remediation_cell(row, target.current ? target.current.action : "");
        remediation_cell(row, target.current ? target.current.status : "");
        remediation_cell(row, target.current ? target.current.result : "");
        table.appendChild(row);
    });

    $("#remediation-selection-body").empty().append(table);
}

function get_remediation_targets() {
    return $("input[name='remediation_target']:checked").map(function() {
        return {
            remediator: this.dataset.remediator,
            observable_type: this.dataset.observableType,
            observable_value: this.dataset.observableValue,
            current_id: this.dataset.currentId ? Number(this.dataset.currentId) : null,
        };
    }).get();
}

function check_targets_selected(targets) {
    if (targets.length === 0) {
        alert("Select at least one remediation target");
        return false;
    }

    return true;
}

function show_remediation_targets(alert_uuids) {
    $('#remediation-selection-body').text('loading data...');
    $('#remediation-selection-modal').modal('show');
    aceApi.post("/remediation/targets/lookup", {alert_uuids: alert_uuids})
    .then(function(result) { render_remediation_targets(result.data); })
    .catch(function(err) {
        $('#remediation-selection-modal').modal('hide');
        alert('Failed to load remediation targets: ' + err.message);
    });
}

// closes the selection, opens the result dialog with a progress message, and returns the targets
// ticked in the selection
function start_remediation_action(progress) {
    const targets = get_remediation_targets();
    if (!check_targets_selected(targets)) {
        return null;
    }

    $('#remediation-selection-modal').modal('hide');
    $('#remediation-body').text(progress);
    $('#remediation-modal').modal('show');
    return targets;
}

function report_remediation(message) {
    $('#remediation-body').text(message);
}

function queue_remediations(action, progress) {
    const targets = start_remediation_action(progress);
    if (targets === null) {
        return;
    }

    aceApi.post("/remediation/remediations", {
        action: action,
        targets: targets.map(function(target) {
            return {remediator: target.remediator, observable_type: target.observable_type, observable_value: target.observable_value};
        }),
    })
    .then(function(result) { report_remediation("queued " + result.data.length + " remediation(s)"); })
    .catch(function(err) { report_remediation("Failed to queue remediation: " + err.message); });
}

function restore_remediation_targets() {
    queue_remediations("restore", "restoring targets...");
}

function remove_remediation_targets() {
    queue_remediations("remove", "removing targets...");
}

// Stop and Clear act on each ticked target's latest remediation, one request each, and report
// how many succeeded and why the others did not
function act_on_current_remediations(progress, request, done) {
    const targets = start_remediation_action(progress);
    if (targets === null) {
        return;
    }

    const ids = targets.map(function(target) { return target.current_id; }).filter(function(id) { return id !== null; });
    if (ids.length === 0) {
        report_remediation("none of the selected targets has a remediation");
        return;
    }

    Promise.allSettled(ids.map(request)).then(function(results) {
        const failures = results.filter(function(result) { return result.status === "rejected"; })
            .map(function(result) { return result.reason.message; });
        let message = done + " " + (ids.length - failures.length) + " remediation(s)";
        if (failures.length > 0) {
            message += "; " + failures.join("; ");
        }
        report_remediation(message);
    });
}

function stop_remediation() {
    act_on_current_remediations("stopping remediation...", function(id) {
        return aceApi.post("/remediation/remediations/" + id + "/cancel");
    }, "stopped");
}

function delete_remediation() {
    act_on_current_remediations("deleting remediation...", function(id) {
        return aceApi.del("/remediation/remediations/" + id);
    }, "cleared");
}
