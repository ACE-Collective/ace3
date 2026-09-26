// The selection guard of the bulk alert actions (set disposition, take ownership).
//
// Before an action runs, it shows what the selection actually holds -- how many alerts, in
// which queues, owned by whom -- so a select-all that swept in someone else's alerts is
// visible before it lands rather than after. Each group can be unchecked in one click.
//
// It also asks before touching another analyst's alerts. The server enforces that rule
// (check_alert_ownership in saq/database/util/alert.py): an alert owned by another active
// analyst changes only when the request names it in the take_owned field, as
// alert_uuid:owner_id pairs, the owner being who had the alert when the analyst looked.
// Each such owner gets a checkbox here, unchecked, so the safe default is to leave their
// alerts alone. A selection spanning more than one queue must be acknowledged before a
// disposition can be saved.
//
// Pages describe each selected alert as
//   {uuid, queue, owner_id, owner_name, owner_enabled, disposition}
// and call render() when the dialog opens. The container carries data-current-user-id.

var SelectionGuard = (function() {
    "use strict";

    const ACTIONS = {
        disposition: {
            verb_many: function(n) { return "set the disposition of " + n + " " + plural(n, "alert"); },
            take_many: function(n, name) { return "Take " + n + " " + plural(n, "alert") + " from " + name + " and set " + (n == 1 ? "its" : "their") + " disposition"; },
            take_one: function(name) { return "Take this alert from " + name + " and set its disposition"; },
            check_queues: true,
        },
        take: {
            verb_many: function(n) { return "take ownership of " + n + " " + plural(n, "alert"); },
            take_many: function(n, name) { return "Take " + n + " " + plural(n, "alert") + " from " + name; },
            take_one: function(name) { return "Take this alert from " + name; },
            check_queues: false,
        },
    };

    function plural(n, word) {
        return n == 1 ? word : word + "s";
    }

    function current_user_id(container) {
        return Number(container.dataset.currentUserId);
    }

    // true when changing the alert needs its owner's alerts to be taken first
    function owned_by_another(alert, user_id) {
        return alert.owner_id != null && alert.owner_id !== user_id && alert.owner_enabled;
    }

    // true when any of these alerts belongs to another active analyst
    function needs_confirmation(alerts, user_id) {
        return alerts.some(function(alert) { return owned_by_another(alert, user_id); });
    }

    // groups alerts by key_of(alert), keeping first-seen order; each group is
    // {key, label, uuids}
    function group_by(alerts, key_of, label_of) {
        const groups = new Map();
        alerts.forEach(function(alert) {
            const key = key_of(alert);
            if (!groups.has(key)) {
                groups.set(key, { key: key, label: label_of(alert), uuids: [] });
            }
            groups.get(key).uuids.push(alert.uuid);
        });
        return Array.from(groups.values());
    }

    function owner_label(alert, user_id) {
        if (alert.owner_id == null) return "unowned";
        if (alert.owner_id === user_id) return "you";
        return alert.owner_enabled ? alert.owner_name : alert.owner_name + " (disabled)";
    }

    function element(tag, class_name, text) {
        const node = document.createElement(tag);
        if (class_name) node.className = class_name;
        if (text != null) node.textContent = text;
        return node;
    }

    // one line of the breakdown: "Queues  default 20  jdoe 3". With more than one group and
    // a way to deselect, each group is a button that unchecks its alerts.
    function breakdown_row(label, groups, state) {
        const row = element("div", "d-flex flex-wrap align-items-center gap-1 mb-1");
        row.appendChild(element("span", "text-muted me-1", label));
        const removable = groups.length > 1 && state.options.on_deselect;
        groups.forEach(function(group) {
            const text = group.label + " " + group.uuids.length;
            if (!removable) {
                row.appendChild(element("span", "badge text-bg-light border", text));
                return;
            }

            const chip = element("button", "btn btn-sm btn-outline-secondary py-0");
            chip.type = "button";
            chip.title = "Uncheck these " + group.uuids.length + " " + plural(group.uuids.length, "alert");
            chip.appendChild(document.createTextNode(text + " "));
            chip.appendChild(element("span", "bi bi-x"));
            chip.addEventListener("click", function() {
                const removed = new Set(group.uuids);
                state.options.on_deselect(group.uuids);
                state.alerts = state.alerts.filter(function(alert) { return !removed.has(alert.uuid); });
                draw(state);
            });
            row.appendChild(chip);
        });
        return row;
    }

    function checkbox(id, text, checked, on_change) {
        const wrapper = element("div", "form-check mt-1");
        const input = element("input", "form-check-input");
        input.type = "checkbox";
        input.id = id;
        input.checked = checked;
        input.addEventListener("change", function() { on_change(input.checked); });
        const label = element("label", "form-check-label", text);
        label.htmlFor = id;
        wrapper.appendChild(input);
        wrapper.appendChild(label);
        return wrapper;
    }

    function draw(state) {
        const container = state.container;
        const action = ACTIONS[state.options.action];
        const user_id = current_user_id(container);
        const alerts = state.alerts;
        const id_prefix = (container.id || "selection_guard") + "_";
        // redrawing replaces the checkbox the analyst just used; keep keyboard focus on it
        const focused_id = container.contains(document.activeElement) ? document.activeElement.id : null;
        container.replaceChildren();

        // the other analysts whose alerts are selected, and which of them the analyst
        // agreed to take alerts from
        const other_owners = group_by(
            alerts.filter(function(alert) { return owned_by_another(alert, user_id); }),
            function(alert) { return alert.owner_id; },
            function(alert) { return alert.owner_name; });
        const queues = group_by(alerts, function(alert) { return alert.queue; }, function(alert) { return alert.queue; });
        const queue_check_needed = action.check_queues && queues.length > 1;

        const left_alone = other_owners
            .filter(function(owner) { return !state.taken.has(owner.key); })
            .reduce(function(total, owner) { return total + owner.uuids.length; }, 0);
        const applied = alerts.length - left_alone;

        if (alerts.length == 0) {
            container.appendChild(element("div", "small text-muted", "No alerts are selected."));
        }

        if (alerts.length > 1) {
            const summary = element("div", "border rounded p-2 mb-2");
            summary.appendChild(element("div", "fw-semibold mb-1", alerts.length + " alerts selected"));
            summary.appendChild(breakdown_row("Queues", queues, state));
            summary.appendChild(breakdown_row("Owners", group_by(alerts,
                function(alert) { return alert.owner_id == null ? "none" : alert.owner_id; },
                function(alert) { return owner_label(alert, user_id); }), state));
            if (state.options.action === "disposition") {
                summary.appendChild(breakdown_row("Dispositions", group_by(alerts,
                    function(alert) { return alert.disposition || "OPEN"; },
                    function(alert) { return alert.disposition || "OPEN"; }), state));
            }
            container.appendChild(summary);
        }

        if (queue_check_needed) {
            const warning = element("div", "alert alert-warning py-2 mb-2");
            warning.appendChild(element("div", null,
                "These alerts are in " + queues.length + " queues. Make sure every one of them is meant to change."));
            warning.appendChild(checkbox(id_prefix + "queues", "Change alerts in all " + queues.length + " queues",
                state.queues_confirmed, function(checked) { state.queues_confirmed = checked; draw(state); }));
            container.appendChild(warning);
        }

        other_owners.forEach(function(owner) {
            const warning = element("div", "alert alert-warning py-2 mb-2");
            const count = owner.uuids.length;
            warning.appendChild(element("div", null, alerts.length == 1
                ? "This alert is owned by " + owner.label + "."
                : count + " of these alerts " + (count == 1 ? "is" : "are") + " owned by " + owner.label + "."));
            const text = alerts.length == 1 ? action.take_one(owner.label) : action.take_many(count, owner.label);
            warning.appendChild(checkbox(id_prefix + "take_" + owner.key, text, state.taken.has(owner.key), function(checked) {
                if (checked) {
                    state.taken.add(owner.key);
                } else {
                    state.taken.delete(owner.key);
                }
                draw(state);
            }));
            container.appendChild(warning);
        });

        // what the button will actually do, once anything needs spelling out
        if (alerts.length > 0 && applied == 0) {
            container.appendChild(element("div", "small text-muted",
                "Nothing will change unless you take " + (alerts.length == 1 ? "it" : "them") + "."));
        } else if (alerts.length > 1 || other_owners.length) {
            let outcome = "This will " + action.verb_many(applied);
            if (left_alone > 0) {
                outcome += " and leave " + left_alone + " owned by " + (other_owners.length == 1 ? other_owners[0].label : "other analysts") + " alone";
            }
            if (queue_check_needed && !state.queues_confirmed) {
                outcome += " once you confirm the queues";
            }
            container.appendChild(element("div", "small text-muted", outcome + "."));
        }

        // the confirmations the server acts on
        const take_owned = [];
        other_owners.forEach(function(owner) {
            if (state.taken.has(owner.key)) {
                owner.uuids.forEach(function(uuid) { take_owned.push(uuid + ":" + owner.key); });
            }
        });
        state.take_owned = take_owned.join(",");
        const field = element("input");
        field.type = "hidden";
        field.name = "take_owned";
        field.value = state.take_owned;
        container.appendChild(field);

        if (state.options.submit) {
            state.options.submit.disabled = applied == 0 || (queue_check_needed && !state.queues_confirmed);
        }

        if (focused_id) {
            const refocus = document.getElementById(focused_id);
            if (refocus) refocus.focus();
        }
    }

    // Renders the guard for the given alerts into container.
    //   options.action     "disposition" or "take"
    //   options.submit     the button that runs the action; disabled until it would do something
    //   options.on_deselect(uuids)  unchecks alerts on the page; omit where there is no selection
    function render(container, alerts, options) {
        const state = {
            container: container,
            alerts: alerts,
            options: options,
            taken: new Set(),
            queues_confirmed: false,
            take_owned: "",
        };
        container._selection_guard = state;
        draw(state);
    }

    // the take_owned value for a guard rendered into container, for callers that post it
    // themselves rather than submitting the surrounding form
    function take_owned(container) {
        const state = container._selection_guard;
        return state ? state.take_owned : "";
    }

    return {
        needs_confirmation: needs_confirmation,
        owned_by_another: owned_by_another,
        render: render,
        take_owned: take_owned,
    };
})();
