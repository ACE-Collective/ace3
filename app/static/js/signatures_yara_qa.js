// Signatures -> Yara QA Results.
//
// Everything on this page comes from the v2 API (/api/v2/signatures/yara-qa), called directly from
// the browser (same origin, authenticated by the Flask session cookie). Flask only renders the
// shell. Downloads are plain links to the API: the browser saves the zip, which is encrypted with
// the password "infected".

var QA_PAGE = null;
var QA_API = null;
var QA_ALERT_URL = null;
var QA_CAN_DOWNLOAD = false;
var QA_MATCH_PAGE_SIZE = 25;

var qa_state = {
    offset: 0,
    total: 0,
    // uuid of the expanded signature, and its match listing state
    expanded: null,
    version: "",
    match_offset: 0,
};

function qa_request(url) {
    return fetch(url, { method: "GET", credentials: "same-origin" }).then(function(response) {
        if (!response.ok) {
            return response.text().then(function(text) {
                throw new Error(qa_error_message(text, response));
            });
        }
        return response.json();
    });
}

// FastAPI reports failures as {"detail": "..."} or {"detail": {"message": "..."}}; surface the
// sentence rather than the envelope.
function qa_error_message(text, response) {
    try {
        var parsed = JSON.parse(text);
        if (parsed && typeof parsed.detail === "string") {
            return parsed.detail;
        }
        if (parsed && parsed.detail && typeof parsed.detail.message === "string") {
            return parsed.detail.message;
        }
    } catch (e) {
        // not JSON; fall through to the raw text
    }
    return text || response.statusText;
}

function qa_show_error(message) {
    $("#qa_error").text(message).toggleClass("d-none", !message);
}

// every value placed in the page came from rule files or analyzed data: always text, never markup
function qa_text(value) {
    return $("<div>").text(value === null || value === undefined ? "" : String(value)).html();
}

function qa_date(value) {
    if (!value) {
        return "";
    }
    return value.replace("T", " ").replace(/\.\d+$/, "");
}

function qa_size(bytes) {
    if (bytes < 1024) {
        return bytes + " B";
    }
    var units = ["KB", "MB", "GB"];
    var value = bytes;
    var unit = -1;
    do {
        value /= 1024;
        unit++;
    } while (value >= 1024 && unit < units.length - 1);
    return value.toFixed(1) + " " + units[unit];
}

function qa_short_version(version) {
    return /^[0-9a-f]{40}$/.test(version) ? version.substring(0, 10) : version;
}

var QA_STATUS_LABELS = {
    qa: '<span class="badge bg-info text-dark">QA</span>',
    not_qa: '<span class="badge bg-secondary">not QA</span>',
    missing: '<span class="badge bg-warning text-dark">removed</span>',
};

function qa_filters() {
    var params = new URLSearchParams();
    var q = $("#qa_q").val().trim();
    if (q) {
        params.set("q", q);
    }
    if ($("#qa_status").val()) {
        params.set("status", $("#qa_status").val());
    }
    if ($("#qa_has_matches").val()) {
        params.set("has_matches", $("#qa_has_matches").val());
    }
    params.set("sort", $("#qa_sort").val());
    params.set("descending", $("#qa_descending").is(":checked") ? "true" : "false");
    params.set("limit", $("#qa_limit").val());
    params.set("offset", qa_state.offset);
    return params;
}

function qa_load_signatures() {
    qa_show_error("");
    return qa_request(QA_API + "/?" + qa_filters().toString()).then(function(page) {
        qa_state.total = page.total;
        $("#qa_inventory_warning")
            .text(page.inventory_error ? "Some rule files could not be read, so rules that have never matched may be missing: " + page.inventory_error : "")
            .toggleClass("d-none", !page.inventory_error);
        qa_render_signatures(page);
    }).catch(function(error) {
        qa_show_error("Unable to load YARA QA signatures: " + error.message);
    });
}

function qa_render_signatures(page) {
    var rows = $("#qa_signature_rows").empty();
    if (page.data.length === 0) {
        rows.append('<tr><td colspan="8" class="text-muted">No signatures match these filters.</td></tr>');
    }

    page.data.forEach(function(signature) {
        var row = $('<tr class="qa-signature-row">').attr("data-uuid", signature.signature_uuid);
        row.append($('<td class="qa-name">').html(
            "<strong>" + qa_text(signature.name) + "</strong>" +
            (signature.source_path ? '<br><span class="text-muted small">' + qa_text(signature.source_path) + "</span>" : "")));
        row.append($('<td class="qa-uuid">').html(
            "<code>" + qa_text(signature.signature_uuid) + "</code> " +
            '<button type="button" class="btn btn-xs btn-outline-secondary qa-copy" title="copy uuid"><i class="bi bi-clipboard"></i></button>'));
        row.append($("<td>").html(QA_STATUS_LABELS[signature.status] || qa_text(signature.status)));
        row.append($("<td>").text(signature.enabled === null ? "" : (signature.enabled ? "yes" : "no")));
        row.append($("<td>").text(signature.match_count));
        row.append($("<td>").text(signature.stored_count));
        row.append($("<td>").text(signature.version_count));
        row.append($("<td>").text(signature.last_match_at ? qa_date(signature.last_match_at) : "never"));
        rows.append(row);

        if (qa_state.expanded === signature.signature_uuid) {
            qa_expand(row, signature.signature_uuid, false);
        }
    });

    var first = page.total === 0 ? 0 : page.offset + 1;
    var last = page.offset + page.data.length;
    $("#qa_page_info").text(first + "–" + last + " of " + page.total);
    $("#qa_prev").prop("disabled", page.offset === 0);
    $("#qa_next").prop("disabled", last >= page.total);
}

function qa_collapse() {
    $("#qa_signature_rows tr.qa-detail-row").remove();
    qa_state.expanded = null;
}

// open the detail row under a signature row: its versions, and its stored files
function qa_expand(row, signature_uuid, reset) {
    $("#qa_signature_rows tr.qa-detail-row").remove();
    qa_state.expanded = signature_uuid;
    if (reset) {
        qa_state.version = "";
        qa_state.match_offset = 0;
    }

    var cell = $('<td colspan="8">').html('<span class="text-muted">Loading…</span>');
    var detail = $('<tr class="qa-detail-row">').append(cell);
    row.after(detail);

    qa_request(QA_API + "/" + encodeURIComponent(signature_uuid)).then(function(signature) {
        qa_render_detail(cell, signature);
        qa_load_matches(cell, signature_uuid);
    }).catch(function(error) {
        cell.html('<span class="text-danger"></span>').find("span").text("Unable to load signature: " + error.message);
    });
}

function qa_render_detail(cell, signature) {
    var select = $('<select class="form-select form-select-sm qa-version" style="width: auto;">');
    select.append($("<option>").val("").text("all versions"));
    signature.versions.forEach(function(version) {
        select.append($("<option>").val(version.signature_version).text(
            qa_short_version(version.signature_version) + " — " + version.match_count + " matches, " +
            version.stored_count + " stored, last " + qa_date(version.last_match_at)));
    });
    select.val(qa_state.version);

    var toolbar = $('<div class="d-flex flex-wrap align-items-center gap-2 mb-2">');
    toolbar.append($('<label class="small text-muted mb-0">').text("Version"));
    toolbar.append(select);
    if (signature.current_version) {
        toolbar.append($('<span class="small text-muted">').text("loaded now: " + qa_short_version(signature.current_version)));
    }
    if (QA_CAN_DOWNLOAD) {
        toolbar.append('<button type="button" class="btn btn-sm btn-outline-dark qa-download-selected" disabled>Download selected</button>');
        toolbar.append('<a class="btn btn-sm btn-outline-dark qa-download-all" title="password: infected">Download all (this version)</a>');
    }

    cell.empty().append(toolbar).append('<div class="qa-matches"></div>');
    qa_update_download_all(cell, signature.signature_uuid);
}

function qa_update_download_all(cell, signature_uuid) {
    var params = new URLSearchParams();
    if (qa_state.version) {
        params.set("version", qa_state.version);
    }
    var url = QA_API + "/" + encodeURIComponent(signature_uuid) + "/download";
    if (params.toString()) {
        url += "?" + params.toString();
    }
    cell.find(".qa-download-all").attr("href", url)
        .text(qa_state.version ? "Download all (this version)" : "Download all");
}

function qa_load_matches(cell, signature_uuid) {
    var params = new URLSearchParams({ limit: QA_MATCH_PAGE_SIZE, offset: qa_state.match_offset });
    if (qa_state.version) {
        params.set("version", qa_state.version);
    }

    var target = cell.find(".qa-matches").html('<span class="text-muted">Loading…</span>');
    qa_request(QA_API + "/" + encodeURIComponent(signature_uuid) + "/matches?" + params.toString()).then(function(page) {
        qa_render_matches(target, signature_uuid, page);
        qa_update_selection(cell);
    }).catch(function(error) {
        target.html('<span class="text-danger"></span>').find("span").text("Unable to load matches: " + error.message);
    });
}

function qa_render_matches(target, signature_uuid, page) {
    if (page.total === 0) {
        target.html('<p class="text-muted mb-0">No stored files' + (qa_state.version ? " for this version" : "") + ".</p>");
        return;
    }

    var table = $('<table class="table table-sm table-bordered qa-match-table mb-2">');
    var head = $("<tr>");
    if (QA_CAN_DOWNLOAD) {
        head.append('<th style="width: 2rem"><input type="checkbox" class="form-check-input qa-select-all" title="select all local files"></th>');
    }
    ["File", "SHA256", "Size", "Version", "Hits", "First seen", "Last seen", "Expires", "Node", ""].forEach(function(label) {
        head.append($("<th>").text(label));
    });
    table.append($("<thead>").append(head));

    var body = $("<tbody>");
    page.data.forEach(function(match) {
        var row = $("<tr>").attr("data-match-id", match.id);
        if (QA_CAN_DOWNLOAD) {
            var box = $('<input type="checkbox" class="form-check-input qa-select">').val(match.id);
            if (!match.local) {
                box.prop("disabled", true).attr("title", "stored on node " + match.node);
            }
            row.append($("<td>").append(box));
        }
        row.append($('<td class="qa-file-name">').text(match.file_name));
        row.append($('<td class="qa-sha256">').append($("<code>").text(match.sha256.substring(0, 16) + "…").attr("title", match.sha256)));
        row.append($("<td>").text(qa_size(match.file_size)));
        row.append($("<td>").append($("<code>").text(qa_short_version(match.signature_version)).attr("title", match.signature_version)));
        row.append($("<td>").text(match.hit_count));
        row.append($("<td>").text(qa_date(match.first_seen)));
        row.append($("<td>").text(qa_date(match.last_seen)));
        row.append($("<td>").text(qa_date(match.expires_at)));
        row.append($("<td>").text(match.node));

        var actions = $('<td class="text-nowrap">');
        actions.append('<button type="button" class="btn btn-xs btn-outline-secondary qa-view-match">Match</button> ');
        if (QA_CAN_DOWNLOAD) {
            if (match.local) {
                actions.append($('<a class="btn btn-xs btn-outline-dark" title="password: infected">Download</a>')
                    .attr("href", QA_API + "/matches/" + match.id + "/download"));
            } else {
                actions.append($('<span class="small text-muted">').text("on " + match.node));
            }
        }
        if (match.alert_uuid) {
            actions.append(" ").append($('<a class="btn btn-xs btn-outline-primary" target="_blank" rel="noopener">Alert</a>')
                .attr("href", QA_ALERT_URL + "?direct=" + encodeURIComponent(match.alert_uuid)));
        }
        row.append(actions);
        body.append(row);
    });
    table.append(body);

    var pager = $('<div class="d-flex align-items-center gap-2">');
    var first = page.offset + 1;
    var last = page.offset + page.data.length;
    pager.append($('<button type="button" class="btn btn-xs btn-outline-secondary qa-match-prev">&laquo;</button>').prop("disabled", page.offset === 0));
    pager.append($('<button type="button" class="btn btn-xs btn-outline-secondary qa-match-next">&raquo;</button>').prop("disabled", last >= page.total));
    pager.append($('<span class="small text-muted">').text(first + "–" + last + " of " + page.total + " stored files"));

    target.empty().append(table).append(pager);
}

function qa_selected_ids(cell) {
    return cell.find(".qa-select:checked").map(function() { return $(this).val(); }).get();
}

function qa_update_selection(cell) {
    var count = qa_selected_ids(cell).length;
    cell.find(".qa-download-selected").prop("disabled", count === 0)
        .text(count ? "Download selected (" + count + ")" : "Download selected");
}

function qa_show_match(match_id) {
    var body = $("#qa_match_modal_body").html('<span class="text-muted">Loading…</span>');
    $("#qa_match_modal_label").text("Match " + match_id);
    $("#qa_match_modal_record").attr("href", QA_API + "/matches/" + match_id + "/record");
    bootstrap.Modal.getOrCreateInstance(document.getElementById("qa_match_modal")).show();

    qa_request(QA_API + "/matches/" + match_id).then(function(match) {
        var summary = match.match_summary || {};
        var info = $('<dl class="row small mb-3">');
        [["Rule", summary.rule], ["Namespace", summary.namespace], ["Version", match.signature_version],
         ["File", match.file_name], ["SHA256", match.sha256], ["Analysis", match.root_uuid],
         ["Tags", (summary.tags || []).join(", ")], ["String matches", summary.string_match_count]].forEach(function(item) {
            info.append($('<dt class="col-sm-3">').text(item[0]));
            info.append($('<dd class="col-sm-9 text-break">').text(item[1] === undefined || item[1] === null ? "" : item[1]));
        });

        var strings = $('<table class="table table-sm table-bordered small">');
        strings.append("<thead><tr><th>String</th><th>Matches</th><th>First offset</th></tr></thead>");
        var rows = $("<tbody>");
        (summary.strings || []).forEach(function(s) {
            rows.append($("<tr>")
                .append($("<td>").append($("<code>").text(s.identifier)))
                .append($("<td>").text(s.count))
                .append($("<td>").text(s.first_offset === null ? "" : "0x" + s.first_offset.toString(16))));
        });
        strings.append(rows);

        var meta = $('<pre class="small bg-light p-2 mb-0" style="max-height: 16rem; overflow: auto;">')
            .text(JSON.stringify(summary.meta || {}, null, 2));

        body.empty().append(info).append("<h6>Strings</h6>").append(strings).append("<h6>Meta</h6>").append(meta);
        if (!match.local) {
            body.append($('<p class="small text-muted mt-2 mb-0">').text(
                "The full match record and the file are stored on node " + match.node + "."));
        }
    }).catch(function(error) {
        body.html('<span class="text-danger"></span>').find("span").text("Unable to load match: " + error.message);
    });
}

function qa_reload_from_start() {
    qa_state.offset = 0;
    qa_collapse();
    qa_load_signatures();
}

$(document).ready(function() {
    QA_PAGE = $("#yara_qa_page");
    QA_API = QA_PAGE.data("api");
    QA_ALERT_URL = QA_PAGE.data("alert-url");
    QA_CAN_DOWNLOAD = String(QA_PAGE.data("can-download")) === "true";

    $("#qa_filters").on("submit", function(event) {
        event.preventDefault();
        qa_reload_from_start();
    });
    $("#qa_status, #qa_has_matches, #qa_sort, #qa_descending, #qa_limit").on("change", qa_reload_from_start);
    $("#qa_reset").on("click", function() {
        $("#qa_q").val("");
        $("#qa_status").val("qa");
        $("#qa_has_matches").val("");
        $("#qa_sort").val("name");
        $("#qa_descending").prop("checked", false);
        $("#qa_limit").val("50");
        qa_reload_from_start();
    });

    $("#qa_prev").on("click", function() {
        qa_state.offset = Math.max(0, qa_state.offset - parseInt($("#qa_limit").val(), 10));
        qa_collapse();
        qa_load_signatures();
    });
    $("#qa_next").on("click", function() {
        qa_state.offset += parseInt($("#qa_limit").val(), 10);
        qa_collapse();
        qa_load_signatures();
    });

    var rows = $("#qa_signature_rows");
    rows.on("click", "tr.qa-signature-row", function(event) {
        if ($(event.target).closest(".qa-copy").length) {
            return;
        }
        var uuid = $(this).data("uuid");
        if (qa_state.expanded === uuid) {
            qa_collapse();
        } else {
            qa_expand($(this), uuid, true);
        }
    });
    rows.on("click", ".qa-copy", function(event) {
        event.stopPropagation();
        var uuid = $(this).closest("tr").data("uuid");
        if (navigator.clipboard) {
            navigator.clipboard.writeText(uuid);
        }
    });
    rows.on("change", ".qa-version", function() {
        var cell = $(this).closest("td");
        qa_state.version = $(this).val();
        qa_state.match_offset = 0;
        qa_update_download_all(cell, qa_state.expanded);
        qa_load_matches(cell, qa_state.expanded);
    });
    rows.on("click", ".qa-match-prev, .qa-match-next", function() {
        var cell = $(this).closest("tr.qa-detail-row > td");
        var step = $(this).hasClass("qa-match-next") ? QA_MATCH_PAGE_SIZE : -QA_MATCH_PAGE_SIZE;
        qa_state.match_offset = Math.max(0, qa_state.match_offset + step);
        qa_load_matches(cell, qa_state.expanded);
    });
    rows.on("change", ".qa-select, .qa-select-all", function() {
        var cell = $(this).closest("tr.qa-detail-row > td");
        if ($(this).hasClass("qa-select-all")) {
            cell.find(".qa-select:not(:disabled)").prop("checked", $(this).is(":checked"));
        }
        qa_update_selection(cell);
    });
    rows.on("click", ".qa-download-selected", function() {
        var cell = $(this).closest("tr.qa-detail-row > td");
        var params = new URLSearchParams();
        qa_selected_ids(cell).forEach(function(id) {
            params.append("match_id", id);
        });
        window.location.href = QA_API + "/" + encodeURIComponent(qa_state.expanded) + "/download?" + params.toString();
    });
    rows.on("click", ".qa-view-match", function() {
        qa_show_match($(this).closest("tr").data("match-id"));
    });

    qa_load_signatures();
});
