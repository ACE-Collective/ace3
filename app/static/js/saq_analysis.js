//
// javascript functions for the analysis view
//

// this gets loaded when the document loads up
var current_alert_uuid = null;
var ownership_check_failures = 0;
var last_successful_check = null;
var FAILURE_WARNING_THRESHOLD = 3;

function update_status_display(status, is_locked) {
    var el = $("#alert-status-value");
    if (is_locked) {
        el.html(
            '<span class="badge text-bg-warning">' +
            '<span class="bi bi-lock-fill"></span> ' +
            $("<span>").text(status).html() +
            ' &mdash; locked actions are disabled until analysis completes</span>'
        );
    } else {
        el.text(status);
    }
}

function update_lock_ui(is_locked) {
    $(".lock-dependent").each(function() {
        var el = $(this);
        // <button>/<input> honor the disabled property; <a> dropdown items do not, so also
        // toggle Bootstrap's .disabled class (which greys the item and sets pointer-events:none,
        // blocking the wired click handler) and mirror the state with aria-disabled.
        el.prop("disabled", is_locked);
        el.toggleClass("disabled", is_locked);
        el.attr("aria-disabled", is_locked ? "true" : null);
        var tooltip = bootstrap.Tooltip.getInstance(el[0]);
        if (tooltip) tooltip.dispose();
        if (is_locked) {
            new bootstrap.Tooltip(el[0], { title: "alert is currently locked" });
        }
    });
}

function format_time_ago(date) {
    var seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 30) return "just now";
    if (seconds < 60) return "less than a minute ago";
    var minutes = Math.floor(seconds / 60);
    if (minutes === 1) return "1 minute ago";
    if (minutes < 60) return minutes + " minutes ago";
    var hours = Math.floor(minutes / 60);
    if (hours === 1) return "about 1 hour ago";
    return "about " + hours + " hours ago";
}

function check_alert_meta() {
    try {
        if (current_alert_uuid == null)
            return;

        var params = new URLSearchParams({ direct: current_alert_uuid });
        fetch("get_alert_meta?" + params.toString(), {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error("HTTP " + response.status);
            }
            return response.json();
        })
        .then(function(data) {
            ownership_check_failures = 0;
            last_successful_check = Date.now();
            $("#ownership_check_warning").addClass("d-none");

            // update lock state and status field
            var is_locked = data["is_locked"] === true;
            var new_status = data["status"] || current_alert_status;
            var lock_changed = is_locked !== current_alert_is_locked;
            var status_changed = new_status !== current_alert_status;

            if (lock_changed) {
                current_alert_is_locked = is_locked;
                update_lock_ui(is_locked);
            }
            if (lock_changed || status_changed) {
                current_alert_status = new_status;
                update_status_display(new_status, is_locked);
            }

            var response_owner_id = data["owner_id"] != null ? Number(data["owner_id"]) : null;
            var local_owner_id = current_alert_owner_id != null ? Number(current_alert_owner_id) : null;

            if (response_owner_id !== null && response_owner_id !== local_owner_id) {
                current_alert_owner_id = response_owner_id;
                $("#alert_thief").text(data["owner_name"]);

                if (data["owner_time"]) {
                    var ownerDate = new Date(data["owner_time"]);
                    $("#alert_ownership_time").text(format_time_ago(ownerDate));
                } else {
                    $("#alert_ownership_time").text("just now");
                }

                $("#alert_ownership_changed_modal").modal("show");
            }
        })
        .catch(function(error) {
            ownership_check_failures++;
            console.log("failed to check alert meta: " + error);
            if (ownership_check_failures >= FAILURE_WARNING_THRESHOLD) {
                $("#ownership_check_warning").removeClass("d-none");
            }
        });
    } catch(error) {
        console.log("unable to check alert meta: " + error);
    } finally {
        setTimeout(check_alert_meta, 5000);
    }
}

$(document).ready(function() {
//$(window).load(function() {
// debugger; // FREAKING AWESOME

    check_alert_meta();

    // apply initial lock state
    if (typeof current_alert_is_locked !== "undefined" && current_alert_is_locked) {
        update_lock_ui(true);
        update_status_display(current_alert_status, true);
    }

    // Triggered when the modal is shown
    $('#disposition_modal').on('shown.bs.modal', function(e) {

        // Get the disposition value
        var disposition = $(e.relatedTarget).data('disposition');

        // Send a click to the radio button so that the hide/show save to event action happens. Just
        // setting the radio "checked" property to "true" will not work for this.
        $("#option_" + disposition).click();
    });

    // Reset directive selection when add observable modal opens
    $('#add_observable_modal').on('show.bs.modal', function () {
        $("#add_observable_directives_multiselect").val([]);
        $("#add_observable_directives_text").val("");
        $("#add_observable_directives_multiselect_container").show();
        $("#add_observable_directives_text_container").hide();
    });

    $("#add_observable_type").change(function (e) {
        const observable_type = $("#add_observable_type option:selected").text();
        var add_observable_input = document.getElementById("add_observable_value");
        var directives_multiselect = $("#add_observable_directives_multiselect");
        var directives_multiselect_container = $("#add_observable_directives_multiselect_container");
        var directives_text_container = $("#add_observable_directives_text_container");

        // Reset directive selection
        directives_multiselect.val([]);
        $("#add_observable_directives_text").val("");

        // Toggle directive input type based on observable type
        if (['email_address', 'user'].includes(observable_type)) {
            directives_multiselect_container.hide();
            directives_text_container.show();
        } else {
            directives_text_container.hide();
            directives_multiselect_container.show();
        }

        // Auto-select 'sandbox' for file types
        if (observable_type === 'file') {
            directives_multiselect.val(['sandbox']);
        }

        // Handle observable value input type changes
        if (!['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation', 'file'].includes(observable_type)) {
            add_observable_input.parentNode.removeChild(add_observable_input);
            $("#add_observable_value_content").append('<input type="text" class="form-control" id="add_observable_value" name="add_observable_value" value="" placeholder="Enter Value"/>');
        } else if (observable_type !== 'file') {
            add_observable_input.parentNode.removeChild(add_observable_input);
            let placeholder_src = JSON.parse(window.localStorage.getItem("placeholder_src"));
            let placeholder_dst = JSON.parse(window.localStorage.getItem("placeholder_dst"));
            $("#add_observable_value_content").append('<span id="add_observable_value"><input class="form-control" type="text" name="add_observable_value_A" id="add_observable_value_A" value="" placeholder="' + placeholder_src[observable_type] + '"> to ' +
                '<input class="form-control" type="text" name="add_observable_value_B" id="add_observable_value_B" value="" placeholder="' + placeholder_dst[observable_type] + '"></span>');
        } else {
            $("#add_observable_modal").modal("hide");
            $("#file_modal").modal("show");
        }
    });

    $("#btn-submit-comment").click(function(e) {
        $("#comment-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#comment-form").append('<input type="hidden" name="redirect" value="analysis" />');
        $("#comment-form").submit();
    });

    $("#tag-form").submit(function(e) {
        $("#tag-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#tag-form").append('<input type="hidden" name="redirect" value="analysis" />');
    });

    $("#tag-remove-form").submit(function(e) {
        $("#tag-remove-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#tag-remove-form").append('<input type="hidden" name="redirect" value="analysis" />');
    });

    $("#btn-submit-tags").click(function(e) {
        $("#tag-form").submit();
    });

    $("#btn-submit-tags-remove").click(function(e) {
        $("#tag-remove-form").submit();
    });

    $("#btn-save-to-event").click(function(e) {
        let disposition = $("input[name='disposition']:checked").val()
        let disposition_comment = $("textarea[name='comment']").val()

        // Inject the alert uuid, disposition, and comment to the event form. This way alerts that are going to be added to an
        // event are NOT dispositioned prior to being added to the event. This caused an issue with the analysis module
        // that changes the analysis mode to "event", but it also lets analysts back out of the modal if they realize
        // they don't want to disposition the alerts or add them to an event after all.
        $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + current_alert_uuid + '" />');
        $("#event-form").append('<input type="hidden" name="disposition" value="' + disposition + '" />');
        $("#event-form").append('<input type="hidden" name="disposition_comment" value="' + disposition_comment + '" />');

    });

    $("#btn-open-event-modal").click(function(e) {
        // Inject the alert uuid into the event form for direct "Add to Event" (without disposition)
        $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + current_alert_uuid + '" />');
    });

    $("#btn-disposition-and-remediate").click(function(e) {
        // set the disposition of selected alerts
        disposition = $("input[name='disposition']:checked").val();
        comment = $("textarea[name='comment']").val();
        (function() {
            const params = new URLSearchParams({
                alert_uuids: current_alert_uuid,
                disposition: disposition,
                disposition_comment: comment
            });
            fetch('set_disposition', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: params,
                credentials: 'same-origin'
            })
            .then(function(resp){
                if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            })
            .then(function(){
                show_remediation_targets([current_alert_uuid]);
            })
            .catch(function(err){
                alert('Failed to set disposition: ' + err.message);
            });
        })();
    });

    //$('#btn-stats').click(function(e) {
        //e.preventDefault();
        /*var panel = $.jsPanel({
            position: "center",
            title: "Default Title",
            //content: $(".jsPanel-content"),
            size: { height: 270, width: 430 }
        });
        panel.on("jspanelloaded", function(event, id) {
            graph_alert($(".jsPanel-content")[0]);
        });*/

        //graph_alert($("#visualization")[0]);
    //});

    $('#btn-assign-ownership').click(function(e) {
        // add a hidden field to the form and then submit
        $("#assign-ownership-form").append('<input type="hidden" name="alert_uuid" value="' + current_alert_uuid + '" />').submit();
    });

    $("#btn-analyze_alert").click(function(e) {
        $('#analyze-alert-form').submit();
    });

    $("#btn-toggle-prune-volatile").click(function(e) {
        $('#toggle-prune-form-volatile').submit();
    });

    // pull this out of the disposition form
    current_alert_uuid = $("#alert_uuid").prop("value");

    // event times setup
    document.getElementById("event_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("alert_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("ownership_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("disposition_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("contain_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("remediation_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");

    $('input[name="event_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="alert_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="ownership_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="disposition_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="contain_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="remediation_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    // add observable time setup
    $('input[name="add_observable_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    // add observable expiration time setup
    $('input[name="observable_expiration_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    // Handle "Jump To Analysis" links with smooth scrolling and highlight
    function scrollToAndHighlight(targetId) {
        var target = document.getElementById(targetId);
        if (!target) return;

        var applyHighlight = function() {
            target.classList.add('jump-highlight');
            setTimeout(function() {
                target.classList.remove('jump-highlight');
            }, 2000);
        };

        // If already in view, scrollIntoView is a no-op and 'scrollend'
        // may never fire — flash now and skip the listener.
        var rect = target.getBoundingClientRect();
        if (rect.top >= 0 && rect.bottom <= window.innerHeight) {
            applyHighlight();
            return;
        }

        // Defer the highlight until smooth scrolling lands. Listen for
        // 'scrollend' (one-shot) with a fallback timer in case the event
        // isn't supported or never fires.
        var fired = false;
        var onEnd = function() {
            if (fired) return;
            fired = true;
            window.removeEventListener('scrollend', onEnd);
            applyHighlight();
        };
        window.addEventListener('scrollend', onEnd, { once: true });
        setTimeout(onEnd, 1200);

        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // Handle clicks on "Jump To Analysis" links
    $(document).on('click', 'a[href^="#"]', function(e) {
        var href = $(this).attr('href');
        if (href && href.length > 1) {
            var targetId = href.substring(1);
            var target = document.getElementById(targetId);
            if (target) {
                e.preventDefault();
                history.pushState(null, null, href);
                scrollToAndHighlight(targetId);
            }
        }
    });

    // Handle initial page load with hash in URL
    if (window.location.hash && window.location.hash.length > 1) {
        function tryScrollToHash() {
            setTimeout(function() {
                scrollToAndHighlight(window.location.hash.substring(1));
            }, 100);
        }

        if (document.readyState === 'complete') {
            // Page already fully loaded, scroll now
            tryScrollToHash();
        } else {
            // Wait for page to finish loading
            $(window).on('load', tryScrollToHash);
        }
    }

    // === Breadcrumb Navigation ===

    var manualBreadcrumbTime = 0;
    var breadcrumbDebounceTimer = null;

    // Walk up the DOM from an observable <li> to build the ancestry chain.
    // Returns array of {id, type, value} objects, root-first.
    // Note: The template renders <li> and <ul> as siblings, so the parent
    // observable <li> is a preceding sibling of an ancestor <ul>, not an
    // ancestor element itself. We must walk up through parent elements and
    // check for preceding sibling <li>.saq-observable-node at each level.
    function getObservableAncestry(liElement) {
        var ancestry = [];
        var current = $(liElement);

        while (current.length && current.hasClass('saq-observable-node')) {
            ancestry.unshift({
                id: current.attr('id'),
                type: current.data('observable-type'),
                value: current.data('observable-value')
            });
            var found = $();
            var node = current.parent();
            while (node.length && node.prop('tagName')) {
                var prev = node.prevAll('li.saq-observable-node').first();
                if (prev.length) {
                    found = prev;
                    break;
                }
                node = node.parent();
            }
            current = found;
        }

        return ancestry;
    }

    // Render the breadcrumb bar from an ancestry array.
    function renderBreadcrumb(ancestry) {
        var $bar = $('#breadcrumb_bar');
        var $ol = $('#breadcrumb');

        if (!ancestry || ancestry.length === 0) {
            $bar.hide();
            return;
        }

        $ol.empty();

        // First item: "Alert" root
        $ol.append(
            '<li class="breadcrumb-item">' +
            '<a href="#" class="breadcrumb-scroll-top">Alert</a>' +
            '</li>'
        );

        ancestry.forEach(function(node, index) {
            var isLast = (index === ancestry.length - 1);
            var typeHtml = '<span class="breadcrumb-type">' + $('<span>').text(node.type).html() + '</span>';
            var valueHtml = '<span class="breadcrumb-value" title="' + $('<span>').text(node.value).html() + '">' + $('<span>').text(node.value).html() + '</span>';
            var displayText = typeHtml + ' ' + valueHtml;

            if (isLast) {
                $ol.append(
                    '<li class="breadcrumb-item active" aria-current="page">' + displayText + '</li>'
                );
            } else {
                $ol.append(
                    '<li class="breadcrumb-item">' +
                    '<a href="#" class="breadcrumb-nav-link" data-target-id="' + node.id + '">' +
                    displayText + '</a></li>'
                );
            }
        });

        $bar.show();
    }

    // Expand collapsed parent nodes and scroll to target.
    function expandAndScrollTo(targetId) {
        var target = document.getElementById(targetId);
        if (!target) return;

        // Expand any hidden ancestor <ul> elements
        $(target).parents('ul').each(function() {
            if ($(this).css('display') === 'none') {
                $(this).show();
                // Update the toggle icon on the preceding <li>
                $(this).prev('li').find('.toggle-icon.bi-chevron-right')
                    .removeClass('bi-chevron-right')
                    .addClass('bi-chevron-down');
            }
        });

        scrollToAndHighlight(targetId);
    }

    // Click handler: navigate button on observables
    $(document).on('click', '.saq-breadcrumb-btn', function(e) {
        e.stopPropagation();
        var $li = $(this).closest('li.saq-observable-node');
        if ($li.length) {
            manualBreadcrumbTime = Date.now();
            var ancestry = getObservableAncestry($li[0]);
            renderBreadcrumb(ancestry);
        }
    });

    // Click handler: breadcrumb item navigation
    $(document).on('click', '.breadcrumb-nav-link', function(e) {
        e.preventDefault();
        var targetId = $(this).data('target-id');
        if (targetId) {
            expandAndScrollTo(targetId);
            // Update breadcrumb to show this node as the active one
            var target = document.getElementById(targetId);
            if (target && $(target).hasClass('saq-observable-node')) {
                manualBreadcrumbTime = Date.now();
                renderBreadcrumb(getObservableAncestry(target));
            }
        }
    });

    // Click handler: scroll to top from "Alert" breadcrumb item
    $(document).on('click', '.breadcrumb-scroll-top', function(e) {
        e.preventDefault();
        var contentArea = document.getElementById('content_area');
        if (contentArea) {
            contentArea.scrollTo({ top: 0, behavior: 'smooth' });
        }
    });

    // IntersectionObserver: auto-update breadcrumb on scroll
    var contentArea = document.getElementById('content_area');
    if (contentArea) {
        var observer = new IntersectionObserver(function(entries) {
            // Skip if user recently clicked the navigate button
            if (Date.now() - manualBreadcrumbTime < 3000) return;

            // Find the first intersecting observable
            var intersecting = null;
            for (var i = 0; i < entries.length; i++) {
                if (entries[i].isIntersecting) {
                    intersecting = entries[i].target;
                    break;
                }
            }

            if (intersecting) {
                // Debounce
                clearTimeout(breadcrumbDebounceTimer);
                breadcrumbDebounceTimer = setTimeout(function() {
                    if (Date.now() - manualBreadcrumbTime < 3000) return;
                    var ancestry = getObservableAncestry(intersecting);
                    renderBreadcrumb(ancestry);
                }, 100);
            }
        }, {
            root: contentArea,
            rootMargin: '-10% 0px -85% 0px',
            threshold: 0
        });

        // Observe all observable nodes
        document.querySelectorAll('.saq-observable-node').forEach(function(el) {
            observer.observe(el);
        });
    }

});

// attachment downloading
var $download_element;

function download_url(url) {
    if ($download_element) {
        $download_element.attr('src', url);
    } else {
        $download_element = $('<iframe>', { id: 'download_element', src: url }).hide().appendTo('body');
    }
}

function graph_alert(container) {
    (function() {
        const params = new URLSearchParams({ alert_uuid: current_alert_uuid });
        fetch('/json?' + params.toString(), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function(resp){
            if (!resp.ok) { throw new Error(resp.statusText); }
            return resp.json();
        })
        .then(function(data){
            var nodes = new vis.DataSet(data['nodes']);
            // create an array with edges
            var edges = new vis.DataSet(data['edges']);
            // create a network
            // this must be an actual DOM element
            //var container = $(".jsPanel-content")[0];
            var data = {
                nodes: nodes,
                edges: edges
            };
            var options = {
                nodes: {
                    shape: "dot",
                    size: 10 },
                layout: {
                    /*hierarchical: {
                        enabled: true,
                        sortMethod: 'directed'
                    }*/
                }
            };

            var network = new vis.Network(container, data, options);
            network.stopSimulation();
            network.stabilize();

            // turn off the physics engine once it's stabilized
            network.once("stabilized", function() {
                // don't let it run stabilize again
                network.on("startStabilizing", function() {
                    network.stopSimulation();
                });

                //network.setOptions({
                    //physics: { enabled: false }
                //});
                network.fit();
            });

            network.on("click", function() {
            });

            network.on("resize", function() {
                network.fit();
            });
    
            network.on("selectNode", function(e) {
                for (var i = 0; i < e.nodes.length; i++) {
                    var node = data.nodes.get(e.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.details, saved_label: node.label, font: { background: 'white' }});
                    }

                    if ('observable_uuid' in node && 'module_path' in node) {
                        var new_window = window.open("/analysis?observable_uuid=" + node.observable_uuid + "&module_path=" + encodeURIComponent(node.module_path), "");
                        if (new_window) { } else { alert("Unable to open a new window (adblocker?)"); }
                    }
                }
            });

            network.on("deselectNode", function(e) {
                for (var i = 0; i < e.previousSelection.nodes.length; i++) {
                    var node = data.nodes.get(e.previousSelection.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.saved_label});
                    }
                }
            });

            $("#btn-fit-to-window").click(function(e) {
                network.fit();
            });
        })
        .catch(function(){
            alert('DOH');
        });
    })();
}

function delete_comment(comment_id) {
    if (! confirm("Delete comment?")) 
        return;

    try {
        $("#comment_id").val(comment_id.toString());
    } catch (e) {
        alert(e);
        return;
    }

    $("#delete_comment_form").submit();
}

// observable comment functions — AJAX to FastAPI at /api/v2/observable-comments/
function show_observable_comment_modal_for(obsType, obsValue) {
    $('#obs_comment_type').val(obsType);
    $('#obs_comment_value').val(obsValue);
    $('#obs_comment_text').val('');
    $('#obs_comment_edit_id').val('');
    $('#obs_comment_modal_title').text('Add Observable Comment');
    var modal = new bootstrap.Modal(document.getElementById('observable_comment_modal'));
    modal.show();
}

function submit_observable_comment() {
    var commentId = $('#obs_comment_edit_id').val();
    var commentText = $('#obs_comment_text').val().trim();
    if (!commentText) { alert('Comment cannot be empty'); return; }

    if (commentId) {
        // edit existing comment
        $.ajax({
            url: '/api/v2/observable-comments/' + commentId,
            method: 'PATCH',
            contentType: 'application/json',
            data: JSON.stringify({ comment: commentText }),
            success: function() { window.location.reload(); },
            error: function(xhr) {
                var msg = 'Error updating comment';
                try { msg = JSON.parse(xhr.responseText).detail; } catch(e) {}
                alert(msg);
            }
        });
    } else {
        // create new comment
        var obsType = $('#obs_comment_type').val();
        var obsValue = $('#obs_comment_value').val();
        $.ajax({
            url: '/api/v2/observable-comments/',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                observable_type: obsType,
                observable_value: obsValue,
                comment: commentText
            }),
            success: function() { window.location.reload(); },
            error: function(xhr) {
                var msg = 'Error adding comment';
                try { msg = JSON.parse(xhr.responseText).detail; } catch(e) {}
                alert(msg);
            }
        });
    }
}

function delete_observable_comment(commentId) {
    if (!confirm("Delete observable comment?")) return;
    $.ajax({
        url: '/api/v2/observable-comments/' + commentId,
        method: 'DELETE',
        success: function() { window.location.reload(); },
        error: function(xhr) {
            var msg = 'Error deleting comment';
            try { msg = JSON.parse(xhr.responseText).detail; } catch(e) {}
            alert(msg);
        }
    });
}

function edit_observable_comment(commentId, element) {
    var currentText = $(element).siblings('.obs-comment-text').text().trim();
    $('#obs_comment_text').val(currentText);
    $('#obs_comment_edit_id').val(commentId.toString());
    $('#obs_comment_type').val('');
    $('#obs_comment_value').val('');
    $('#obs_comment_modal_title').text('Edit Observable Comment');
    var modal = new bootstrap.Modal(document.getElementById('observable_comment_modal'));
    modal.show();
}

// sets all filters
function set_filters(filters) {
    (function() {
        const params = new URLSearchParams({ filters: JSON.stringify(filters) });
        fetch('set_filters?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){ if (!resp.ok) { throw new Error(resp.statusText); } })
        .then(function(){ window.location = '/ace/manage'; })
        .catch(function(err){ alert('DOH: ' + err.message); });
    })();
}

// This is kind of gross, but it does the job until we have proper searching/filtering routes.
function filter_events_by_observable_and_status(o_type, o_value, event_status) {
    $(document).ready(function(){
        $('<form action="/ace/events/manage" method="POST">' +
            '<input type="hidden" name="filter_observable_type" value="' + o_type + '"/>' +
            '<input type="hidden" name="filter_observable_value" value="' + o_value + '"/>' +
            '<input type="hidden" name="filter_event_status" value="' + event_status + '"/>' +
            '<input type="hidden" name="filter_event_type" value="ANY"/>' +
            '<input type="hidden" name="filter_event_vector" value="ANY"/>' +
            '<input type="hidden" name="filter_event_prevention_tool" value="ANY"/>' +
            '<input type="hidden" name="filter_event_risk_level" value="ANY"/>' +
            '</form>'
        ).appendTo('body').submit();
    });
}

// sets the owner of the alert
function set_owner(alert_uuid) {
    (function() {
        const params = new URLSearchParams();
        params.append('alert_uuids', alert_uuid);
        fetch('set_owner?' + params.toString(), { credentials: 'same-origin' })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            window.location.replace(window.location);
        })
        .catch(function(err){ alert(err.message); });
    })();
}

function toggleCollapseAll(button) {
    var card = $(button).closest('.card');
    var isCollapsing = $(button).find('i').hasClass('bi-arrows-collapse');

    if (isCollapsing) {
        card.find('.toggle-icon.bi-chevron-down').each(function() {
            collapseTree(this);
        });
        $(button).html('<i class="bi bi-arrows-expand"></i> Expand All');
    } else {
        card.find('.toggle-icon.bi-chevron-right').each(function() {
            collapseTree(this);
        });
        $(button).html('<i class="bi bi-arrows-collapse"></i> Collapse All');
    }
}

// collapses ul that exist under li
function collapseTree(element) {
    var nextElement = $(element).parent().next();
    var nextNextElement = $(element).parent().next().next();
    
    if(nextElement.is('a') && nextNextElement.is('ul')) {
        nextNextElement.toggle();
    } else if (nextElement.is('ul')) {
        nextElement.toggle();
    }

    $(element).toggleClass('bi-chevron-down').toggleClass('bi-chevron-right');

    var last = $(element).siblings().last();
    if (last.attr('name') == 'observable_preview') {
        last.toggle();
    }
}

const INDENT_GUIDE_STORAGE_KEY = 'ace.analysisIndentGuide';

function toggleIndentGuide(button) {
    var card = document.getElementById('analysis-overview-card');
    if (!card) return;
    var enabled = card.classList.toggle('indent-rainbow');
    $(button).toggleClass('active', enabled);
    window.localStorage.setItem(INDENT_GUIDE_STORAGE_KEY, JSON.stringify(enabled));
}

$(function() {
    var card = document.getElementById('analysis-overview-card');
    if (!card) return;

    card.querySelectorAll('ul').forEach(function(ul) {
        var depth = 0;
        var ancestor = ul.parentElement;
        while (ancestor && ancestor !== card) {
            if (ancestor.tagName === 'UL') depth++;
            ancestor = ancestor.parentElement;
        }
        if (depth > 0) {
            ul.dataset.indentDepth = (depth - 1) % 7;
        }
    });

    var stored = window.localStorage.getItem(INDENT_GUIDE_STORAGE_KEY);
    if (stored && JSON.parse(stored) === true) {
        card.classList.add('indent-rainbow');
        $('#btn-toggle-indent-guide').addClass('active');
    }

    $(card).on('click', 'ul[data-indent-depth]', function(event) {
        if (!card.classList.contains('indent-rainbow')) return;
        if (event.target !== this) return;
        var rect = this.getBoundingClientRect();
        var relativeX = event.clientX - rect.left;
        if (relativeX < -4 || relativeX > 6) return;
        var prevLi = this.previousElementSibling;
        if (!prevLi || prevLi.tagName !== 'LI') return;
        var toggleIcon = prevLi.querySelector(':scope > .toggle-icon');
        if (toggleIcon) collapseTree(toggleIcon);
    });

    var breadcrumbBar = document.getElementById('breadcrumb_bar');
    function updateAnalysisOverviewStickyTop() {
        var top = (breadcrumbBar && breadcrumbBar.offsetParent !== null) ? breadcrumbBar.offsetHeight : 0;
        card.style.setProperty('--analysis-overview-sticky-top', top + 'px');
    }
    updateAnalysisOverviewStickyTop();
    if (breadcrumbBar) {
        new MutationObserver(updateAnalysisOverviewStickyTop).observe(breadcrumbBar, {
            attributes: true,
            attributeFilter: ['style']
        });
        window.addEventListener('resize', updateAnalysisOverviewStickyTop);
    }
});
