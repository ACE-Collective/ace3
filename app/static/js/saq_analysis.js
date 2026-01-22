//
// javascript functions for the analysis view
//

// this gets loaded when the document loads up
var current_alert_uuid = null;

function check_alert_meta() {
    try {
        if (current_alert_uuid == null)
            return;

        // Modern fetch equivalent of the above $.ajax GET request
        const params = new URLSearchParams({ direct: current_alert_uuid });
        fetch(`get_alert_meta?${params.toString()}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data["owner_id"] != null && data["owner_id"] != current_alert_owner_id) {
                current_alert_owner_id = data["owner_id"];
                $("#alert_thief").text(data["owner_name"]);
                $("#alert_ownership_changed_modal").modal("show");
            } else {
                //console.log(data);
            }
        })
        .catch(error => {
            console.log("failed: " + error);
        });
    } catch(error) {
        console.log("unable to check alert meta: " + e);
    } finally {
        setTimeout(check_alert_meta, 5000);
    }
}

$(document).ready(function() {
//$(window).load(function() {
// debugger; // FREAKING AWESOME

    check_alert_meta();

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
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            target.classList.add('jump-highlight');
            setTimeout(function() {
                target.classList.remove('jump-highlight');
            }, 1500);
        }
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
