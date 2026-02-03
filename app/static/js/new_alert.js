/*MULTISELECT_SETTINGS = {
        enableFiltering: true,
        enableFullValueFiltering: true,
        dropUp: true,
        includeSelectAllOption: false,
        maxHeight: '300'
    };*/

$(document).ready(function() {
    $('input[name="new_alert_insert_date"]').datetimepicker({
      showSecond: true,
      dateFormat: 'mm-dd-yy',
      timeFormat: 'HH:mm:ss'
    });

    $('input[name="observables_times_0"]').datetimepicker({
      showSecond: true,
      dateFormat: 'mm-dd-yy',
      timeFormat: 'HH:mm:ss'
    });
    //let multiselect = $('.multiselect-ui');
    //multiselect.multiselect(MULTISELECT_SETTINGS);
    //multiselect.multiselect('select', 'sandbox');
});

function new_alert_observable() {
  var index = new Date().valueOf()
  (function() {
    const params = new URLSearchParams({ index: index });
    fetch('new_alert_observable?' + params.toString(), { credentials: 'same-origin' })
    .then(function(resp){
      if (!resp.ok) { throw new Error(resp.statusText); }
      return resp.text();
    })
    .then(function(data){
      $('#new_alert_observables').append(data);
      populateObservableTypeSelect('#observables_types_' + index, { defaultValue: 'file' });
      $('input[name="observables_times_' + index + '"]').datetimepicker({
        showSecond: true,
        dateFormat: 'mm-dd-yy',
        timeFormat: 'HH:mm:ss'
      });
    })
    .catch(function(err){
      alert('DOH: ' + err.message);
    });
  })();
}

function clear_multiselect(multiselect) {
    //multiselect.multiselect('deselectAll', false);
    //multiselect.multiselect('updateButtonText');
}

function new_alert_observable_type_changed(index) {
  var type_input = document.getElementById("observables_types_" + index);
  var value_input = document.getElementById("observables_values_" + index);
  var directives_input_multiselect = $("#observables_directives_multiselect_" + index);
  var directives_input_multiselect_container = $("#observables_directives_multiselect_container_" + index);
  var directives_input_text = $("#observables_directives_text_" + index)[0];
  var directives_input_text_container = $("#observables_directives_text_container_" + index);
  var target_input_container = $("#new_alert_observable_value_" + index);

  if (['email_address', 'user'].includes(type_input.value)) {
      directives_input_multiselect_container.hide();
      clear_multiselect(directives_input_multiselect);
      directives_input_text.value = "";
      directives_input_text_container.show();

  } else {
      directives_input_text_container.hide();
      directives_input_text.value = "";
      clear_multiselect(directives_input_multiselect);
      directives_input_multiselect_container.show();
  }

  if (type_input.value === 'file') {
      directives_input_multiselect.multiselect('select', 'sandbox');
      if (value_input.type !== 'file') {
          target_input_container.html('<input class="form-control" type="file" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
      }
  } else if (['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation', 'file_location'].includes(type_input.value)) {
      value_input.parentNode.removeChild(value_input);
      let placeholder_src = JSON.parse(window.localStorage.getItem("placeholder_src"));
      let placeholder_dst = JSON.parse(window.localStorage.getItem("placeholder_dst"));
      target_input_container.html('<span class="form-inline" style="display: contents" id="observables_values_' + index + '" >' +
          '<input class="form-control" style="width:auto" type="text" name="observables_values_' + index + '_A" id="observables_values_' + index + '_A" value="" placeholder="' + placeholder_src[type_input.value] + '"> to ' +
          '<input class="form-control" style="width:auto" type="text" name="observables_values_' + index + '_B" id="observables_values_' + index + '_B" value="" placeholder="' + placeholder_dst[type_input.value] + '" title="Multiple values should be comma-separated"></span>');
  } else {
      target_input_container.html(`
  <input class="form-control" type="hidden" id="observable_data_sep_${index}" name="observable_data_sep_${index}" value="single">
  <div class="input-group" style="width:100%;">
    <span id="observable_input_container_${index}" style="flex:1;"><input class="form-control" type="text" style="width:100%;" name="observables_values_${index}" id="observables_values_${index}"/></span>
    <span class="input-group-btn">
      <button class="btn btn-outline-dark" type="button" id="observables_multi_${index}">...</button>
    </span>
  </div>`);
      /* when the click the ... button is toggles between text and textarea */
      var multi_button = $("#observables_multi_" + index);
      multi_button.click(function (e) {
          // get the index of the element
          var button_index = /_([0-9]+)$/.exec(e.target.id)[1];
          // reference to the actual input element
          var target_input_element = $("#observables_values_" + button_index)[0];
          // reference to the container so we can swap out the components
          var target_input_container = $("#observable_input_container_" + button_index);
          // figured this out in the debugger, when it's an input text field then the localName is "input"
          if (target_input_element.localName == "input") {
              // change it over to textarea control
              target_input_container.html(`<textarea class="form-control" style="width:100%;" rows=4 name="observables_values_${button_index}" id="observables_values_${button_index}"></textarea>`);
              // when we POST we indicate this is a "multi" field
              $("#observable_data_sep_" + button_index).val("multi");
              // show the additional button to submit multiple alerts
              $('#submit_type_multi').show();
              $('#observables_values_' + button_index).focus();
          } else {
              // otherwise swap it back
              target_input_container.html(`<input class="form-control" type="text" style="width:100%;" name="observables_values_${button_index}" id="observables_values_${button_index}"/>`);
              $("#observable_data_sep_" + button_index).val("single");
              $('#observables_values_' + button_index).focus();
          }
      });
  }
}

function new_alert_remove_observable(index) {
  var element = document.getElementById("new_alert_observable_" + index);
  element.parentNode.removeChild(element);
}