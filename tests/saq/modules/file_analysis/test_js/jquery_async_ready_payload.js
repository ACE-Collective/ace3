// Synthesized (NOT sample-derived). The dominant modern phishing-kit shape:
// an ASYNC $(document).ready handler that stages its exfil call, awaits, and
// then throws deep in obfuscated member access.
//
// Two things this pins, both of which broke a real sample:
//   1. The async continuation throws after the await -> an UNHANDLED REJECTION.
//      Node's default terminates the process with a non-zero exit AFTER the
//      harness already wrote its trace + report, so the client discarded a
//      good result. The harness must record the rejection and NOT crash.
//   2. The exfil URL staged AFTER the await must still reach the trace, which
//      only happens if the harness drains the event loop before snapshotting.
$(document).ready(async function () {
  fetch("https://example.com/async-c2-pre");
  await new Promise(function (r) { setTimeout(r, 10); });
  fetch("https://example.com/async-c2-post");
  // real (non-recorder) values, mirroring the sample: a helper returns a
  // string, and calling a missing method on it throws a genuine TypeError.
  var helper = { pick: function () { return "not-callable"; } };
  helper.pick().definitelyNotAMethod();
});
