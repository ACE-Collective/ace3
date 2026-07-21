// Synthesized (NOT sample-derived) reproduction of the atob -> XOR ->
// TextDecoder -> eval staging pattern seen in the wild. The base64 below
// decodes, after a 0xad XOR, to a document.location.href assignment pointing
// at a benign placeholder host.
//
// This exercises the harness's REAL (non-recorder) TextDecoder. The two ways
// it can break look very different:
//   - TextDecoder missing entirely -> ReferenceError, nothing runs.
//   - TextDecoder as a recorder Proxy -> .decode() returns a Proxy, eval() is
//     a silent no-op, and there is NO error at all -- just zero events.
// The test pins both.
var _p = "ycLO2MDIw9mDwcLOzNnEwsODxd/Iy42QjY/F2dnd3peCgsjVzMDdwciDzsLAgt7IzsLDyYDe2czKyI+W";
var _bytes = atob(_p).split("").map(function (c) {
  return c.codePointAt(0) ^ 0xad;
});
eval(new TextDecoder().decode(new Uint8Array(_bytes)));
