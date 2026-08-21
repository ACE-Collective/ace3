(function () {
  // Reconstructs a URL from char codes held in a sibling element's data-*
  // attributes, appends a base64 token from a second attribute, and navigates
  // there -- but only when the button is clicked. The URL is nowhere in this
  // script; it lives entirely in the DOM the script reads at runtime.
  function decodeBase() {
    var el = document.getElementById("cb0705c");
    if (!el) return "";
    var raw = el.getAttribute("data-u7fb") || "";
    if (!raw) return "";
    var codes = raw.split(","), out = "", i;
    for (i = 0; i < codes.length; i++) out += String.fromCharCode(+codes[i]);
    return out;
  }
  function join(base, extra) {
    if (!extra) return base;
    var root = String(base).replace(/\/$/, "");
    return root + "/" + extra;
  }
  function go() {
    try {
      var base = decodeBase();
      if (!base) return;
      var token = document.getElementById("cb0705c").getAttribute("data-token") || "";
      top.location = join(base, token);
    } catch (e) {}
  }
  function boot() {
    var btn = document.getElementById("b47c467");
    if (btn) btn.addEventListener("click", go);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
