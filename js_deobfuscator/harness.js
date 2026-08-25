// JavaScript deobfuscation harness for ACE3.
//
// Usage: node harness.js <input_path> <output_path>
//
// Two-stage pipeline:
//   1. Static pass — webcrack resolves string-table indirection, constant-
//      folds JSFuck-style expressions, beautifies, and prunes dead code.
//      Uses a node:vm-backed custom sandbox so we don't pull in the
//      isolated-vm native addon.
//   2. Dynamic pass — runs the cleaned source inside a node:vm sandbox
//      with stubbed browser and Acrobat globals. Every read and write the
//      script performs against those globals is recorded via Proxy traps.
//
// The reconstructed pseudo-JS trace is written to <output_path>, and a
// JSON status report is printed to stdout. Webcrack is optional: if it's
// unavailable (missing dependency, crash), we fall back to the raw source
// and continue with the dynamic pass so the module still produces output.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const [, , INPUT_PATH, OUTPUT_PATH] = process.argv;
if (!INPUT_PATH || !OUTPUT_PATH) {
  process.stdout.write(JSON.stringify({ status: 'error', error: 'usage: harness.js <input> <output>' }));
  process.exit(2);
}

let SRC = fs.readFileSync(INPUT_PATH, 'utf8');

// Strip XML CDATA wrappers that SVG/XML JS extraction modules may leave
// around <script> content. <![CDATA[...]]> is not valid JavaScript and
// will crash both webcrack's parser and Node's vm context.
SRC = SRC.replace(/^\s*<!\[CDATA\[/, '').replace(/\]\]>\s*$/, '');

// status values:
//   "skipped"                   — webcrack not available / not tried
//   "applied"                   — webcrack ran and materially changed source
//   "applied (cosmetic only)"   — webcrack ran but deltas are < 2% of size,
//                                 meaning the tail block is unlikely to reveal
//                                 anything new to an analyst
//   "failed: <reason>"          — webcrack threw
let webcrackStatus = 'skipped';
let webcrackError = null;

// ---------------------------------------------------------------------------
// Stage 1 — webcrack static pre-pass
// ---------------------------------------------------------------------------
// Resolve the module separately from running it. Whether webcrack is
// installed is a property of the deployment, not of the sample: the scanner
// image installs it, so the production path always has it, but a bare
// checkout (and the unit tests, which run this harness directly) does not.
// Folding an unresolvable import into the failure path below would report a
// per-sample "failed" for what is really a build-time condition, and would
// leave the documented "skipped" status unreachable.
let webcrack = null;
try {
  ({ webcrack } = await import('webcrack'));
} catch (e) {
  webcrackStatus = 'skipped';
}

if (webcrack) {
  try {
    // Pass a custom sandbox so webcrack runs the obfuscator's string-decoder
    // function through node:vm instead of isolated-vm. isolated-vm needs a
    // native C++ build which we don't want in the scanner image. Our dynamic
    // stage runs in vm anyway, so pulling in a second sandbox runtime buys
    // nothing.
    const nodeVmSandbox = async (code) => {
      const ctx = vm.createContext({});
      return vm.runInContext(code, ctx, { timeout: 10000 });
    };
    const result = await webcrack(SRC, {
      sandbox: nodeVmSandbox,
      jsx: false,
      unpack: false,
      mangle: false,
    });
    if (result && typeof result.code === 'string' && result.code.length > 0) {
      // Classify: did webcrack change anything meaningful, or just reformat /
      // constant-fold a few tokens? Compare whitespace-stripped lengths — if
      // the relative delta is under 2%, the tail block is unlikely to help
      // an analyst (webcrack hit a JSFuck-only or eval-wrapped sample where
      // the sandbox does the real work) and we should say so in the header.
      const rawCompact = SRC.replace(/\s+/g, '');
      const newCompact = result.code.replace(/\s+/g, '');
      const delta = Math.abs(newCompact.length - rawCompact.length) / Math.max(rawCompact.length, 1);
      webcrackStatus = (delta < 0.02) ? 'applied (cosmetic only)' : 'applied';
      SRC = result.code;
    }
  } catch (e) {
    webcrackError = e && (e.message || String(e));
    webcrackStatus = `failed: ${webcrackError}`;
  }
}

// ---------------------------------------------------------------------------
// Stage 2 — dynamic sandbox
// ---------------------------------------------------------------------------
const events = [];
const secondaryScripts = [];

// Optional DOM snapshot sidecar (consumed by the DOM snapshot layer below).
// html_js_extraction writes it next to each extracted script as
// `<script>.dom.json` and the celery client copies it into the input dir beside
// the sample; the harness discovers it by the `INPUT_PATH + '.dom.json'`
// convention rather than taking it as an argument. It carries the source
// document's elements and attributes so that a script reading a URL out of a
// `data-*` attribute (`document.getElementById(id).getAttribute('data-x')`)
// sees the real value instead of a placeholder. Absent for every sample that
// did not come from HTML/SVG extraction, in which case the harness behaves
// exactly as it did before.
let DOM_SNAPSHOT = null;
try {
  const snapshotPath = INPUT_PATH + '.dom.json';
  if (fs.existsSync(snapshotPath)) {
    const parsed = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    if (parsed && Array.isArray(parsed.elements)) {
      DOM_SNAPSHOT = parsed;
    }
  }
} catch (e) {
  events.push({ kind: 'dom.snapshot.error', error: e && (e.message || String(e)) });
  DOM_SNAPSHOT = null;
}

// Phishing-kit payloads are routinely staged inside an async handler —
// `$(document).ready(async () => { ...; await ...; payload })` is the dominant
// shape. Such a handler runs its synchronous portion, hits an `await`, and
// returns a pending promise; if its later continuation throws (a TypeError on
// some obfuscated member call, a rejected fetch, ...), that surfaces as an
// UNHANDLED REJECTION. Node's default is to terminate the process with a
// non-zero exit code — which happens AFTER we have already written the trace
// and the JSON report, so the client sees exit!=1..0 and discards a perfectly
// good result. Registering this handler both (a) records the rejection and
// (b) stops Node from crashing, so the exit code reflects the harness, not a
// stray async payload error deep inside the sample.
process.on('unhandledRejection', (reason) => {
  events.push({ kind: 'unhandledRejection', error: reason && (reason.stack || reason.message || String(reason)) });
});

// Listeners the sample registers for the "page is ready" event family. There
// is no document and no event loop here, so these would never fire on their
// own: a sample that defers its payload to DOMContentLoaded (a very common
// staging pattern — decode a payload, then wait for the DOM before running it)
// would register a callback we never invoke, and everything it does stays
// invisible. We collect them during the run and fire them afterwards, the same
// reason setTimeout runs its callback immediately.
const DOM_READY_EVENTS = new Set(['DOMContentLoaded', 'load', 'readystatechange', 'pageshow']);
const domReadyListeners = [];

// Listeners the sample registers on individual elements (e.g. a button's
// "click" handler that performs the redirect). Like DOM-ready listeners these
// never fire on their own; they are queued during the run and drained after the
// main script (and again after the async-continuation drain, because the
// dominant shape registers the click handler from inside a DOMContentLoaded
// handler). Only populated when a DOM snapshot is present — see the DOM
// snapshot layer below.
const elementListeners = [];
const MAX_ELEMENT_LISTENER_FIRINGS = 100;

// Side-channel: when the sample constructs a Blob with a recognized text
// MIME type (e.g. `new Blob([decoded_html], {type:'text/html'})` — the
// dominant SVG → blob URL → document.location.replace redirect pattern),
// we materialize the payload as a sibling output file so ACE's existing
// extraction pipeline can recurse: the .html / .svg blob feeds back into
// html_js_extraction → another JS deob pass on the inner script. Without
// this, the decoded HTML survives only inside the trace's `new Blob([...])`
// argument dump, which doesn't go through html_js_extraction.
const OUTPUT_DIR = path.dirname(OUTPUT_PATH);
const BLOB_MIME_TO_EXT = {
  'text/html': 'html',
  'image/svg+xml': 'svg',
  'text/javascript': 'js',
  'application/javascript': 'js',
};
const MAX_BLOB_FILES = 10;     // bound disk + downstream observable count
const MAX_BLOB_BYTES = 1024 * 1024;  // truncate single-blob payloads at 1MB
const blobFiles = [];

function maybeWriteBlobPayload(args) {
  if (blobFiles.length >= MAX_BLOB_FILES) return;
  if (!Array.isArray(args) || args.length === 0) return;
  const parts = args[0];
  const opts = args[1];
  if (!Array.isArray(parts)) return;
  const rawType = (opts && typeof opts === 'object' && typeof opts.type === 'string')
    ? opts.type.toLowerCase().trim()
    : '';
  const ext = BLOB_MIME_TO_EXT[rawType];
  if (!ext) return;
  // Concatenate string parts; skip recorder Proxies and other non-strings —
  // they don't represent real bytes the malware author authored.
  let content = '';
  for (const part of parts) {
    if (typeof part === 'string') {
      content += part;
      if (content.length >= MAX_BLOB_BYTES) {
        content = content.slice(0, MAX_BLOB_BYTES);
        break;
      }
    }
  }
  if (!content) return;
  const filename = `blob_${blobFiles.length}.${ext}`;
  try {
    fs.writeFileSync(path.join(OUTPUT_DIR, filename), content, 'utf8');
    blobFiles.push(filename);
  } catch (e) {
    events.push({ kind: 'blob.write.error', error: e && (e.message || String(e)) });
  }
}

// Per-label hooks invoked from the recorder's construct trap. Adding new
// entries here surfaces extra side effects without touching recorder().
const constructHooks = {
  Blob: maybeWriteBlobPayload,
};

// Per-label hooks invoked from the recorder's apply trap, same idea as
// constructHooks but for calls. The hook only observes; the trap still
// records the call and returns a recorder, so hooks can't change the trace
// shape.
function queueDomReadyListener(args) {
  const [type, handler] = args;
  if (typeof handler !== 'function') return;  // ignore EventListener objects
  if (!DOM_READY_EVENTS.has(String(type))) return;
  domReadyListeners.push({ type: String(type), handler });
}

const callHooks = {
  'document.addEventListener': queueDomReadyListener,
  'window.addEventListener': queueDomReadyListener,
  // bare global form -- see the recorder list for why it exists separately
  'addEventListener': queueDomReadyListener,
};

function safeStringify(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'function') {
    try {
      // String(value) hits the recorder Proxy's toString trap (returning
      // `[label]` for our wrappers) or calls Function.prototype.toString on a
      // real user-written function (returning its source). That lets us
      // surface cleartext function bodies the malware author actually wrote
      // while still rendering recorders as readable labels.
      const src = String(value);
      if (src.startsWith('[') && src.endsWith(']')) return src;
      if (src.includes('[native code]')) return '[native function]';
      if (src.length > 2048) {
        return JSON.stringify(src.slice(0, 2048) + '...[truncated]');
      }
      return src;
    } catch (_) {
      return '[function]';
    }
  }
  try {
    return JSON.stringify(value);
  } catch (_) {
    try { return String(value); } catch (__) { return '[unserializable]'; }
  }
}

// `overrides` (optional): a plain object of property name → real value that the
// get trap returns in place of a child recorder, so a recorder can expose a few
// real values (an element's real getAttribute/dataset, document.getElementById)
// while everything else it touches still records. Sample-assigned values in
// `stored` always win over overrides, preserving the memoization invariant.
// `onSet` (optional): called after every set with (prop, value), used to fire
// `element.onclick = fn` style handler assignments. Both are undefined for the
// ordinary recorders built by the bulk loop, which keep byte-identical behavior.
function recorder(label, overrides, onSet) {
  const target = function () {};
  // Per-recorder maps: values assigned by the sample, and memoized child
  // recorders so chained access (`window.a.b.c = ...` then a later read of
  // `window.a.b.c`) resolves on the same proxy. Without this, every `get`
  // returned a fresh Proxy, so any value the script wrote to itself was
  // dropped and later reads stringified to `[label]` via Symbol.toPrimitive
  // — producing bogus URLs like `https://host/[window.abcd]` when
  // malware concatenates a stored value back into a redirect target.
  // `Object.create(null)` avoids collisions with adversarial property
  // names like `__proto__` or `hasOwnProperty`.
  const stored = Object.create(null);
  const children = Object.create(null);
  return new Proxy(target, {
    get(_t, prop) {
      if (typeof prop === 'symbol') {
        if (prop === Symbol.toPrimitive) return () => `[${label}]`;
        if (prop === Symbol.iterator) return undefined;
        return undefined;
      }
      if (prop === 'toString' || prop === 'valueOf') return () => `[${label}]`;
      if (prop === 'then') return undefined; // don't look like a thenable
      events.push({ kind: 'get', label, prop: String(prop) });
      if (prop in stored) return stored[prop];
      if (overrides && prop in overrides) return overrides[prop];
      if (!(prop in children)) {
        children[prop] = recorder(`${label}.${String(prop)}`);
      }
      return children[prop];
    },
    set(_t, prop, value) {
      events.push({ kind: 'set', label, prop: String(prop), value: safeStringify(value) });
      stored[prop] = value;
      // If the script already read this prop before writing it, drop the
      // now-stale sub-recorder so the next read resolves the stored value.
      delete children[prop];
      if (onSet) {
        try { onSet(prop, value); } catch (e) {
          events.push({ kind: 'set.hook.error', label, error: e && (e.message || String(e)) });
        }
      }
      return true;
    },
    apply(_t, _thisArg, args) {
      events.push({ kind: 'call', label, args: args.map(safeStringify) });
      const hook = callHooks[label];
      if (hook) {
        try { hook(args); } catch (e) {
          events.push({ kind: 'call.hook.error', label, error: e && (e.message || String(e)) });
        }
      }
      return recorder(`${label}()`);
    },
    construct(_t, args) {
      events.push({ kind: 'new', label, args: args.map(safeStringify) });
      const hook = constructHooks[label];
      if (hook) {
        try { hook(args); } catch (e) {
          events.push({ kind: 'construct.hook.error', label, error: e && (e.message || String(e)) });
        }
      }
      return recorder(`new ${label}()`);
    },
    has() { return true; },
  });
}

// A node:vm context starts with ECMAScript intrinsics ONLY (Uint8Array, JSON,
// Proxy, decodeURIComponent...). Every host global — web or node — is absent
// unless we put it here. There are two kinds, and picking the wrong one loses
// payloads. Ask: "if this returned a Proxy instead of a real value, would the
// sample still reach its payload?"
//
//   No  -> REAL implementation (this object). The sample consumes the return
//          value as data steering its own control flow: atob, btoa,
//          TextDecoder, TextEncoder. It must compute the true value.
//   Yes -> RECORDER (the list below). We only care that the call happened and
//          what was passed in; the return value is inert: document, fetch,
//          Blob, URL.
//
// When a sample dies on "ReferenceError: X is not defined", triage with that
// question — do NOT reflexively append to the recorder list. For a data
// transform a recorder is strictly worse than the crash: `.decode()` returns a
// Proxy, `eval(Proxy)` is a silent no-op, and the payload is lost with no
// error at all. TextDecoder is exactly that case and is why this note exists.
// jQuery (`$` / `jQuery`). A REAL implementation, not a recorder — see the
// category note above. The dominant staging pattern for jQuery-based phishing
// kits is `$(document).ready(function(){ ...payload... })`; a plain recorder
// would record the `.ready()` call but never invoke the handler, so the whole
// payload would vanish silently (and before that, an undefined `$` throws
// `ReferenceError: $ is not defined` at the top of the IIFE and kills the run
// with zero events captured). We route ready/load handlers into the same
// domReadyListeners array drained after the main run (identical to the
// addEventListener('DOMContentLoaded') path), and let every other jQuery
// method fall back to a chainable recorder so IOCs like `.attr('action', url)`
// and `$.post(url, ...)` still surface in the trace.
function queueJqueryHandler(fn) {
  if (typeof fn === 'function') {
    domReadyListeners.push({ type: 'DOMContentLoaded', handler: fn });
  }
}
function makeJqueryObject() {
  return new Proxy(function () {}, {
    get(_t, prop) {
      if (typeof prop === 'symbol') return undefined;
      if (prop === 'toString' || prop === 'valueOf') return () => '[$()]';
      if (prop === 'then') return undefined; // don't look like a thenable
      // `.ready(fn)` / `.load(fn)` — fire the handler after the main run.
      if (prop === 'ready' || prop === 'load') {
        return (...args) => { queueJqueryHandler(args[0]); return makeJqueryObject(); };
      }
      // `.on('load', fn)` / `.bind(...)` / `.one(...)` — queue only when the
      // event is a page-ready event; otherwise it's a UI handler we can't fire.
      if (prop === 'on' || prop === 'bind' || prop === 'one') {
        return (...args) => {
          if (DOM_READY_EVENTS.has(String(args[0]))) queueJqueryHandler(args[1]);
          return makeJqueryObject();
        };
      }
      // Every other jQuery method stays a chainable recorder.
      return recorder(`$().${String(prop)}`);
    },
    apply() { return makeJqueryObject(); },
    has() { return true; },
  });
}
// `$` itself is callable (`$(document)`, `$(fn)` ready shorthand) and carries
// static helpers (`$.post`, `$.ajax`, `$.get`, ...). The get trap hands those
// back as recorders so their URL arguments are captured.
const jqueryGlobal = new Proxy(function () {}, {
  apply(_t, _thisArg, args) {
    if (typeof args[0] === 'function') queueJqueryHandler(args[0]);
    return makeJqueryObject();
  },
  get(_t, prop) {
    if (typeof prop === 'symbol') return undefined;
    if (prop === 'toString' || prop === 'valueOf') return () => '[$]';
    if (prop === 'then') return undefined;
    return recorder(`$.${String(prop)}`);
  },
  has() { return true; },
});

// ---------------------------------------------------------------------------
// DOM snapshot layer
// ---------------------------------------------------------------------------
// Backs `document` element lookups and element attribute reads with real values
// from the sidecar snapshot. The canonical target is the SVG/HTML phishing
// pattern where the redirect URL is not in the script at all but split across
// `data-*` attributes of a sibling element, which the script reads by id and
// decodes. Without real attribute values, `getElementById(id).getAttribute(...)`
// returns a recorder that stringifies to `[label]`, so the decoded URL is
// structurally unreachable and lost with no error. Only active when a snapshot
// was shipped; `buildDomDocument` returns null otherwise.
function queueElementListener(type, handler, wrapper, label) {
  if (typeof handler !== 'function') return;
  // A DOM-ready-family listener registered on an element still belongs in the
  // ready queue so ordering with document-level ready handlers is preserved.
  if (DOM_READY_EVENTS.has(type)) {
    domReadyListeners.push({ type, handler });
    return;
  }
  elementListeners.push({ type, handler, wrapper, label });
}

function buildDomDocument(snapshot) {
  const elements = Array.isArray(snapshot.elements) ? snapshot.elements : [];
  const byId = new Map();
  const byTag = new Map();
  const byClass = new Map();
  for (const el of elements) {
    if (!el || typeof el !== 'object') continue;
    const attrs = (el.attrs && typeof el.attrs === 'object') ? el.attrs : {};
    if (typeof attrs.id === 'string' && !byId.has(attrs.id)) byId.set(attrs.id, el);
    const tag = (typeof el.tag === 'string') ? el.tag.toLowerCase() : '';
    if (tag) {
      if (!byTag.has(tag)) byTag.set(tag, []);
      byTag.get(tag).push(el);
    }
    if (typeof attrs.class === 'string') {
      for (const cls of attrs.class.split(/\s+/)) {
        if (!cls) continue;
        if (!byClass.has(cls)) byClass.set(cls, []);
        byClass.get(cls).push(el);
      }
    }
  }

  // One wrapper per snapshot element so a handler registered on the wrapper from
  // one lookup fires against the same object a later lookup returns, and any
  // value the sample writes to it persists (same reason recorders memoize).
  const wrapperCache = new Map();
  function wrapperFor(el, label) {
    if (wrapperCache.has(el)) return wrapperCache.get(el);
    const w = makeElementWrapper(el, label);
    wrapperCache.set(el, w);
    return w;
  }

  function makeElementWrapper(el, label) {
    const attrs = (el.attrs && typeof el.attrs === 'object') ? el.attrs : {};
    const dataset = Object.create(null);
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('data-')) {
        const camel = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        dataset[camel] = String(v);
      }
    }
    // `wrapper` is referenced by the listener closures below; it is assigned
    // once recorder() has built it, which is before any handler can run.
    let wrapper;
    const overrides = Object.create(null);
    overrides.getAttribute = (name) => ((String(name) in attrs) ? String(attrs[String(name)]) : null);
    overrides.hasAttribute = (name) => (String(name) in attrs);
    overrides.dataset = dataset;
    overrides.id = (typeof attrs.id === 'string') ? attrs.id : '';
    overrides.className = (typeof attrs.class === 'string') ? attrs.class : '';
    overrides.tagName = (typeof el.tag === 'string') ? el.tag.toUpperCase() : '';
    overrides.nodeName = overrides.tagName;
    const ownText = (typeof el.text === 'string') ? el.text : '';
    overrides.textContent = ownText;
    overrides.innerText = ownText;
    if ('value' in attrs) overrides.value = String(attrs.value);
    // `.content` must mirror the browser rather than fall through to a child
    // recorder: a DocumentFragment on <template>, the reflected `content`
    // attribute on <meta>, and undefined on every other element. Kits stash one
    // piece of the URL in a <template> and read it through
    // `el.content ? el.content.textContent : el.textContent`. A recorder is
    // truthy, so that ternary takes the fragment branch and a
    // `[#id.content.textContent]` placeholder lands in the middle of the URL —
    // the run reports ok and the URL is lost. The same ternary applied to a
    // plain element needs `.content` to be falsy to take the textContent branch.
    const tag = (typeof el.tag === 'string') ? el.tag.toLowerCase() : '';
    if (tag === 'template') {
      const textNode = recorder(`${label}.content.firstChild`, {
        textContent: ownText, nodeValue: ownText, data: ownText, wholeText: ownText,
      });
      overrides.content = recorder(`${label}.content`, {
        textContent: ownText, firstChild: textNode, childNodes: [textNode],
      });
    } else if ('content' in attrs) {
      overrides.content = String(attrs.content);
    } else {
      overrides.content = undefined;
    }
    // A real function, so the call does not pass through the apply trap — it
    // must therefore record the call itself to keep the registration visible in
    // the trace, then queue the handler to fire after the main script.
    overrides.addEventListener = function (type, handler, ...rest) {
      events.push({ kind: 'call', label: `${label}.addEventListener`, args: [type, handler, ...rest].map(safeStringify) });
      queueElementListener(String(type), handler, wrapper, label);
    };
    // `el.onclick = fn` etc. — fire the assigned handler like a listener.
    const onSet = (prop, value) => {
      if (typeof prop === 'string' && /^on[a-z]+$/.test(prop) && typeof value === 'function') {
        queueElementListener(prop.slice(2), value, wrapper, label);
      }
    };
    wrapper = recorder(label, overrides, onSet);
    return wrapper;
  }

  // Selector support is deliberately the minimal subset real phishing kits use:
  // `#id`, `.class`, bare tag. Anything more complex degrades to a recorder
  // (visible as such in the trace) rather than pretending to match.
  function matchSelector(sel) {
    const s = String(sel).trim();
    if (/^#[\w-]+$/.test(s)) { const el = byId.get(s.slice(1)); return el ? [el] : []; }
    if (/^\.[\w-]+$/.test(s)) return (byClass.get(s.slice(1)) || []).slice();
    if (/^[a-zA-Z][\w-]*$/.test(s)) return (byTag.get(s.toLowerCase()) || []).slice();
    return null;  // unsupported selector
  }

  const docOverrides = Object.create(null);
  // On a miss, return a recorder rather than null: a sample that dereferences
  // the result (`.getAttribute`, `.addEventListener`) would otherwise throw a
  // TypeError mid-trace and lose everything after it — the exact failure class
  // recorders exist to prevent. The cost is that a `=== null` branch takes the
  // wrong path, which is the accepted trade.
  docOverrides.getElementById = (id) => {
    const el = byId.get(String(id));
    if (el) return wrapperFor(el, `#${String(id)}`);
    return recorder(`document.getElementById(${JSON.stringify(String(id))})`);
  };
  docOverrides.querySelector = (sel) => {
    const matched = matchSelector(sel);
    if (matched === null) return recorder(`document.querySelector(${JSON.stringify(String(sel))})`);
    if (!matched.length) return recorder(`document.querySelector(${JSON.stringify(String(sel))}):null`);
    return wrapperFor(matched[0], `querySelector(${JSON.stringify(String(sel))})`);
  };
  docOverrides.querySelectorAll = (sel) => {
    const matched = matchSelector(sel);
    if (matched === null) return recorder(`document.querySelectorAll(${JSON.stringify(String(sel))})`);
    return matched.map((el, i) => wrapperFor(el, `querySelectorAll(${JSON.stringify(String(sel))})[${i}]`));
  };
  docOverrides.getElementsByTagName = (tag) => (byTag.get(String(tag).toLowerCase()) || []).map((el, i) => wrapperFor(el, `getElementsByTagName(${JSON.stringify(String(tag))})[${i}]`));
  docOverrides.getElementsByClassName = (cls) => (byClass.get(String(cls)) || []).map((el, i) => wrapperFor(el, `getElementsByClassName(${JSON.stringify(String(cls))})[${i}]`));
  docOverrides.readyState = 'complete';

  return recorder('document', docOverrides);
}

const domDocument = DOM_SNAPSHOT ? buildDomDocument(DOM_SNAPSHOT) : null;

const sandbox = {
  $: jqueryGlobal,
  jQuery: jqueryGlobal,
  console: {
    log: (...a) => events.push({ kind: 'console.log', args: a.map(safeStringify) }),
    warn: (...a) => events.push({ kind: 'console.warn', args: a.map(safeStringify) }),
    error: (...a) => events.push({ kind: 'console.error', args: a.map(safeStringify) }),
    info: (...a) => events.push({ kind: 'console.info', args: a.map(safeStringify) }),
    debug: () => {},
  },
  atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
  btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
  // Host-realm classes handed to the sandbox directly. Cross-realm is fine:
  // a Uint8Array built inside the vm decodes correctly through these because
  // node brand-checks via internal slots, which are realm-agnostic.
  TextDecoder,
  TextEncoder,
  setTimeout: (fn, _ms, ...rest) => {
    if (typeof fn === 'string') {
      secondaryScripts.push({ kind: 'setTimeout', body: fn });
    } else if (typeof fn === 'function') {
      try { fn.apply(null, rest); } catch (e) { events.push({ kind: 'setTimeout.error', error: String(e) }); }
    }
    return 0;
  },
  setInterval: (fn, _ms, ...rest) => {
    // Fire the callback a bounded number of times so countdown-style
    // redirects (e.g. decrement from 5 → 0 then window.top.location.href)
    // get captured. Break on exception to avoid infinite-loop patterns.
    if (typeof fn === 'function') {
      for (let i = 0; i < 10; i++) {
        try { fn.apply(null, rest); } catch (e) { break; }
      }
    }
    return 0;
  },
  setImmediate: (fn) => {
    if (typeof fn === 'function') {
      try { fn(); } catch (e) { events.push({ kind: 'setImmediate.error', error: String(e) }); }
    }
    return 0;
  },
  clearTimeout: () => {},
  clearInterval: () => {},
  queueMicrotask: (fn) => { try { fn(); } catch (_) {} },
};

// When a DOM snapshot was shipped, install the snapshot-backed `document`
// (and window/top/self/parent, which the sample may reach it through as
// `window.document`) before the bulk loop. The `Object.hasOwn` guard at the
// bottom of the loop then skips these names, so they keep the real document
// instead of being overwritten by a plain recorder.
if (domDocument) {
  sandbox.document = domDocument;
  const winOverride = Object.create(null);
  winOverride.document = domDocument;
  for (const name of ['window', 'top', 'self', 'parent']) {
    sandbox[name] = recorder(name, winOverride);
  }
}

// Browser globals — each one is its own recorder so events are labeled
// clearly (e.g. "document.createElement.src = ...").
for (const name of [
  // DOM / BOM
  'window', 'document', 'location', 'navigator', 'top', 'self', 'parent',
  'frames', 'frameElement', 'screen', 'history', 'localStorage',
  'sessionStorage', 'fetch', 'XMLHttpRequest', 'WebSocket', 'crypto',
  'indexedDB', 'performance', 'Image', 'Audio', 'HTMLElement', 'Element',
  'Node', 'MutationObserver', 'alert', 'prompt', 'confirm',
  // The bare global forms. `window.addEventListener(...)` resolves through the
  // window recorder, but plain `addEventListener(...)` is its own global and
  // without it the sample dies on ReferenceError before reaching its payload.
  // Real samples use both, sometimes in the same file.
  'addEventListener', 'removeEventListener', 'dispatchEvent',
  // Web APIs commonly used to stage a payload before redirecting. The
  // SVG-redirect family does `new Blob([decoded_html], {type:'text/html'})`
  // → `URL.createObjectURL` → `document.location.replace`. node:vm doesn't
  // expose Blob/File/etc., so without a recorder the construct call throws
  // ReferenceError mid-trace and the analyst sees nothing. With the
  // recorder, the construct trap captures the decoded HTML in plaintext
  // via safeStringify, and downstream URL extraction picks up the URLs
  // from inside the trace's `new Blob([...])` line.
  'Blob', 'File', 'FileReader', 'FormData',
  // Adobe Acrobat / PDF JavaScript — top-level objects plus commonly used
  // "this.*" methods that PDF scripts dereference as unqualified names after
  // obfuscation (e.g. `this[a0_0x471eff(0x128)]()` resolving to `getField`)
  'app', 'util', 'SOAP', 'color', 'event', 'global', 'xfa',
  'Collab', 'Doc', 'Field', 'Net', 'identity', 'security', 'spell', 'media',
  // 'URL' sits in this block for historical reasons but is load-bearing for
  // the web Blob-redirect flow above, not Acrobat. It stays a RECORDER: real
  // URL.createObjectURL() rejects our Blob recorder with "TypeError: The
  // 'obj' argument must be an instance of Blob", reintroducing the very
  // mid-trace crash the recorders exist to prevent; real `new URL(x)` throws
  // on the non-absolute strings obfuscated samples routinely pass; and even
  // on success it only yields an IOC-free `blob:nodedata:<uuid>`. (Node does
  // have createObjectURL — "node lacks it" is NOT the reason. Don't promote.)
  'getField', 'getTemplate', 'info', 'numPages', 'pageNum', 'path', 'URL',
  'submitForm', 'mailForm', 'mailDoc', 'closeDoc', 'exportDataObject',
  'resetForm', 'addScript', 'syncAnnotScan', 'importDataObject',
  'calculateNow', 'addAnnot', 'getAnnot', 'getAnnots', 'getOCGs',
  'getPageBox', 'getPageNthWord', 'getPageNthWordQuads', 'getPageNumWords',
  'getURL', 'print', 'setAction',
]) {
  // Real implementations above win. This loop runs after the literal, so
  // without this guard adding a name that already has a real implementation
  // would silently downgrade it to a Proxy stub — the exact silent-miss
  // described in the category note above. No current collisions; this is
  // preventive.
  if (Object.hasOwn(sandbox, name)) continue;
  sandbox[name] = recorder(name);
}
sandbox.globalThis = sandbox;

// Compile and run as separate steps so the two failures stay distinguishable.
// Collapsing them (vm.runInContext does both) throws away the one signal that
// says whether the input was JavaScript at all: a SyntaxError means it never
// parsed and is not JS, while a ReferenceError means it parsed fine and died
// mid-execution — which proves it IS JS. Downstream tagging depends on the
// difference. Explicit filename keeps stack traces as "evalmachine.<anonymous>".
let runError = null;
let errorType = null; // 'compile' | 'runtime' | null
let script = null;
vm.createContext(sandbox);
try {
  script = new vm.Script(SRC, { filename: 'evalmachine.<anonymous>' });
} catch (e) {
  runError = e && (e.stack || e.message || String(e));
  errorType = 'compile';
}
if (script) {
  try {
    script.runInContext(sandbox, { timeout: 5000, displayErrors: true });
  } catch (e) {
    runError = e && (e.stack || e.message || String(e));
    errorType = 'runtime';
  }
}

// Now that the main script has finished, fire the DOM-ready listeners it
// registered. Deferred until here rather than fired at registration so the
// real DOMContentLoaded ordering holds: a sample may register the handler
// before defining what the handler needs, and firing early would throw on a
// not-yet-initialized binding. Runs before the secondary-script loop below so
// anything these handlers queue (e.g. a setTimeout string body) still gets
// picked up.
for (const { type, handler } of domReadyListeners) {
  events.push({ kind: 'domready.start', source: type });
  try {
    handler(recorder(`${type}Event`));
  } catch (e) {
    events.push({ kind: 'domready.error', error: e && (e.message || String(e)) });
  }
}

// Fire element-level listeners (click, etc.) the sample registered — commonly
// from inside the DOM-ready handlers just drained, which is why this runs after
// them. Each handler is called with the wrapper as `this` and a synthetic event
// whose target is that wrapper, so a click-gated redirect executes and its URL
// is recorded. Bounded so a handler that re-registers itself can't wedge the
// harness. Called again after the async-continuation drain below for listeners
// registered from a post-`await` continuation.
function fireElementListeners() {
  let fired = 0;
  while (elementListeners.length && fired < MAX_ELEMENT_LISTENER_FIRINGS) {
    const { type, handler, wrapper, label } = elementListeners.shift();
    fired++;
    events.push({ kind: 'element.listener.start', source: `${label} ${type}` });
    const evtOverride = Object.create(null);
    evtOverride.target = wrapper;
    evtOverride.currentTarget = wrapper;
    evtOverride.type = type;
    evtOverride.preventDefault = () => {};
    evtOverride.stopPropagation = () => {};
    try {
      handler.call(wrapper, recorder(`${type}Event`, evtOverride));
    } catch (e) {
      events.push({ kind: 'element.listener.error', error: e && (e.message || String(e)) });
    }
  }
}
fireElementListeners();

// A ready handler may be async: its synchronous portion has run, but anything
// after an `await` is still queued. Yield to the event loop a bounded number
// of times so those continuations (and any timers they scheduled) execute and
// record before we snapshot the trace — otherwise the post-await payload, which
// is often where the real credential-exfil call lives, is rendered as nothing.
// `setImmediate` here is Node's real one (module scope), distinct from the
// sandbox stub. The loop is bounded so a self-rescheduling promise can't wedge
// the harness; each pass fully drains the microtask queue.
for (let i = 0; i < 20; i++) {
  await new Promise((resolve) => setImmediate(resolve));
}

// Catch element listeners registered from a post-`await` continuation (e.g. a
// handler wired up only after an async fetch resolves).
fireElementListeners();

// Re-run any secondary scripts the sample revealed so their global writes get
// recorded too. Today that means setTimeout handlers passed as strings — the
// only thing that pushes to secondaryScripts. The Function constructor is the
// raw vm intrinsic and is NOT hooked, so Function-ctor payloads are not
// captured here.
const alreadyRun = new Set();
for (let i = 0; i < secondaryScripts.length; i++) {
  const entry = secondaryScripts[i];
  if (alreadyRun.has(entry.body)) continue;
  alreadyRun.add(entry.body);
  events.push({ kind: 'secondary.start', source: entry.kind });
  try {
    vm.runInContext(entry.body, sandbox, { timeout: 5000, displayErrors: true });
  } catch (e) {
    events.push({ kind: 'secondary.error', error: e && (e.message || String(e)) });
  }
}

// Emit a deobfuscated pseudo-JS file: one line per significant event.
// Downstream URL extraction just needs the string values to be visible in
// plaintext, so we render them as JS-ish assignments.
const lines = [];
lines.push('// ACE3 javascript deobfuscator -- reconstructed from sandbox trace');
lines.push(`// source: ${INPUT_PATH}`);
lines.push(`// webcrack static pass: ${webcrackStatus}`);
lines.push('');
for (const ev of events) {
  if (ev.kind === 'set') {
    lines.push(`${ev.label}.${ev.prop} = ${ev.value};`);
  } else if (ev.kind === 'call') {
    lines.push(`${ev.label}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'new') {
    lines.push(`new ${ev.label}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'console.log' || ev.kind === 'console.warn' || ev.kind === 'console.error' || ev.kind === 'console.info') {
    lines.push(`${ev.kind}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'secondary.start') {
    lines.push(`// --- secondary payload (${ev.source}) ---`);
  } else if (ev.kind === 'secondary.error') {
    lines.push(`// secondary error: ${ev.error}`);
  } else if (ev.kind === 'domready.start') {
    lines.push(`// --- deferred payload (${ev.source} listener) ---`);
  } else if (ev.kind === 'domready.error') {
    lines.push(`// deferred payload error: ${ev.error}`);
  } else if (ev.kind === 'element.listener.start') {
    lines.push(`// --- deferred payload (${ev.source} listener) ---`);
  } else if (ev.kind === 'element.listener.error') {
    lines.push(`// deferred payload error: ${ev.error}`);
  } else if (ev.kind === 'dom.snapshot.error') {
    lines.push(`// dom snapshot error: ${ev.error}`);
  }
}
if (secondaryScripts.length) {
  lines.push('');
  lines.push('// Raw secondary script bodies:');
  for (const entry of secondaryScripts) {
    lines.push(`// [${entry.kind}]`);
    lines.push(entry.body);
    lines.push('');
  }
}
// Only append the webcracked source tail when webcrack materially changed
// it. On "cosmetic only" / "skipped" / "failed" runs the tail is just the
// raw obfuscated blob (or a trivially reformatted version), which (a)
// provides zero additional analyst value beyond the sandbox trace, and (b)
// can poison downstream URL / IOC extractors that try to parse the whole
// file — notably urlfinderlib feeds the content to an lxml HTML parser that
// chokes on huge embedded string literals. Dropping the tail in the
// non-"applied" cases keeps the emitted file small, ASCII-clean, and
// trivially parseable while preserving the tail for the field_btn1-style
// obfuscator.io case where it's genuinely useful.
if (webcrackStatus === 'applied') {
  lines.push('');
  lines.push('// --- deobfuscated source (post-webcrack) ---');
  lines.push('if (false) {');
  lines.push(SRC);
  lines.push('}');
}
if (runError) {
  lines.push('');
  lines.push(`// run error: ${runError}`);
}

fs.writeFileSync(OUTPUT_PATH, lines.join('\n') + '\n', 'utf8');

process.stdout.write(JSON.stringify({
  status: runError ? 'error_during_run' : 'ok',
  event_count: events.length,
  secondary_script_count: secondaryScripts.length,
  error: runError,
  error_type: errorType,
  webcrack_status: webcrackStatus,
  webcrack_error: webcrackError,
  blob_files: blobFiles,
  dom_snapshot: !!DOM_SNAPSHOT,
}));
