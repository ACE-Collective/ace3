#!/usr/bin/env python

import argparse
import base64
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import cv2  # type: ignore
import mycdp  # type: ignore
import numpy as np
from PIL import Image  # type: ignore
from selenium_recaptcha_solver import RecaptchaSolver  # type: ignore
from seleniumbase import SB  # type: ignore
from yaml import safe_load  # type: ignore

# Stealth JS to inject into ServiceWorker/Worker contexts via CDP and via the
# Worker/Blob constructor patches in STEALTH_JS. Must be self-contained
# (no references to main page globals). Mirrors what main-page STEALTH_JS does
# but for worker scope, because workers are what creepjs / browserscan use to
# cross-check OS / GPU / timezone signals against the spoofed UA.
SW_STEALTH_JS = """
(function() {
    // platform: workers' WorkerNavigator.platform leaks 'Linux x86_64' even with
    // CDP Network.setUserAgentOverride.userAgentMetadata.platform = 'Windows'.
    const navProto = Object.getPrototypeOf(navigator);
    if (navProto) {
        try {
            Object.defineProperty(navProto, 'platform', {
                get: () => 'Win32', configurable: true,
            });
        } catch(e) {}
    }
    // navigator.userAgentData: the CDP override sets the *header* values but the
    // JS accessor often still reports the underlying OS. Override the prototype.
    if (typeof navigator !== 'undefined' && navigator.userAgentData) {
        const uad = navigator.userAgentData;
        const uadProto = Object.getPrototypeOf(uad);
        try {
            Object.defineProperty(uadProto, 'platform', {
                get: () => 'Windows', configurable: true,
            });
        } catch(e) {}
        const _orig = uadProto.getHighEntropyValues;
        if (typeof _orig === 'function') {
            uadProto.getHighEntropyValues = function(hints) {
                return _orig.call(this, hints).then(v => Object.assign({}, v, {
                    platform: 'Windows',
                    platformVersion: '10.0.0',
                    architecture: 'x86',
                    bitness: '64',
                    model: '',
                    wow64: false,
                }));
            };
        }
    }
    // WebGL: both OffscreenCanvas-derived contexts AND the bare prototypes
    // (which both context types share methods from). Hook getParameter on the
    // prototypes so every gl.getParameter(UNMASKED_VENDOR_WEBGL/RENDERER_WEBGL)
    // returns the spoofed Intel iGPU instead of SwiftShader.
    function patchGetParam(proto) {
        if (!proto || !proto.prototype || !proto.prototype.getParameter) return;
        const _gp = proto.prototype.getParameter;
        proto.prototype.getParameter = function(p) {
            if (p === 0x9245) return 'Intel Inc.';
            if (p === 0x9246) return 'Intel Iris OpenGL Engine';
            return _gp.call(this, p);
        };
        try {
            proto.prototype.getParameter.toString = () => 'function getParameter() { [native code] }';
        } catch(e) {}
    }
    if (typeof WebGLRenderingContext !== 'undefined')  patchGetParam(WebGLRenderingContext);
    if (typeof WebGL2RenderingContext !== 'undefined') patchGetParam(WebGL2RenderingContext);
    if (typeof OffscreenCanvas !== 'undefined') {
        const _gc = OffscreenCanvas.prototype.getContext;
        OffscreenCanvas.prototype.getContext = function(t, a) {
            const c = _gc.call(this, t, a);
            if (c && (t === 'webgl' || t === 'webgl2' || t === 'experimental-webgl')) {
                const _gp = c.getParameter.bind(c);
                c.getParameter = function(p) {
                    if (p === 0x9245) return 'Intel Inc.';
                    if (p === 0x9246) return 'Intel Iris OpenGL Engine';
                    return _gp(p);
                };
            }
            return c;
        };
    }
    // Timezone: the container has no TZ set so Intl reports UTC. Override at
    // the JS level since CDP Emulation.setTimezoneOverride doesn't always
    // propagate to worker contexts.
    if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
        const _ro = Intl.DateTimeFormat.prototype.resolvedOptions;
        Intl.DateTimeFormat.prototype.resolvedOptions = function() {
            const r = _ro.call(this);
            if (r && r.timeZone === 'UTC') r.timeZone = 'America/New_York';
            return r;
        };
        try {
            Intl.DateTimeFormat.prototype.resolvedOptions.toString = () => 'function resolvedOptions() { [native code] }';
        } catch(e) {}
    }
})();
"""

def _detect_chrome_version() -> tuple[str, str]:
    """Returns (major, full) version of the Chrome/Chromium binary the scanner will drive.

    Reads it from the binary itself at module load so the spoofed UA and
    Sec-CH-UA headers stay in lockstep with the actual Chrome the image ships,
    closing the version-drift gap that bot detectors fingerprint on. Falls
    back to a known-recent version if detection fails.
    """
    for binary in ("google-chrome", "google-chrome-stable", "chromium"):
        try:
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True, timeout=5, check=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        for tok in result.stdout.strip().split():
            if tok and tok[0].isdigit() and "." in tok:
                return tok.split(".", 1)[0], tok
    return "147", "147.0.7727.101"


BYPASS_CHROME_MAJOR, BYPASS_CHROME_FULL = _detect_chrome_version()
BYPASS_UA = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{BYPASS_CHROME_FULL} Safari/537.36"
)


def _detect_chrome_grease(major: str, full: str) -> tuple[list[dict], list[dict]]:
    """Returns (brands, fullVersionList) — Chrome's own userAgentData output.

    Chrome's GREASE algorithm (the rotating "Not_A Brand"-style entry that
    accompanies Chromium/Google Chrome in userAgentData.brands) changes
    periodically — different brand strings, different shuffle positions, even
    different version numbers. Hardcoding goes stale silently when Chrome
    rotates. Instead we ask the installed Chrome what it would emit, by
    rendering a tiny page that resolves navigator.userAgentData and writes the
    result to a data attribute, then parsing the dumped DOM.

    Falls back to a sensible hardcoded list if detection fails (Chrome binary
    missing, parse failure, etc.) so the scanner still works.
    """
    fallback_brands = [
        {"brand": "Chromium", "version": major},
        {"brand": "Not_A Brand", "version": "8"},
        {"brand": "Google Chrome", "version": major},
    ]
    fallback_full = [
        {"brand": "Chromium", "version": full},
        {"brand": "Not_A Brand", "version": "8.0.0.0"},
        {"brand": "Google Chrome", "version": full},
    ]

    html_payload = (
        '<!DOCTYPE html><html><body data-uad=""></body><script>'
        'navigator.userAgentData.getHighEntropyValues(["fullVersionList"])'
        '.then(function(v){'
        '  document.body.dataset.uad = btoa(JSON.stringify({'
        '    brands: v.brands, full: v.fullVersionList'
        '  }));'
        '}).catch(function(e){});'
        '</script></html>'
    )
    data_url = "data:text/html;base64," + base64.b64encode(html_payload.encode()).decode()

    for binary in ("google-chrome", "google-chrome-stable", "chromium"):
        try:
            result = subprocess.run(
                [
                    binary,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--virtual-time-budget=2000",
                    "--dump-dom",
                    data_url,
                ],
                capture_output=True, text=True, timeout=15, check=True,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        m = re.search(r'data-uad="([A-Za-z0-9+/=]+)"', result.stdout)
        if not m:
            continue
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8")
            data = json.loads(decoded)
            brands = data.get("brands")
            full_list = data.get("full")
            if isinstance(brands, list) and isinstance(full_list, list) and brands and full_list:
                return brands, full_list
        except Exception:
            continue
    return fallback_brands, fallback_full


BYPASS_BRANDS, BYPASS_FULL_VERSION_LIST = _detect_chrome_grease(BYPASS_CHROME_MAJOR, BYPASS_CHROME_FULL)

# JavaScript to inject before any page scripts run, to mask automation signals.
STEALTH_JS = """
// 0. Native toString masking (per-function, not global)
// Browserscan / creepjs lie-detection reads Object.getOwnPropertyDescriptor(...).get.toString()
// for getters. If the result isn't "function ... { [native code] }", the override is flagged.
// We could override Function.prototype.toString globally, but creepjs's lie-detector then
// trips its hasToStringProxy / Function.toString lieProps detector via behavioral checks
// (new toString(), call interface, etc.) that are very hard to mimic perfectly for a
// non-native function. So instead: we attach a per-function .toString property that returns
// the native-looking string. This works for `.toString()` direct calls — which is what
// browserscan's getter inspector uses — and avoids tripping the toString-proxy detector.
function maskNative(fn, signature) {
    const masked = 'function ' + signature + '() { [native code] }';
    try {
        Object.defineProperty(fn, 'toString', {
            value: function toString() { return masked; },
            writable: false, enumerable: false, configurable: true,
        });
        Object.defineProperty(fn.toString, 'toString', {
            value: function toString() { return 'function toString() { [native code] }'; },
            writable: false, enumerable: false, configurable: true,
        });
    } catch(e) {}
    return fn;
}

// 1. navigator.webdriver — handled natively by --disable-blink-features=AutomationControlled
// Do NOT override via Object.defineProperty, as CreepJS lie detection will flag
// a non-native getter on Navigator.prototype.webdriver.

// 2. Fix Notification.permission for headless Chrome
// Real Chrome returns 'default' when user hasn't interacted with permission prompt
if (typeof Notification !== 'undefined') {
    Object.defineProperty(Notification, 'permission', {
        get: () => 'default',
    });
}

// 3. Fix navigator.permissions.query to behave like real Chrome
const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
window.navigator.permissions.query = (parameters) => {
    if (parameters.name === 'notifications') {
        return Promise.resolve({ state: Notification.permission });
    }
    return originalQuery(parameters);
};

// 4. Fix navigator.plugins instanceof PluginArray check
// Headless Chrome has plugins but the prototype chain is broken
const originalPlugins = navigator.plugins;
if (originalPlugins && !(originalPlugins instanceof PluginArray)) {
    Object.defineProperty(Navigator.prototype, 'plugins', {
        get: function() {
            const p = originalPlugins;
            Object.setPrototypeOf(p, PluginArray.prototype);
            return p;
        },
        configurable: true,
    });
}

// 5. Simulate taskbar by reducing screen.availHeight
// Emulation.setDeviceMetricsOverride doesn't support setting availHeight
// separately, so we override it in JS. CreepJS can detect this override
// (Screen "lies"), but noTaskbar=true is a stronger headless indicator.
Object.defineProperty(Screen.prototype, 'availHeight', {
    get: () => screen.height - 40,
    configurable: true,
});

// 6. Fix navigator.platform to match Windows UA spoof
// Workers inherit the real OS platform. Override it on WorkerNavigator prototype
// if we're in the main window context, inject via Page.addScriptToEvaluateOnNewDocument.
// For the main context, fix navigator.platform to match our Windows UA spoof.
if (typeof Navigator !== 'undefined') {
    const platGet = maskNative(function() { return 'Win32'; }, 'get platform');
    Object.defineProperty(Navigator.prototype, 'platform', {
        get: platGet,
        configurable: true,
    });
}

// 6b. Fix navigator.userAgentData to match Windows UA spoof
// CDP Network.setUserAgentOverride.userAgentMetadata sets the Sec-CH-UA-Platform
// HEADER but the JS-side navigator.userAgentData.platform accessor still leaks
// the underlying OS (e.g. 'Linux'). Override the prototype so JS reads Windows.
if (typeof navigator !== 'undefined' && navigator.userAgentData) {
    const uad = navigator.userAgentData;
    const uadProto = Object.getPrototypeOf(uad);
    try {
        const uadPlatGet = maskNative(function() { return 'Windows'; }, 'get platform');
        Object.defineProperty(uadProto, 'platform', {
            get: uadPlatGet,
            configurable: true,
        });
    } catch(e) {}
    const _orig = uadProto.getHighEntropyValues;
    if (typeof _orig === 'function') {
        const hookedGHEV = maskNative(function(hints) {
            return _orig.call(this, hints).then(v => Object.assign({}, v, {
                platform: 'Windows',
                platformVersion: '10.0.0',
                architecture: 'x86',
                bitness: '64',
                model: '',
                wow64: false,
            }));
        }, 'getHighEntropyValues');
        uadProto.getHighEntropyValues = hookedGHEV;
    }
}

// 7. Inject stealth overrides into Worker contexts
// Page.addScriptToEvaluateOnNewDocument only covers the main page; Workers get a
// clean global. We intercept Blob construction and Worker creation to prepend
// stealth overrides into any JavaScript blob that might be used as a Worker script.
// Mirrors SW_STEALTH_JS: platform, userAgentData, WebGL prototype hook, timezone.
(function() {
    const WORKER_STEALTH = [
        '/* stealth */',
        '(function(){',
        '  try {',
        '    const navProto = Object.getPrototypeOf(navigator);',
        '    if (navProto) Object.defineProperty(navProto, "platform", { get: () => "Win32", configurable: true });',
        '  } catch(e) {}',
        '  if (navigator.userAgentData) {',
        '    try {',
        '      const uadProto = Object.getPrototypeOf(navigator.userAgentData);',
        '      Object.defineProperty(uadProto, "platform", { get: () => "Windows", configurable: true });',
        '      const _o = uadProto.getHighEntropyValues;',
        '      if (typeof _o === "function") {',
        '        uadProto.getHighEntropyValues = function(h) {',
        '          return _o.call(this, h).then(v => Object.assign({}, v, {',
        '            platform: "Windows", platformVersion: "10.0.0",',
        '            architecture: "x86", bitness: "64", model: "", wow64: false',
        '          }));',
        '        };',
        '      }',
        '    } catch(e) {}',
        '  }',
        '  function patchGP(proto) {',
        '    if (!proto || !proto.prototype || !proto.prototype.getParameter) return;',
        '    const _gp = proto.prototype.getParameter;',
        '    proto.prototype.getParameter = function(p) {',
        '      if (p===0x9245) return "Intel Inc.";',
        '      if (p===0x9246) return "Intel Iris OpenGL Engine";',
        '      return _gp.call(this, p);',
        '    };',
        '    try { proto.prototype.getParameter.toString = () => "function getParameter() { [native code] }"; } catch(e) {}',
        '  }',
        '  if (typeof WebGLRenderingContext !== "undefined")  patchGP(WebGLRenderingContext);',
        '  if (typeof WebGL2RenderingContext !== "undefined") patchGP(WebGL2RenderingContext);',
        '  if (typeof OffscreenCanvas !== "undefined") {',
        '    const _gc = OffscreenCanvas.prototype.getContext;',
        '    OffscreenCanvas.prototype.getContext = function(t, a) {',
        '      const c = _gc.call(this, t, a);',
        '      if (c && (t==="webgl"||t==="webgl2"||t==="experimental-webgl")) {',
        '        const _gp = c.getParameter.bind(c);',
        '        c.getParameter = function(p) {',
        '          if (p===0x9245) return "Intel Inc.";',
        '          if (p===0x9246) return "Intel Iris OpenGL Engine";',
        '          return _gp(p);',
        '        };',
        '      }',
        '      return c;',
        '    };',
        '  }',
        '  if (typeof Intl !== "undefined" && Intl.DateTimeFormat) {',
        '    const _ro = Intl.DateTimeFormat.prototype.resolvedOptions;',
        '    Intl.DateTimeFormat.prototype.resolvedOptions = function() {',
        '      const r = _ro.call(this);',
        '      if (r && r.timeZone === "UTC") r.timeZone = "America/New_York";',
        '      return r;',
        '    };',
        '  }',
        '})();',
    ].join('\\n');

    // Patch Worker/SharedWorker constructors. For URL-based workers we prepend
    // the stealth code via importScripts(). For blob: URLs we fetch the blob
    // synchronously (sync XHR works because the blob URL is same-origin),
    // prepend the stealth code, and recreate the blob.
    function patchWorkerCtor(Orig, name) {
        const Patched = function(scriptURL, options) {
            // Module workers can't easily importScripts; pass through.
            if (options && options.type === 'module') {
                return new Orig(scriptURL, options);
            }
            try {
                const url = String(scriptURL);
                if (url.startsWith('blob:')) {
                    // Sync-fetch the blob body, prepend stealth, recreate.
                    const xhr = new XMLHttpRequest();
                    xhr.open('GET', url, false);
                    xhr.send();
                    const body = xhr.responseText || '';
                    const newBlob = new Blob(
                        [WORKER_STEALTH + '\\n' + body],
                        { type: 'application/javascript' }
                    );
                    return new Orig(URL.createObjectURL(newBlob), options);
                }
                const resolved = new URL(url, location.href).href;
                const blob = new Blob(
                    [WORKER_STEALTH + '\\nimportScripts("' + resolved + '");'],
                    { type: 'application/javascript' }
                );
                return new Orig(URL.createObjectURL(blob), options);
            } catch(e) {
                return new Orig(scriptURL, options);
            }
        };
        Patched.prototype = Orig.prototype;
        Object.defineProperty(Patched, 'name', { value: name });
        return Patched;
    }

    if (typeof Worker !== 'undefined') {
        window.Worker = patchWorkerCtor(Worker, 'Worker');
    }
    if (typeof SharedWorker !== 'undefined') {
        window.SharedWorker = patchWorkerCtor(SharedWorker, 'SharedWorker');
    }

    // 7b. Block ServiceWorker registration so fingerprinters fall through to
    // SharedWorker / Worker (which we patch with WORKER_STEALTH). ServiceWorker
    // requires same-origin URLs and rejects blob: URLs, so we can't easily
    // prepend stealth at the URL level. Cleanest path is to make register()
    // reject — callers' .catch handlers then move on.
    try {
        if (navigator.serviceWorker) {
            const swProto = Object.getPrototypeOf(navigator.serviceWorker);
            const reg = maskNative(function register() {
                return Promise.reject(new DOMException(
                    'ServiceWorker registration is not supported in this context.',
                    'SecurityError'
                ));
            }, 'register');
            try {
                Object.defineProperty(swProto, 'register', {
                    value: reg, writable: false, enumerable: false, configurable: true,
                });
            } catch(e) {}
        }
    } catch(e) {}
})();

// 8. Spoof WebGL renderer to hide SwiftShader
// Chrome falls back to SwiftShader in Docker (no GPU). The renderer string
// "SwiftShader" is a known headless signal. Hook getParameter to return a
// common integrated GPU string. Mask the hook's toString via maskNative so
// browserscan / creepjs prototype-lies detectors don't flag it.
(function() {
    const SPOOFED_VENDOR = 'Intel Inc.';
    const SPOOFED_RENDERER = 'Intel Iris OpenGL Engine';
    function patchGP(proto) {
        if (!proto || !proto.prototype || !proto.prototype.getParameter) return;
        const _gp = proto.prototype.getParameter;
        proto.prototype.getParameter = maskNative(function(param) {
            // UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246
            if (param === 0x9245) return SPOOFED_VENDOR;
            if (param === 0x9246) return SPOOFED_RENDERER;
            return _gp.call(this, param);
        }, 'getParameter');
    }
    patchGP(WebGLRenderingContext);
    if (typeof WebGL2RenderingContext !== 'undefined') patchGP(WebGL2RenderingContext);
})();

// 9. Fix CSS system colors for headless detection
// Headless Chrome resolves the CSS system color "ActiveText" to rgb(255, 0, 0) because
// no OS theme is loaded. Real Windows Chrome uses a different value.
// CreepJS creates an element with inline style "background-color: ActiveText" and reads
// the computed value. We inject a CSS rule that overrides this via !important.
// This runs before <head> exists, so we observe the DOM and inject as soon as possible.
(function() {
    const css = '[style*="ActiveText"] { background-color: rgb(0, 102, 204) !important; }';
    function injectStyle(parent) {
        const s = document.createElement('style');
        s.textContent = css;
        parent.appendChild(s);
    }
    if (document.head) {
        injectStyle(document.head);
    } else if (document.documentElement) {
        injectStyle(document.documentElement);
    } else {
        new MutationObserver((_, obs) => {
            if (document.documentElement) {
                obs.disconnect();
                injectStyle(document.documentElement);
            }
        }).observe(document, { childList: true });
    }
})();

// 9. Override matchMedia for hover/pointer CSS media queries
// Xvfb/headless Chrome reports no input devices (hover:none, pointer:none).
// We override matchMedia to report hover:hover and pointer:fine.
const _origMatchMedia = window.matchMedia.bind(window);
window.matchMedia = function(query) {
    const result = _origMatchMedia(query);
    const overrides = [
        [/\(\s*hover\s*:\s*none\s*\)/, false],
        [/\(\s*hover\s*:\s*hover\s*\)/, true],
        [/\(\s*any-hover\s*:\s*none\s*\)/, false],
        [/\(\s*any-hover\s*:\s*hover\s*\)/, true],
        [/\(\s*pointer\s*:\s*none\s*\)/, false],
        [/\(\s*pointer\s*:\s*fine\s*\)/, true],
        [/\(\s*any-pointer\s*:\s*none\s*\)/, false],
        [/\(\s*any-pointer\s*:\s*fine\s*\)/, true],
    ];
    for (const [pattern, matches] of overrides) {
        if (pattern.test(query)) {
            return Object.assign({}, result, {matches, media: query});
        }
    }
    return result;
};

// 10. Apply stealth into same-origin iframe windows
// Each frame has its own globals (its own Navigator, Worker, WebGLRenderingContext,
// Intl, etc.). Page.addScriptToEvaluateOnNewDocument does propagate to about:blank
// iframes in theory, but in practice creepjs and similar fingerprinters create a
// hidden iframe and access self[i] / iframe.contentWindow before our injected
// script reliably runs in that frame. So we proactively patch any iframe's window
// the moment JS first reaches for it.
(function() {
    // The same WORKER_STEALTH the main-window section 7 uses. Defined here
    // because section 7's IIFE-local copy is out of scope. Keep them in sync.
    const WORKER_STEALTH = [
        '/* stealth */',
        '(function(){',
        '  try {',
        '    const navProto = Object.getPrototypeOf(navigator);',
        '    if (navProto) Object.defineProperty(navProto, "platform", { get: () => "Win32", configurable: true });',
        '  } catch(e) {}',
        '  if (navigator.userAgentData) {',
        '    try {',
        '      const uadProto = Object.getPrototypeOf(navigator.userAgentData);',
        '      Object.defineProperty(uadProto, "platform", { get: () => "Windows", configurable: true });',
        '      const _o = uadProto.getHighEntropyValues;',
        '      if (typeof _o === "function") {',
        '        uadProto.getHighEntropyValues = function(h) {',
        '          return _o.call(this, h).then(v => Object.assign({}, v, {',
        '            platform: "Windows", platformVersion: "10.0.0",',
        '            architecture: "x86", bitness: "64", model: "", wow64: false',
        '          }));',
        '        };',
        '      }',
        '    } catch(e) {}',
        '  }',
        '  function patchGP(proto) {',
        '    if (!proto || !proto.prototype || !proto.prototype.getParameter) return;',
        '    const _gp = proto.prototype.getParameter;',
        '    proto.prototype.getParameter = function(p) {',
        '      if (p===0x9245) return "Intel Inc.";',
        '      if (p===0x9246) return "Intel Iris OpenGL Engine";',
        '      return _gp.call(this, p);',
        '    };',
        '    try { proto.prototype.getParameter.toString = () => "function getParameter() { [native code] }"; } catch(e) {}',
        '  }',
        '  if (typeof WebGLRenderingContext !== "undefined")  patchGP(WebGLRenderingContext);',
        '  if (typeof WebGL2RenderingContext !== "undefined") patchGP(WebGL2RenderingContext);',
        '  if (typeof OffscreenCanvas !== "undefined") {',
        '    const _gc = OffscreenCanvas.prototype.getContext;',
        '    OffscreenCanvas.prototype.getContext = function(t, a) {',
        '      const c = _gc.call(this, t, a);',
        '      if (c && (t==="webgl"||t==="webgl2"||t==="experimental-webgl")) {',
        '        const _gp = c.getParameter.bind(c);',
        '        c.getParameter = function(p) {',
        '          if (p===0x9245) return "Intel Inc.";',
        '          if (p===0x9246) return "Intel Iris OpenGL Engine";',
        '          return _gp(p);',
        '        };',
        '      }',
        '      return c;',
        '    };',
        '  }',
        '  if (typeof Intl !== "undefined" && Intl.DateTimeFormat) {',
        '    const _ro = Intl.DateTimeFormat.prototype.resolvedOptions;',
        '    Intl.DateTimeFormat.prototype.resolvedOptions = function() {',
        '      const r = _ro.call(this);',
        '      if (r && r.timeZone === "UTC") r.timeZone = "America/New_York";',
        '      return r;',
        '    };',
        '  }',
        '})();',
    ].join('\\n');

    // Track patched frames via a WeakSet in main scope (not via an enumerable
    // property on iframe.window — that would leak to lie-detectors as a
    // non-standard property on the window object).
    const _patchedFrames = new WeakSet();
    function patchFrame(w) {
        if (!w) return;
        if (_patchedFrames.has(w)) return;
        _patchedFrames.add(w);

        // platform on the iframe's Navigator.prototype
        try {
            if (w.Navigator && w.Navigator.prototype) {
                Object.defineProperty(w.Navigator.prototype, 'platform', {
                    get: () => 'Win32', configurable: true,
                });
            }
        } catch(e) {}

        // navigator.userAgentData on the iframe's instance/prototype
        try {
            const uad = w.navigator && w.navigator.userAgentData;
            if (uad) {
                const uadProto = Object.getPrototypeOf(uad);
                try {
                    Object.defineProperty(uadProto, 'platform', {
                        get: () => 'Windows', configurable: true,
                    });
                } catch(e) {}
                const _orig = uadProto.getHighEntropyValues;
                if (typeof _orig === 'function') {
                    uadProto.getHighEntropyValues = function(hints) {
                        return _orig.call(this, hints).then(v => Object.assign({}, v, {
                            platform: 'Windows', platformVersion: '10.0.0',
                            architecture: 'x86', bitness: '64', model: '', wow64: false,
                        }));
                    };
                }
            }
        } catch(e) {}

        // WebGL on iframe's prototypes
        try {
            function patchGP(proto) {
                if (!proto || !proto.prototype || !proto.prototype.getParameter) return;
                const _gp = proto.prototype.getParameter;
                proto.prototype.getParameter = function(p) {
                    if (p === 0x9245) return 'Intel Inc.';
                    if (p === 0x9246) return 'Intel Iris OpenGL Engine';
                    return _gp.call(this, p);
                };
            }
            if (w.WebGLRenderingContext) patchGP(w.WebGLRenderingContext);
            if (w.WebGL2RenderingContext) patchGP(w.WebGL2RenderingContext);
        } catch(e) {}

        // Timezone override on iframe's Intl
        try {
            if (w.Intl && w.Intl.DateTimeFormat) {
                const _ro = w.Intl.DateTimeFormat.prototype.resolvedOptions;
                w.Intl.DateTimeFormat.prototype.resolvedOptions = function() {
                    const r = _ro.call(this);
                    if (r && r.timeZone === 'UTC') r.timeZone = 'America/New_York';
                    return r;
                };
            }
        } catch(e) {}

        // Worker / SharedWorker ctor patches on iframe's window. These use the
        // iframe's own Blob, URL, XMLHttpRequest so the resulting blob URL is
        // same-origin to the iframe.
        try {
            function patchWorkerCtor(Orig, name) {
                const Patched = function(scriptURL, options) {
                    if (options && options.type === 'module') {
                        return new Orig(scriptURL, options);
                    }
                    try {
                        const url = String(scriptURL);
                        if (url.startsWith('blob:')) {
                            const xhr = new w.XMLHttpRequest();
                            xhr.open('GET', url, false);
                            xhr.send();
                            const body = xhr.responseText || '';
                            const newBlob = new w.Blob(
                                [WORKER_STEALTH + '\\n' + body],
                                { type: 'application/javascript' }
                            );
                            return new Orig(w.URL.createObjectURL(newBlob), options);
                        }
                        const resolved = new w.URL(url, w.location.href).href;
                        const blob = new w.Blob(
                            [WORKER_STEALTH + '\\nimportScripts("' + resolved + '");'],
                            { type: 'application/javascript' }
                        );
                        return new Orig(w.URL.createObjectURL(blob), options);
                    } catch(e) {
                        return new Orig(scriptURL, options);
                    }
                };
                Patched.prototype = Orig.prototype;
                try { Object.defineProperty(Patched, 'name', { value: name }); } catch(e) {}
                return Patched;
            }
            if (w.Worker) w.Worker = patchWorkerCtor(w.Worker, 'Worker');
            if (w.SharedWorker) w.SharedWorker = patchWorkerCtor(w.SharedWorker, 'SharedWorker');
        } catch(e) {}
    }

    // Hook 1: iframe.contentWindow getter — covers any code that reads it
    try {
        const cwDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (cwDesc && cwDesc.get) {
            const _origGet = cwDesc.get;
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                get: function() {
                    const w = _origGet.call(this);
                    try { patchFrame(w); } catch(e) {}
                    return w;
                },
                configurable: true,
            });
        }
    } catch(e) {}

    // Hook 2: DOM insertion methods — covers code that does `self[i]` indexed
    // window access, which bypasses the contentWindow getter. We patch the
    // iframe's contentWindow synchronously when it's appended to the DOM, so
    // by the time any later code reads self[i], the patches are already in.
    //
    // Important: when a DocumentFragment is appended (creepjs does this), its
    // children move OUT of the fragment INTO the parent. By the time we run,
    // the fragment is empty — so we have to also walk the parent to find any
    // iframes that just landed there.
    function checkNodeForIframes(n) {
        if (!n) return;
        try {
            if (n.tagName === 'IFRAME') {
                const w = n.contentWindow;
                if (w) patchFrame(w);
            }
            if (n.querySelectorAll) {
                n.querySelectorAll('iframe').forEach(function(f) {
                    try { if (f.contentWindow) patchFrame(f.contentWindow); } catch(e) {}
                });
            }
        } catch(e) {}
    }
    function patchInsertedNode(parent, child) {
        checkNodeForIframes(child);   // common case: child is an Element with iframes
        checkNodeForIframes(parent);  // DocumentFragment case: children moved to parent
    }
    try {
        const _appendChild = Node.prototype.appendChild;
        Node.prototype.appendChild = function(child) {
            const r = _appendChild.call(this, child);
            patchInsertedNode(this, child);
            return r;
        };
    } catch(e) {}
    try {
        const _insertBefore = Node.prototype.insertBefore;
        Node.prototype.insertBefore = function(child, ref) {
            const r = _insertBefore.call(this, child, ref);
            patchInsertedNode(this, child);
            return r;
        };
    } catch(e) {}
    try {
        if (Element.prototype.append) {
            const _append = Element.prototype.append;
            Element.prototype.append = function() {
                const args = arguments;
                const r = _append.apply(this, args);
                for (let i = 0; i < args.length; i++) patchInsertedNode(this, args[i]);
                return r;
            };
        }
        if (Element.prototype.prepend) {
            const _prepend = Element.prototype.prepend;
            Element.prototype.prepend = function() {
                const args = arguments;
                const r = _prepend.apply(this, args);
                for (let i = 0; i < args.length; i++) patchInsertedNode(this, args[i]);
                return r;
            };
        }
    } catch(e) {}

    // Patch any iframes that exist at script load (rare for our injection
    // timing but cheap to handle)
    try {
        document.querySelectorAll && document.querySelectorAll('iframe').forEach(function(f) {
            try { if (f.contentWindow) patchFrame(f.contentWindow); } catch(e) {}
        });
    } catch(e) {}
})();
"""

# Default config path baked into the scanner Docker image.
DEFAULT_CONFIG_PATH = "/opt/app/phishkit_config.yaml"

# Artifact holding the top-level response body when the scanned URL served
# JavaScript rather than a page. The .js extension is load-bearing: ACE's
# JavaScriptDeobfuscationAnalyzer triggers on it.
TOP_LEVEL_SCRIPT_NAME = "script.js"

# Artifact holding captured response bodies and WebSocket traffic, one
# "MARKER URL: <url>" line per block. This is a grep/yara corpus, not a
# document. It used to be appended to dom.html, which made dom.html both a
# parseable DOM and a pile of raw bodies -- anything HTML-aware then mis-read the
# bodies, extracting a <script> that sat inside a JS string literal as if it were
# a real inline script and producing a "JavaScript" file that is not JavaScript.
# Splitting it out is what lets ACE keep parsing dom.html (whose inline scripts
# are genuine) while leaving the corpus alone.
#
# The .txt name is honest labeling, not the enforcement: ACE's PhishkitAnalyzer
# has to exclude HTMLJavaScriptExtractor from this file explicitly, because that
# module falls back to the detected mime type when the extension doesn't match,
# and libmagic reads the captured HTML in here as text/html.
RESPONSE_BODIES_NAME = "response_bodies.txt"


def _safe_to_json(cdp_object):
    """Serializes a CDP object, returning None instead of raising.

    The "raw" dump is a bonus -- nothing downstream reads it; the url/method/
    headers alongside it are what matter. It must therefore never be able to
    destroy the entry it belongs to, which is exactly what it was doing:
    mycdp's Request.to_json() reads self.is_ad_related, which is not one of
    Request's fields, so it raised AttributeError on *every* call. That took the
    whole request entry down with it, so requests.json only ever contained
    type="response" rows -- silently disabling PhishkitAnalyzer's promotion pass
    over type="request" entries. Response.to_json() has no such field and works,
    which is why responses survived and requests never did.
    """
    try:
        return cdp_object.to_json()
    except Exception as e:
        print(f"could not serialize {type(cdp_object).__name__} to json: {e}")
        return None

# Structural CSS selectors the visual_checkbox_bypass handler uses to locate the
# clickable challenge element when no checkbox image matches. Polymorphic kits
# randomize text, colors, classes, ids and even the rendered scale (defeating
# image and text matching) but keep the ARIA semantics of the interactive
# element, so role=button / tabindex=0 survive across instances. Overridable via
# handlers.visual_checkbox_bypass.click_selectors in the YAML config.
DEFAULT_CLICK_SELECTORS = [
    '[role="button"][tabindex="0"]',
    '[role="button"][aria-label]',
]


# Defaults for the content-type lists below. Both are denylists and both fail
# open: an unknown or missing content type is treated as a normal page, so we
# still screenshot it, still attempt bypasses, and still append its body to
# dom.html. Getting a useless screenshot is a much cheaper mistake than silently
# dropping a real one.
DEFAULT_NON_RENDERED_CONTENT_TYPES = [
    "application/javascript",
    "application/json",
    "application/x-javascript",
    "application/xml",
    "text/css",
    "text/javascript",
    "text/plain",
    "text/xml",
]

DEFAULT_SCRIPT_CONTENT_TYPES = [
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
]


@dataclass
class PhishkitConfig:
    skip_body_ext: list
    skip_body_url_patterns: list
    handlers: dict
    bypasses: list
    max_ws_frame_bytes: int = 65536
    # scan_waits.additional_wait: fixed minimum sleep after readyState=complete
    additional_wait: int = 3
    # scan_waits.max_network_wait: additional cap on top of additional_wait
    # during which the scanner keeps waiting for network/URL quiescence
    max_network_wait: float = 10.0
    # Content types Chrome shows in its built-in plain-text viewer rather than
    # rendering as a page. Two consequences, both handled: a screenshot of one is
    # a picture of source we already capture verbatim, and there is no challenge
    # UI on it to bypass. Deliberately wider than script_content_types: nothing
    # in this list renders as a page.
    non_rendered_content_types: list = field(default_factory=lambda: list(DEFAULT_NON_RENDERED_CONTENT_TYPES))
    # Content types whose top-level body is JavaScript. Narrower than the list
    # above: only these can be handed to ACE's JS deobfuscator.
    script_content_types: list = field(default_factory=lambda: list(DEFAULT_SCRIPT_CONTENT_TYPES))


def _load_config(config_path: str) -> PhishkitConfig:
    """Load phishkit config from a YAML file.

    Returns a PhishkitConfig with skip_body_ext, skip_body_url_patterns,
    handlers, bypasses, max_ws_frame_bytes, and scan_waits. Raises on missing
    or invalid config.
    """
    with open(config_path, "r") as f:
        data = safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"config at {config_path} is not a YAML mapping")

    scan_waits = data.get("scan_waits") or {}
    if not isinstance(scan_waits, dict):
        scan_waits = {}

    config = PhishkitConfig(
        skip_body_ext=data.get("skip_body_extensions", []),
        skip_body_url_patterns=data.get("skip_body_url_patterns", []),
        handlers=data.get("handlers", {}),
        bypasses=data.get("bypasses", []),
        max_ws_frame_bytes=int(data.get("max_ws_frame_bytes", 65536)),
        additional_wait=int(scan_waits.get("additional_wait", 3)),
        max_network_wait=float(scan_waits.get("max_network_wait", 10.0)),
        non_rendered_content_types=[
            str(x).lower()
            for x in (data.get("non_rendered_content_types") or DEFAULT_NON_RENDERED_CONTENT_TYPES)
        ],
        script_content_types=[
            str(x).lower()
            for x in (data.get("script_content_types") or DEFAULT_SCRIPT_CONTENT_TYPES)
        ],
    )

    print(
        f"loaded config from {config_path}: {len(config.skip_body_ext)} extensions, "
        f"{len(config.skip_body_url_patterns)} URL patterns, "
        f"{len(config.handlers)} handlers, "
        f"{len(config.bypasses)} bypasses, "
        f"max_ws_frame_bytes={config.max_ws_frame_bytes}, "
        f"additional_wait={config.additional_wait}s, "
        f"max_network_wait={config.max_network_wait}s, "
        f"{len(config.non_rendered_content_types)} non-rendered content types, "
        f"{len(config.script_content_types)} script content types"
    )
    return config


@dataclass
class ScanResult:
    # the url that was scanned
    url: str
    # path to the screenshot file relative to the results_dir/ directory
    screenshots: Optional[str]
    # list of file names relative to the results_dir/downloads/ directory
    downloads: list[str]
    # html of the page
    dom: Optional[str]
    # JSON of the requests/responses
    requests: Optional[str]


class Scanner:
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.requests = []
        self.bytes_downloaded = 0
        self.domain_stats = {}  # domain -> {bytes_downloaded, request_count, response_count, first_request_time, last_finished_time}
        # request_id -> per-socket record aggregated from WebSocket* CDP events
        self.websockets = {}
        # monotonic ts of the most recent Network.* CDP event; 0.0 until the
        # first event arrives. Read by _wait_for_network_quiescence.
        self.last_network_event_ts: float = 0.0

        config = _load_config(config_path)
        self.SKIP_BODY_EXT = config.skip_body_ext
        self.SKIP_BODY_URL_PATTERNS = config.skip_body_url_patterns
        self.HANDLERS = config.handlers
        self.BYPASSES = config.bypasses
        self.MAX_WS_FRAME_BYTES = config.max_ws_frame_bytes
        self.ADDITIONAL_WAIT = config.additional_wait
        self.MAX_NETWORK_WAIT = config.max_network_wait
        self.NON_RENDERED_CONTENT_TYPES = frozenset(config.non_rendered_content_types)
        self.SCRIPT_CONTENT_TYPES = frozenset(config.script_content_types)

        self._bypass_handlers = {
            "visual_checkbox_bypass": self.visual_checkbox_bypass,
        }

    def _get_domain_stats(self, domain: str) -> dict:
        if domain not in self.domain_stats:
            self.domain_stats[domain] = {
                "bytes_downloaded": 0,
                "request_count": 0,
                "response_count": 0,
                "first_request_time": None,
                "last_finished_time": None,
            }
        return self.domain_stats[domain]

    def _compute_metrics(self, url: str, scan_duration: float) -> dict:
        """Compute per-domain metrics from collected requests."""
        domain_metrics = {}
        for domain, stats in self.domain_stats.items():
            entry = {
                "bytes_downloaded": stats["bytes_downloaded"],
                "request_count": stats["request_count"],
                "response_count": stats["response_count"],
            }
            if stats["first_request_time"] and stats["last_finished_time"]:
                entry["duration_seconds"] = round(
                    stats["last_finished_time"] - stats["first_request_time"], 2
                )
            else:
                entry["duration_seconds"] = 0
            domain_metrics[domain] = entry

        return {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "url_scanned": url,
            "total_bytes_downloaded": self.bytes_downloaded,
            "scan_duration_seconds": round(scan_duration, 2),
            "domain_stats": domain_metrics,
        }

    def _count_inflight_requests(self) -> int:
        """Return the number of unique requestIds with a 'request' event but
        no matching 'response' or 'error' event.

        WebSocket entries (type="websocket_*") are ignored — sockets are
        long-lived streams and not a navigation signal; waiting on them would
        hang the scanner forever.
        """
        seen: set = set()
        settled: set = set()
        for entry in self.requests:
            rid = entry.get("requestId")
            if not rid:
                continue
            t = entry.get("type")
            if t == "request":
                seen.add(rid)
            elif t == "response" or t == "error":
                settled.add(rid)
        return len(seen - settled)

    def _format_websocket_block(self, ws: dict) -> str:
        """Render a WebSocket record as a response-bodies corpus block.

        Starts with 'MARKER URL: <ws_url>' so the existing PhishkitAnalyzer
        URL extractor promotes the ws/wss target to an F_URL observable.
        """
        url = ws.get("url") or "<unknown>"
        lines = ["", "", f"MARKER URL: {url}", ""]
        lines.append(f"WebSocket: {url}")
        if ws.get("created_at"):
            lines.append(f"created_at: {ws['created_at']}")
        status = ws.get("handshake_response_status")
        if status is not None:
            lines.append(f"handshake_response_status: {status}")
        for frame in ws.get("frames", []):
            direction = "SENT" if frame.get("direction") == "sent" else "RECV"
            marker = " [truncated]" if frame.get("payload_truncated") else ""
            lines.append(
                f"[{frame.get('date')}] {direction} op={frame.get('opcode')}{marker} "
                f"{frame.get('payload_data') or ''}"
            )
        if ws.get("closed_at"):
            lines.append(f"closed_at: {ws['closed_at']}")
        lines.append("")
        return "\n".join(lines)

    def top_level_response(self) -> Optional[dict]:
        """Returns the response entry for the top-level document, or None.

        Prefers the CDP ResourceType ("Document"), which is exact. Falls back to
        the first non-redirect response -- the document is the response a
        redirect chain lands on, and subresource responses follow it. The
        fallback matters for responses logged before resource_type was captured.
        """
        candidates = [r for r in self.requests if r.get("type") == "response"]
        for entry in candidates:
            if entry.get("resource_type") == "Document":
                return entry

        for entry in candidates:
            status_code = entry.get("status_code")
            if isinstance(status_code, int) and 300 <= status_code < 400:
                continue
            return entry

        return None

    def top_level_content_type(self) -> Optional[str]:
        """Returns the lowercased content type of the top-level document, or
        None if unknown. "application/javascript; charset=utf-8" -> "application/javascript"."""
        entry = self.top_level_response()
        if entry is None:
            return None

        headers = entry.get("headers")
        if not isinstance(headers, dict):
            return None

        # header casing varies between origins
        for name, value in headers.items():
            if name.lower() == "content-type" and isinstance(value, str):
                return value.split(";", 1)[0].strip().lower()

        return None

    def top_level_is_rendered_page(self) -> bool:
        """Returns False when the scanned URL's own response is something Chrome
        shows in its plain-text viewer instead of rendering as a page (JS, JSON,
        CSS, XML...). Fails open: an unknown content type is treated as a page.
        """
        return self.top_level_content_type() not in self.NON_RENDERED_CONTENT_TYPES

    def appendable_response_entries(self) -> list:
        """Returns the entries whose bodies should be fetched, one per exchange.

        Network.getResponseBody is keyed by requestId, and BOTH the request and
        the response entry for a single exchange carry that id -- so taking
        everything with a requestId fetches and appends every body twice. Only a
        response has a body, which makes type == "response" both the correct
        filter and the deduplicating one. It also excludes websocket_* entries,
        which carry a requestId but are not fetchable this way; those have their
        own pass.
        """
        return [
            entry for entry in self.requests
            if entry.get("type") == "response"
            and "requestId" in entry
            and "url" in entry
        ]

    def check_dom_filter(self, url: str) -> bool:
        """Returns True if the URL's response body should be skipped when
        capturing sub-request content, False otherwise."""
        for pattern in self.SKIP_BODY_URL_PATTERNS:
            if pattern in url:
                return True

        if url.startswith("data:") or url.startswith("blob:"):
            return True
        else:
            ext = (
                url.split(".")[-1].lower()
            )  # grab just the ext from urls like data:image/png;base64,<b64data>

        if "." + ext in self.SKIP_BODY_EXT:
            return True

        return False

    async def receive_handler(self, event: mycdp.network.ResponseReceived):
        # print(f"receive handler callback received event {event}")
        try:
            self.last_network_event_ts = time.monotonic()
            request = {
                "date": datetime.now().isoformat(),
                "type": "response",
                "url": event.response.url,
                "requestId": event.request_id,
                "headers": event.response.headers,
                "status_code": event.response.status,
                "encoded_data_length": event.response.encoded_data_length,
                # CDP ResourceType -- "Document" marks the top-level navigation.
                # It lives on the event, not event.response, so it is NOT in
                # "raw" below. Without it, identifying which response is the page
                # is guesswork: URL equality with the scanned URL breaks on
                # redirects, and ordering is only a heuristic.
                "resource_type": str(event.type_),
                "raw": _safe_to_json(event.response),
            }
            self.requests.append(request)
            domain = urlparse(event.response.url).netloc
            if domain:
                self._get_domain_stats(domain)["response_count"] += 1
        except Exception as e:
            print(f"exception parsing network.ResponseReceived event: {event}: {e}")

    async def loading_finished_handler(self, event: mycdp.network.LoadingFinished):
        try:
            self.last_network_event_ts = time.monotonic()
            encoded_bytes = int(event.encoded_data_length)
            self.bytes_downloaded += encoded_bytes
            now = time.time()
            # update the matching response entry and accumulate domain stats
            for entry in reversed(self.requests):
                if (
                    entry.get("requestId") == event.request_id
                    and entry.get("type") == "response"
                ):
                    entry["encoded_data_length"] = encoded_bytes
                    domain = urlparse(entry["url"]).netloc
                    if domain:
                        stats = self._get_domain_stats(domain)
                        stats["bytes_downloaded"] += encoded_bytes
                        stats["last_finished_time"] = now
                    break
        except Exception as e:
            print(f"exception parsing network.LoadingFinished event: {event}: {e}")

    async def loading_failed_handler(self, event: mycdp.network.LoadingFailed):
        try:
            self.last_network_event_ts = time.monotonic()
            error_text = str(event.error_text) if event.error_text else "unknown"
            canceled = bool(event.canceled) if event.canceled is not None else False
            blocked_reason = str(event.blocked_reason) if event.blocked_reason else None
            print(
                f"network request failed: requestId={event.request_id} error={error_text} canceled={canceled}"
            )

            url = None
            for entry in reversed(self.requests):
                if (
                    entry.get("requestId") == event.request_id
                    and entry.get("type") == "request"
                ):
                    url = entry.get("url")
                    break

            error_entry = {
                "date": datetime.now().isoformat(),
                "type": "error",
                "requestId": event.request_id,
                "error_text": error_text,
                "canceled": canceled,
            }
            if url:
                error_entry["url"] = url
            if blocked_reason:
                error_entry["blocked_reason"] = blocked_reason
            self.requests.append(error_entry)
        except Exception as e:
            print(f"exception parsing network.LoadingFailed event: {event}: {e}")

    async def target_attached_handler(self, event: mycdp.target.AttachedToTarget):
        """Inject stealth overrides into newly attached Worker/ServiceWorker targets.

        NOTE: As of 2026-04, nodriver does not dispatch AttachedToTarget events
        to this handler (the events never arrive). This handler is kept in case
        the issue is fixed upstream. The primary stealth injection path for Workers
        is the Blob constructor patch in STEALTH_JS section 7.
        """
        info = event.target_info
        session = event.session_id
        if info.type_ in ('worker', 'service_worker', 'shared_worker'):
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.evaluate(SW_STEALTH_JS),
                    session_id=str(session),
                )
            except Exception as e:
                print(f"SW stealth inject failed for {info.type_}: {e}")
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.run_if_waiting_for_debugger(),
                    session_id=str(session),
                )
            except Exception as e:
                print(f"SW resume failed for {info.type_}: {e}")
        else:
            # Non-worker target (e.g. iframe) — just resume
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.run_if_waiting_for_debugger(),
                    session_id=str(session),
                )
            except Exception:
                pass

    async def send_handler(self, event: mycdp.network.RequestWillBeSent):
        # print(f"send handler callback received event {event}")
        try:
            self.last_network_event_ts = time.monotonic()
            request = {
                "date": datetime.now().isoformat(),
                "type": "request",
                "requestId": event.request_id,
                "method": event.request.method,
                "url": event.request.url,
                "headers": event.request.headers,
                "raw": _safe_to_json(event.request),
            }
            self.requests.append(request)
            domain = urlparse(event.request.url).netloc
            if domain:
                stats = self._get_domain_stats(domain)
                stats["request_count"] += 1
                if stats["first_request_time"] is None:
                    stats["first_request_time"] = time.time()
        except Exception as e:
            print(f"exception parsing network.RequestWillBeSent event: {event}: {e}")

    def _get_websocket_record(self, request_id: str) -> dict:
        """Return the aggregated record for a socket, creating it if missing.

        Some phishing kits open a socket without a prior WebSocketCreated event
        reaching us (e.g. created in a worker context before the handler attached),
        so every handler tolerates a missing record by creating one on demand.
        """
        record = self.websockets.get(request_id)
        if record is None:
            record = {
                "requestId": request_id,
                "url": None,
                "created_at": None,
                "handshake_request_headers": None,
                "handshake_response_status": None,
                "handshake_response_headers": None,
                "frames": [],
                "closed_at": None,
            }
            self.websockets[request_id] = record
        return record

    def _truncate_ws_payload(self, payload: str) -> tuple[str, bool]:
        """Cap frame payload length. Returns (payload, truncated)."""
        if payload is None:
            return "", False
        if len(payload) > self.MAX_WS_FRAME_BYTES:
            return payload[: self.MAX_WS_FRAME_BYTES], True
        return payload, False

    async def websocket_created_handler(self, event: mycdp.network.WebSocketCreated):
        try:
            record = self._get_websocket_record(str(event.request_id))
            record["url"] = event.url
            record["created_at"] = datetime.now().isoformat()
            self.requests.append({
                "date": record["created_at"],
                "type": "websocket_created",
                "requestId": str(event.request_id),
                "url": event.url,
            })
        except Exception as e:
            print(f"exception parsing network.WebSocketCreated event: {event}: {e}")

    async def websocket_will_send_handshake_handler(
        self, event: mycdp.network.WebSocketWillSendHandshakeRequest
    ):
        try:
            record = self._get_websocket_record(str(event.request_id))
            headers = getattr(event.request, "headers", None) or {}
            record["handshake_request_headers"] = headers
            self.requests.append({
                "date": datetime.now().isoformat(),
                "type": "websocket_handshake_request",
                "requestId": str(event.request_id),
                "url": record.get("url"),
                "headers": headers,
            })
        except Exception as e:
            print(
                f"exception parsing network.WebSocketWillSendHandshakeRequest event: {event}: {e}"
            )

    async def websocket_handshake_response_handler(
        self, event: mycdp.network.WebSocketHandshakeResponseReceived
    ):
        try:
            record = self._get_websocket_record(str(event.request_id))
            status = getattr(event.response, "status", None)
            headers = getattr(event.response, "headers", None) or {}
            record["handshake_response_status"] = status
            record["handshake_response_headers"] = headers
            self.requests.append({
                "date": datetime.now().isoformat(),
                "type": "websocket_handshake_response",
                "requestId": str(event.request_id),
                "url": record.get("url"),
                "status_code": status,
                "headers": headers,
            })
        except Exception as e:
            print(
                f"exception parsing network.WebSocketHandshakeResponseReceived event: {event}: {e}"
            )

    def _append_ws_frame(self, record: dict, direction: str, frame) -> dict:
        opcode = getattr(frame, "opcode", None)
        payload_raw = getattr(frame, "payload_data", None)
        payload, truncated = self._truncate_ws_payload(payload_raw)
        entry = {
            "date": datetime.now().isoformat(),
            "direction": direction,
            "opcode": opcode,
            "payload_data": payload,
            "payload_truncated": truncated,
        }
        record["frames"].append(entry)
        return entry

    async def websocket_frame_sent_handler(self, event: mycdp.network.WebSocketFrameSent):
        try:
            record = self._get_websocket_record(str(event.request_id))
            frame_entry = self._append_ws_frame(record, "sent", event.response)
            self.requests.append({
                **frame_entry,
                "type": "websocket_frame_sent",
                "requestId": str(event.request_id),
                "url": record.get("url"),
            })
        except Exception as e:
            print(f"exception parsing network.WebSocketFrameSent event: {event}: {e}")

    async def websocket_frame_received_handler(
        self, event: mycdp.network.WebSocketFrameReceived
    ):
        try:
            record = self._get_websocket_record(str(event.request_id))
            frame_entry = self._append_ws_frame(record, "received", event.response)
            self.requests.append({
                **frame_entry,
                "type": "websocket_frame_received",
                "requestId": str(event.request_id),
                "url": record.get("url"),
            })
        except Exception as e:
            print(f"exception parsing network.WebSocketFrameReceived event: {event}: {e}")

    async def websocket_frame_error_handler(
        self, event: mycdp.network.WebSocketFrameError
    ):
        try:
            record = self._get_websocket_record(str(event.request_id))
            error_message = getattr(event, "error_message", None)
            self.requests.append({
                "date": datetime.now().isoformat(),
                "type": "websocket_frame_error",
                "requestId": str(event.request_id),
                "url": record.get("url"),
                "error_message": error_message,
            })
        except Exception as e:
            print(f"exception parsing network.WebSocketFrameError event: {event}: {e}")

    async def websocket_closed_handler(self, event: mycdp.network.WebSocketClosed):
        try:
            record = self._get_websocket_record(str(event.request_id))
            record["closed_at"] = datetime.now().isoformat()
            self.requests.append({
                "date": record["closed_at"],
                "type": "websocket_closed",
                "requestId": str(event.request_id),
                "url": record.get("url"),
            })
        except Exception as e:
            print(f"exception parsing network.WebSocketClosed event: {event}: {e}")

    def bypass_recaptcha(self, sb: SB):
        searches = ["Please complete the security check to access the website."]
        page_source = sb.cdp.get_page_source()
        if page_source is None:
            print("could not get page source for reCAPTCHA detection -- skipping")
            return
        recaptcha_detected = False
        for search in searches:
            if search in page_source:
                recaptcha_detected = True
                print("detected reCAPTCHA -- attempting to bypass")
                solver = RecaptchaSolver(driver=sb.driver)
                iframe = sb.driver.locator(
                    "#captchabox > div.next.text-center > div > center > div > div > div > iframe"
                )
                print(f"Found Recaptcha: {iframe}")
                solver.click_recaptcha_v2(iframe=iframe)
                sb.wait(0.5)
                sb.driver.click("#btn")
                print("successfully bypassed reCAPTCHA")
                sb.wait(2)  # <-- why are we waiting here?

        if not recaptcha_detected:
            print("no recaptcha detected")

    def bypass_warnings(self, sb: SB) -> bool:
        page_source = sb.cdp.get_page_source()
        if page_source is None:
            print("could not get page source for warning bypass detection -- skipping")
            return False
        page_source_lower = page_source.lower()
        for bypass in self.BYPASSES:
            bypass_type = bypass.get("type")
            searches = bypass.get("searches")

            if not bypass_type or not searches:
                print(
                    f"Invalid bypass. Missing a required key (searches, type): {bypass}"
                )
                continue

            for search in searches:
                if search.lower() in page_source_lower:
                    print(f"detected bypass type {bypass_type} with search {search}")

                    # does this bypass have a handler?
                    if "handler" in bypass:
                        handler_name = bypass["handler"]
                        handler = self._bypass_handlers.get(handler_name)
                        if handler is None:
                            print(f"warning: unknown bypass handler '{handler_name}'")
                            return False
                        try:
                            handler_config = self.HANDLERS.get(handler_name, {})
                            handler(sb, handler_config)
                            return True
                        except Exception as e:
                            print(f"handler {handler_name} failed: {e}")
                            return False

                    # does this bypass use selectors?
                    elif "selectors" in bypass:
                        for selector in bypass["selectors"]:
                            print(f"trying selector {selector}")
                            try:
                                sb.driver.uc_click(selector, 2)
                                print(
                                    f"Successfully bypassed {bypass_type} with selector {selector}"
                                )
                                return True
                            except Exception as e:
                                print(
                                    f"exception attempting to bypass {bypass_type} with {selector}: {e}"
                                )
                        print(f"failed to bypass {bypass_type}")

                    else:
                        print(
                            f"Invalid bypass. Must define selectors or handler: {bypass}"
                        )
                        return False

            print(f"no bypasses found for {bypass_type}")

        return False

    def _wait_for_page_settle(self, sb: SB, timeout: int = 15):
        """Wait for a newly navigated page to finish rendering.

        Polls the page for network idle (no in-flight requests) and DOM
        stability (body innerHTML length stops changing). This handles
        pages that show a loading spinner or fade-in animation after
        document.readyState is already 'complete'.
        """
        sb.wait_for_ready_state_complete(timeout=5)
        poll = 0.5
        waited = 0.0
        last_len = -1
        stable_count = 0
        while waited < timeout:
            time.sleep(poll)
            waited += poll
            try:
                result = sb.execute_cdp_cmd("Runtime.evaluate", {
                    "expression": "document.body ? document.body.innerHTML.length : 0",
                    "returnByValue": True,
                })
                cur_len = result.get("result", {}).get("value", 0)
            except Exception:
                continue
            if cur_len == last_len:
                stable_count += 1
            else:
                stable_count = 0
            last_len = cur_len
            # Consider settled after DOM is unchanged for 2 consecutive polls
            if stable_count >= 4:
                print(f"page settled after {waited:.1f}s (DOM stable)")
                return
        print(f"page settle timeout after {timeout}s, proceeding anyway")

    def _wait_for_network_quiescence(
        self,
        sb,
        max_extra_wait: float,
        quiet_window: float = 1.0,
        poll_interval: float = 0.25,
    ) -> None:
        """Extend the post-load wait while the page is still fetching or
        navigating. Runs *after* the fixed ``additional_wait`` sleep.

        Exits as soon as all three hold for at least ``quiet_window`` seconds:
          - no in-flight requests (see _count_inflight_requests)
          - no send/receive/loading_finished/loading_failed events fired
          - document.location URL hasn't changed

        Bounded by ``max_extra_wait`` total seconds. Addresses tarpit origins
        and post-readyState redirects (e.g. a <script> that fires
        window.location=... after its body finishes downloading). Does not
        replace the minimum ``additional_wait`` — it runs after it.
        """
        if max_extra_wait <= 0:
            return
        start = time.monotonic()
        try:
            last_url = sb.cdp.get_current_url()
        except Exception:
            last_url = None
        url_last_change = start
        while True:
            now = time.monotonic()
            elapsed = now - start
            if elapsed >= max_extra_wait:
                print(
                    f"network wait: cap reached after {elapsed:.1f}s "
                    f"(inflight={self._count_inflight_requests()})"
                )
                return
            try:
                cur_url = sb.cdp.get_current_url()
            except Exception:
                cur_url = last_url
            if cur_url != last_url:
                print(f"network wait: url changed -> {cur_url}")
                url_last_change = now
                last_url = cur_url
            inflight = self._count_inflight_requests()
            net_idle = (
                now - self.last_network_event_ts
                if self.last_network_event_ts
                else float("inf")
            )
            url_idle = now - url_last_change
            if inflight == 0 and net_idle >= quiet_window and url_idle >= quiet_window:
                print(
                    f"network wait: quiet after {elapsed:.1f}s "
                    f"(net_idle={net_idle:.1f}s, url_idle={url_idle:.1f}s)"
                )
                return
            time.sleep(poll_interval)

    def _locate_click_target(self, sb: SB, selectors: list) -> Optional[dict]:
        """Find the first *visible* element matching any of ``selectors``.

        Returns ``{"x", "y", "sel", "w", "h"}`` where (x, y) is the element's
        on-screen center in viewport/CSS pixels (from ``getBoundingClientRect``),
        or ``None`` if nothing visible matches. Used to locate a challenge
        element by its stable DOM structure when the kit has randomized the
        text/styling/scale that image and text matching rely on.
        """
        expression = """
        (function (sels) {
          for (var i = 0; i < sels.length; i++) {
            var els = document.querySelectorAll(sels[i]);
            for (var j = 0; j < els.length; j++) {
              var el = els[j];
              var r = el.getBoundingClientRect();
              var visible = (typeof el.checkVisibility === 'function') ? el.checkVisibility() : true;
              if (visible && r.width > 1 && r.height > 1 &&
                  r.top < window.innerHeight && r.left < window.innerWidth &&
                  r.bottom > 0 && r.right > 0) {
                return {x: r.left + r.width / 2, y: r.top + r.height / 2,
                        sel: sels[i], w: r.width, h: r.height};
              }
            }
          }
          return null;
        })(%s);
        """ % json.dumps(selectors)
        try:
            result = sb.execute_cdp_cmd("Runtime.evaluate", {
                "expression": expression,
                "returnByValue": True,
            })
        except Exception as e:
            print(f"selector lookup failed: {e}")
            return None
        return result.get("result", {}).get("value")

    def _human_click_at(self, sb: SB, x: int, y: int) -> bool:
        """Click (x, y) — viewport/CSS pixels — the way a human would.

        Moves the mouse toward the target with intermediate mousemove events
        first (phishing pages flag clicks with no prior movement as bots), then
        dispatches a CDP left click and waits up to 15s for the page to
        navigate. Returns True if navigation was detected.

        (x, y) are CSS/viewport pixels — the same space used by
        ``getBoundingClientRect`` and CDP ``Input.dispatchMouseEvent`` — so this
        is correct regardless of devicePixelRatio.
        """
        # Use CDP mouse events instead of pyautogui (which requires a display).
        # Simulate mouse movement toward the target first — phishing pages track
        # mousemove events and flag clicks with no prior movement as bots.
        start_x = random.randint(100, 400)
        start_y = random.randint(100, 400)
        steps = 5
        for i in range(steps):
            frac = (i + 1) / steps
            mx = int(start_x + (x - start_x) * frac)
            my = int(start_y + (y - start_y) * frac)
            sb.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": "mouseMoved",
                "x": mx,
                "y": my,
            })
            time.sleep(0.05)
        url_before = sb.cdp.get_current_url()
        for event_type in ("mousePressed", "mouseReleased"):
            sb.execute_cdp_cmd("Input.dispatchMouseEvent", {
                "type": event_type,
                "x": x,
                "y": y,
                "button": "left",
                "buttons": 1 if event_type == "mousePressed" else 0,
                "clickCount": 1,
            })
        # Wait for the page to navigate after the click (some phishing
        # pages show a "verifying" animation for 10+ seconds before
        # redirecting to the credential-harvesting page). A 15s ceiling
        # keeps total scan time within ACE's delay_analysis budget — if
        # no navigation has happened by then, the site is almost always
        # showing a second challenge on the same origin, so waiting
        # longer burns budget without gaining anything.
        max_wait = 15
        poll_interval = 0.5
        waited = 0.0
        print(f"waiting up to {max_wait}s for navigation after click")
        while waited < max_wait:
            time.sleep(poll_interval)
            waited += poll_interval
            try:
                url_now = sb.cdp.get_current_url()
            except Exception:
                continue
            if url_now != url_before:
                print(f"navigation detected after {waited:.1f}s: {url_now}")
                self._wait_for_page_settle(sb)
                return True
        print(f"no navigation after {max_wait}s")
        return False

    def visual_checkbox_bypass(self, sb: SB, config: dict):
        # This one is always changing and requires special handling: https://github.com/seleniumbase/SeleniumBase/issues/2842
        print("visual checkbox bypass handler")
        sb.wait(
            5
        )  # wait a few sec for the turnstile loading symbol to be replaced by a check box
        checkbox_pngs = config.get("checkbox_pngs", [])
        checkboxes = [Image.open(BytesIO(base64.b64decode(png))) for png in checkbox_pngs]

        enable_multi_click = bool(config.get("enable_multi_click", False))
        max_iterations = int(config.get("max_click_iterations", 2)) if enable_multi_click else 1
        max_iterations = max(1, max_iterations)

        matched_indices: set[int] = set()
        confidence = 0.88

        for iteration in range(1, max_iterations + 1):
            # Use CDP screenshot instead of pyautogui.screenshot() because
            # headless2 mode renders via CDP, not to the Xvfb display (which is black).
            result = sb.execute_cdp_cmd("Page.captureScreenshot", {
                "format": "png",
                "fromSurface": True,
                "captureBeyondViewport": False,
            })
            screenshot = Image.open(BytesIO(base64.b64decode(result["data"])))
            screenshot_name = (
                "pre_bypass_screenshot.png"
                if iteration == 1
                else f"pre_bypass_screenshot_iter{iteration}.png"
            )
            pre_bypass_path = os.path.join(self._output_dir, screenshot_name)
            screenshot.save(pre_bypass_path)
            print(f"saved pre-bypass screenshot to {pre_bypass_path} (size={screenshot.size})")

            # Primary: locate the challenge element by its stable structural
            # selector and human-click its on-screen center. Polymorphic kits
            # randomize text/colors/classes/ids and even the rendered scale
            # (which breaks the image and text matching below), but keep
            # role=button/tabindex=0 so the selector survives across instances.
            selectors = config.get("click_selectors", DEFAULT_CLICK_SELECTORS)
            hit = self._locate_click_target(sb, selectors)
            if hit:
                print(
                    f"selector match {hit['sel']} ({hit['w']:.0f}x{hit['h']:.0f}) "
                    f"— clicking at ({hit['x']:.0f},{hit['y']:.0f})"
                )
                self._human_click_at(sb, int(hit["x"]), int(hit["y"]))
                if enable_multi_click:
                    continue
                return

            # Fallback: image template matching for challenges without a
            # role=button structure. Convert screenshot to grayscale numpy array.
            screenshot_gray = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2GRAY)

            match_loc = None
            match_size = None
            match_idx = None
            for idx, checkbox in enumerate(checkboxes):
                if idx in matched_indices:
                    continue
                # Convert needle to grayscale numpy array. Normalize to RGB first
                # so PNGs saved in modes PIL uses for smaller files (P, L, LA,
                # RGBA) don't crash cv2.cvtColor, which only accepts 3- or
                # 4-channel arrays.
                needle_rgb = checkbox if checkbox.mode == "RGB" else checkbox.convert("RGB")
                needle_gray = cv2.cvtColor(np.array(needle_rgb), cv2.COLOR_RGB2GRAY)

                if needle_gray.shape[0] > screenshot_gray.shape[0] or needle_gray.shape[1] > screenshot_gray.shape[1]:
                    print(f"skipping {checkbox.size}: larger than screenshot")
                    continue

                # cv2.matchTemplate is what pyautogui.locate delegates to internally
                tm_result = cv2.matchTemplate(screenshot_gray, needle_gray, cv2.TM_CCOEFF_NORMED)
                _, max_val, _, max_loc = cv2.minMaxLoc(tm_result)
                print(f"iter {iteration} template match idx={idx} {checkbox.size}: score={max_val:.4f} (threshold={confidence})")
                if max_val >= confidence:
                    match_loc = max_loc
                    match_size = (needle_gray.shape[1], needle_gray.shape[0])
                    match_idx = idx
                    break

            if not (match_loc and match_size):
                if iteration == 1:
                    print("Failed to find checkbox visually")
                else:
                    print(f"iter {iteration}: no further matches, done after {iteration - 1} click(s)")
                return

            x = match_loc[0] + match_size[0] // 2
            y = match_loc[1] + match_size[1] // 2
            print(f"Visual match — clicking checkbox at ({x},{y})")
            self._human_click_at(sb, x, y)
            matched_indices.add(match_idx)

        if enable_multi_click:
            print(f"reached max_click_iterations={max_iterations}, stopping")

    def scan(
        self,
        url: str,
        output_dir: str,
        additional_wait: Optional[float] = 3.0,
        proxy: Optional[str] = None,
        max_network_wait: Optional[float] = 10.0,
    ) -> ScanResult:

        # output directory must already exist
        if not os.path.isdir(output_dir):
            raise Exception(f"output_dir {output_dir} does not exist")

        self._output_dir = output_dir
        scan_start_time = time.time()
        screenshot_path = None
        downloads = []
        dom_path = None
        requests_path = None

        # see https://github.com/seleniumbase/SeleniumBase/blob/master/seleniumbase/plugins/sb_manager.py
        sb_kwargs = dict(
            undetectable=True,  # use undetected-chromedriver to evade bot detection
            uc_cdp_events=True,
            log_cdp_events=True,
            xvfb=True,
            xvfb_metrics="1920,1080",  # realistic screen resolution (default is a headless giveaway)
            headless2=True,  # Use Chromium's new headless mode. (Has more features)
            agent=BYPASS_UA,  # set UA at browser level so Workers also get the spoofed UA
            window_size="1920,1040",  # slightly smaller than screen to simulate taskbar
            chromium_arg="--disable-blink-features=AutomationControlled",  # removes navigator.webdriver at Blink level
        )
        if proxy:
            sb_kwargs["proxy"] = proxy
            # redact credentials for logging
            if "@" in proxy:
                prefix, suffix = proxy.rsplit("@", 1)
                if "://" in prefix:
                    scheme = prefix.split("://", 1)[0]
                    redacted = f"{scheme}://****:****@{suffix}"
                else:
                    redacted = f"****:****@{suffix}"
            else:
                redacted = proxy
            print(f"using proxy: {redacted}")

        with SB(**sb_kwargs) as sb:
            # docker stop delivers SIGTERM with 5s grace before SIGKILL (see
            # --stop-timeout 5 in phishkit/phishkit.py). Best-effort flush of
            # whatever scan state we have so analysts get partial dom/requests
            # /screenshot/metrics instead of an empty output dir when the
            # celery worker kills us mid-navigation.
            def _on_term(signum, frame):
                # requests.json and metrics.json are flushed unconditionally --
                # they are content-type agnostic, and requests.json is what marks
                # the output as recoverable.
                try:
                    with open(os.path.join(output_dir, "requests.json"), "w") as fp:
                        json.dump(self.requests, fp, indent=2)
                except Exception as e:
                    print(f"sigterm: failed to flush requests.json: {e}")

                # The dom/screenshot captures are worthless for the same reason
                # they are on the normal path: if Chrome is showing its plain-text
                # viewer there is no page to capture. Fails open -- before any
                # response is logged this reads as a rendered page, so an
                # interrupted navigation still flushes whatever we have.
                interrupted_rendered_page = self.top_level_is_rendered_page()
                if interrupted_rendered_page:
                    try:
                        with open(os.path.join(output_dir, "dom.html"), "w") as fp:
                            fp.write(sb.get_page_source())
                    except Exception as e:
                        print(f"sigterm: failed to flush dom.html: {e}")
                    try:
                        sb.save_screenshot(
                            os.path.join(output_dir, "screenshot.png"), selector="body"
                        )
                    except Exception as e:
                        print(f"sigterm: failed to save screenshot: {e}")
                else:
                    print(
                        f"sigterm: skipping dom/screenshot flush: top level response is "
                        f"{self.top_level_content_type()}, not a rendered page"
                    )
                try:
                    metrics = self._compute_metrics(url, time.time() - scan_start_time)
                    metrics["interrupted"] = True
                    with open(os.path.join(output_dir, "metrics.json"), "w") as fp:
                        json.dump(metrics, fp, indent=2)
                except Exception as e:
                    print(f"sigterm: failed to flush metrics.json: {e}")
                sys.exit(143)  # 128 + SIGTERM

            signal.signal(signal.SIGTERM, _on_term)

            # ask Jeremy about this
            sb.activate_cdp_mode("about:blank")
            self._cdp_tab = sb.cdp.page  # nodriver Tab for sending CDP commands from handlers
            sb.cdp.add_handler(mycdp.network.RequestWillBeSent, self.send_handler)
            sb.cdp.add_handler(mycdp.network.ResponseReceived, self.receive_handler)
            sb.cdp.add_handler(
                mycdp.network.LoadingFinished, self.loading_finished_handler
            )
            sb.cdp.add_handler(mycdp.network.LoadingFailed, self.loading_failed_handler)

            # WebSocket lifecycle capture. Chrome emits WebSocket events under the
            # Network domain but on separate event classes — without these, ws/wss
            # traffic is invisible to the scanner and never shows up in requests.json.
            sb.cdp.add_handler(
                mycdp.network.WebSocketCreated, self.websocket_created_handler
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketWillSendHandshakeRequest,
                self.websocket_will_send_handshake_handler,
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketHandshakeResponseReceived,
                self.websocket_handshake_response_handler,
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketFrameSent, self.websocket_frame_sent_handler
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketFrameReceived,
                self.websocket_frame_received_handler,
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketFrameError, self.websocket_frame_error_handler
            )
            sb.cdp.add_handler(
                mycdp.network.WebSocketClosed, self.websocket_closed_handler
            )

            # Auto-attach to Worker/ServiceWorker targets to inject stealth code.
            # NOTE: waitForDebuggerOnStart must be False. When True, Chrome pauses
            # new Worker targets before execution, expecting the debugger to resume
            # them via Runtime.runIfWaitingForDebugger. However, nodriver/SeleniumBase
            # does not dispatch Target.AttachedToTarget events to our handler, so
            # paused Workers are never resumed and hang indefinitely. With False,
            # Workers start immediately; stealth overrides are still injected into
            # non-blob Workers via the Blob constructor patch in STEALTH_JS section 7.
            sb.cdp.add_handler(mycdp.target.AttachedToTarget, self.target_attached_handler)
            sb.execute_cdp_cmd('Target.setAutoAttach', {
                'autoAttach': True,
                'waitForDebuggerOnStart': False,
                'flatten': True,
            })

            # phishkits detecting on User Agent + Sec-Ch-Ua-Platform on 2025-02-26
            sb.execute_cdp_cmd(
                "Network.setExtraHTTPHeaders",
                {"headers": {"Sec-Ch-Ua-Platform": "Windows"}},
            )

            # override User-Agent, navigator.userAgent, navigator.platform,
            # and all Sec-Ch-Ua-* Client Hints to present as Windows Chrome
            sb.execute_cdp_cmd(
                "Network.setUserAgentOverride",
                {
                    "userAgent": BYPASS_UA,
                    "platform": "Win32",
                    "userAgentMetadata": {
                        # GREASE brand convention rotates with Chrome versions.
                        # Brands and fullVersionList are dynamically captured from the
                        # installed Chrome at module load (see _detect_chrome_grease).
                        # Chrome's GREASE algorithm rotates its "Not_A Brand"-style
                        # entry across versions; asking Chrome itself keeps us aligned
                        # automatically, no hardcoded staleness to babysit.
                        "brands": BYPASS_BRANDS,
                        "fullVersionList": BYPASS_FULL_VERSION_LIST,
                        "platform": "Windows",
                        "platformVersion": "10.0.0",
                        "architecture": "x86",
                        "model": "",
                        "mobile": False,
                        "bitness": "64",
                        "wow64": False,
                    },
                },
            )

            # Spoof timezone and locale at the CDP level so JS Intl APIs report a
            # plausible US timezone instead of the container's UTC default.
            # Intl.DateTimeFormat().resolvedOptions().timeZone == 'UTC' is a
            # well-known automation signal (creepjs + many CF Bot Management
            # heuristics flag it). The STEALTH_JS Intl override is a backup for
            # contexts where setTimezoneOverride doesn't propagate.
            try:
                sb.execute_cdp_cmd(
                    "Emulation.setTimezoneOverride",
                    {"timezoneId": "America/New_York"},
                )
            except Exception as e:
                print(f"setTimezoneOverride failed (continuing): {e}")
            try:
                sb.execute_cdp_cmd(
                    "Emulation.setLocaleOverride",
                    {"locale": "en-US"},
                )
            except Exception as e:
                print(f"setLocaleOverride failed (continuing): {e}")

            # emulate a realistic desktop screen (1920x1080)
            # This sets screen dimensions at the browser level, affecting both
            # JavaScript Screen API and CSS @media queries consistently.
            # Set width/height to 0 so the viewport is determined by window_size,
            # avoiding the "viewport == screen" signal that flags headless browsers.
            sb.execute_cdp_cmd(
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": 0,
                    "height": 0,
                    "deviceScaleFactor": 1,
                    "mobile": False,
                    "screenWidth": 1920,
                    "screenHeight": 1080,
                },
            )

            # Set dark color scheme so CreepJS prefersLightColor check returns false.
            # This uses Emulation CDP so both CSS @media and JS matchMedia agree (no lie).
            sb.execute_cdp_cmd(
                "Emulation.setEmulatedMedia",
                {
                    "features": [
                        {"name": "prefers-color-scheme", "value": "dark"},
                    ],
                },
            )

            # inject stealth overrides before any page scripts run
            sb.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": STEALTH_JS},
            )

            # open the url
            print(f"opening {url}")
            sb.cdp.open(url)

            # wait for the page to load
            print(f"waiting for {url} to load")
            sb.wait_for_ready_state_complete(timeout=3)

            # Bypasses match against the page source. When the scanned URL is a
            # script, Chrome shows the source as text -- so the *source* becomes
            # the page text, and a challenge kit's own UI strings ("Continue",
            # "Click to verify") match against its own source code. That fires a
            # bypass handler against a plain-text document with no challenge on
            # it: it clicks nothing, burns click iterations and nav waits, and
            # leaves a pre_bypass_screenshot of rendered source behind. There is
            # nothing to bypass on a document Chrome never rendered.
            is_rendered_page = self.top_level_is_rendered_page()
            if not is_rendered_page:
                print(
                    f"skipping bypasses: top level response is "
                    f"{self.top_level_content_type()}, not a rendered page"
                )

            # First pass — catches challenges that are already rendered.
            bypassed = False
            if is_rendered_page:
                self.bypass_recaptcha(sb)
                bypassed = self.bypass_warnings(sb)

            # Many phishing kits defer challenge rendering: an inline stager
            # uses setTimeout(...) to inject a second-stage script that
            # fetches/decodes the real challenge UI over the next 1-3s.
            # readyState="complete" fires before that chain finishes, so the
            # first bypass pass sees a page with no challenge on it. After
            # the additional_wait we retry so the deferred UI can be matched.
            if additional_wait:
                print(f"waiting for additional {additional_wait} seconds")
                time.sleep(additional_wait)

            # Extend the wait adaptively while the page is still fetching or
            # navigating — tarpitted origins (e.g. a 6s cfOrigin delay before
            # the HTML arrives) and post-readyState redirects fired by
            # downloaded <script> elements both miss the fixed additional_wait
            # above. Bounded by max_network_wait so long-poll XHRs don't hang
            # the scanner forever.
            if max_network_wait and max_network_wait > 0:
                self._wait_for_network_quiescence(sb, max_extra_wait=max_network_wait)

            if is_rendered_page and not bypassed:
                self.bypass_recaptcha(sb)
                self.bypass_warnings(sb)

            screenshot_path = os.path.join(output_dir, "screenshot.png")

            # Both captures below record what Chrome rendered -- one as a picture,
            # one as a DOM. When the top-level response is something Chrome shows
            # in its plain-text viewer, it rendered no page: the screenshot is a
            # picture of source, and the DOM is the viewer's own <pre> wrapper
            # around that same source, HTML-escaped. Neither says anything the
            # captured body doesn't already say better -- the body is kept
            # verbatim in script.js (scripts) or response_bodies.txt
            # (everything else). self.requests is fully populated by now (the
            # navigation completed and _wait_for_network_quiescence ran above), so
            # the content type is known without re-fetching anything.
            top_level_content_type = self.top_level_content_type()

            # get the screenshot
            if not is_rendered_page:
                print(
                    f"skipping screenshot: top level response is {top_level_content_type}, "
                    f"not a rendered page"
                )
            else:
                try:
                    print(f"saving screenshot to {screenshot_path}")
                    sb.save_screenshot(screenshot_path, selector="body")
                    print(f"screenshot saved to {screenshot_path}")

                except Exception as e:
                    print(f"failed to save screenshot: {e}")

            # capture the dom
            if not is_rendered_page:
                print(
                    f"skipping dom capture: top level response is {top_level_content_type}, "
                    f"not a rendered page"
                )
            else:
                dom_path = os.path.join(output_dir, "dom.html")
                try:
                    print(f"saving dom to {dom_path}")
                    with open(dom_path, "w") as fp:
                        fp.write(sb.get_page_source())
                except Exception as e:
                    print(f"Timed out waiting for html: {e}")

            requests_path = os.path.join(output_dir, "requests.json")
            with open(requests_path, "w") as fp:
                json.dump(self.requests, fp, indent=2)

            # write scan metrics
            try:
                scan_duration = time.time() - scan_start_time
                metrics = self._compute_metrics(url, scan_duration)
                metrics_path = os.path.join(output_dir, "metrics.json")
                with open(metrics_path, "w") as fp:
                    json.dump(metrics, fp, indent=2)
                print(f"metrics written to {metrics_path}")
            except Exception as e:
                print(f"failed to write metrics: {e}")

            # When the scanned URL itself serves JavaScript, Chrome never executes
            # it -- it displays the source in the plain-text viewer. So nothing
            # requests the URLs inside it, and the promotion passes in
            # PhishkitAnalyzer (MARKER URL lines + requests.json) can't see them.
            # Divert that body to its own .js artifact: ACE runs the JS
            # deobfuscator on a .js file, and the deobfuscated output carries the
            # extract_urls directive, which is what actually recovers the staged
            # URLs. Everything else goes to the corpus, which is grep/yara
            # material and is never handed to a parser.
            top_level_entry = self.top_level_response()
            top_level_request_id = (
                top_level_entry.get("requestId") if top_level_entry else None
            )
            divert_top_level_body = (
                top_level_request_id is not None
                and top_level_content_type in self.SCRIPT_CONTENT_TYPES
            )

            # write captured response bodies to the corpus, not into dom.html
            bodies_path = os.path.join(output_dir, RESPONSE_BODIES_NAME)
            for request in self.appendable_response_entries():
                if self.check_dom_filter(request["url"]):
                    continue

                is_top_level_body = (
                    divert_top_level_body
                    and request.get("requestId") == top_level_request_id
                )

                print(f"grabbing response body for {request['url']}")

                # see https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json
                try:
                    response_data = sb.execute_cdp_cmd(
                        "Network.getResponseBody",
                        {"requestId": request["requestId"]},
                    )["body"]

                    if is_top_level_body:
                        body_path = os.path.join(output_dir, TOP_LEVEL_SCRIPT_NAME)
                        print(
                            f"saving top level script body to {body_path} "
                            f"({top_level_content_type})"
                        )
                        with open(body_path, "wb") as fp:
                            fp.write(response_data.encode("utf-8", errors="ignore"))
                        continue

                    appended_data = (
                        "\n\nMARKER URL: " + request["url"] + "\n\n" + response_data
                    )
                    with open(bodies_path, "ab") as fp:
                        fp.write(appended_data.encode("utf-8", errors="ignore"))
                except Exception as e:
                    print(
                        f"failed to grab response body for requestId {request.get('requestId', -1)}: {e}"
                    )

            # append WebSocket lifecycle + frame data to the corpus. One MARKER
            # URL line per socket so PhishkitAnalyzer promotes ws/wss URLs to
            # F_URL observables via the existing extraction path.
            for ws in self.websockets.values():
                try:
                    block = self._format_websocket_block(ws)
                    with open(bodies_path, "ab") as fp:
                        fp.write(block.encode("utf-8", errors="ignore"))
                except Exception as e:
                    print(
                        f"failed to append websocket block for {ws.get('url')}: {e}"
                    )

            downloads = []
            downloads_dir = os.path.join(output_dir, "downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            for dir_path, dir_names, file_names in os.walk(sb.get_downloads_folder()):
                # skip SeleniumBase proxy extension directory (contains credentials)
                dir_names[:] = [d for d in dir_names if d != "proxy_ext_dir"]
                if "proxy_ext_dir" in Path(dir_path).parts:
                    continue
                for file_name in file_names:
                    if file_name.endswith(".lock"):
                        continue

                    source_file_path = os.path.join(dir_path, file_name)
                    target_file_path = os.path.join(downloads_dir, file_name)
                    print(f"copying {source_file_path} to {target_file_path}")
                    shutil.copy(source_file_path, target_file_path)
                    downloads.append(
                        os.path.relpath(target_file_path, start=output_dir)
                    )

        return ScanResult(
            url=url,
            screenshots=screenshot_path,
            downloads=downloads,
            dom=dom_path,
            requests=requests_path,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="The target to scan. By default this is a URL.")
    parser.add_argument(
        "--file",
        default=False,
        action="store_true",
        help="Interpret the target as a local file path.",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="The directory to use for the output files.",
    )
    parser.add_argument(
        "--additional-wait",
        type=int,
        default=None,
        help="Fixed minimum sleep (seconds) after readyState=complete. "
             "Defaults to scan_waits.additional_wait from the YAML config.",
    )
    parser.add_argument(
        "--max-network-wait",
        type=float,
        default=None,
        help="Extra cap (seconds) on top of --additional-wait during which the "
             "scanner waits for network/URL quiescence. Defaults to "
             "scan_waits.max_network_wait from the YAML config.",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy string for SeleniumBase (e.g. host:port or user:pass@host:port).",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to phishkit YAML config file.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir, exist_ok=True)

    if args.file:
        target = Path(args.target).as_uri()
    else:
        target = args.target

    scanner = Scanner(config_path=args.config)
    additional_wait = (
        args.additional_wait if args.additional_wait is not None
        else scanner.ADDITIONAL_WAIT
    )
    max_network_wait = (
        args.max_network_wait if args.max_network_wait is not None
        else scanner.MAX_NETWORK_WAIT
    )
    result = scanner.scan(
        target,
        args.output_dir,
        additional_wait,
        proxy=args.proxy,
        max_network_wait=max_network_wait,
    )
    print(result)
    sys.exit(0)
