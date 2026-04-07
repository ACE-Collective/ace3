#!/usr/bin/env python

import argparse
import base64
import json
import os
import random
import shutil
import sys
import time
from dataclasses import dataclass
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

# Stealth JS to inject into ServiceWorker/Worker contexts via CDP.
# Must be self-contained (no references to main page globals).
SW_STEALTH_JS = """
(function() {
    const navProto = Object.getPrototypeOf(navigator);
    if (navProto) {
        Object.defineProperty(navProto, 'platform', {
            get: () => 'Win32', configurable: true,
        });
    }
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
})();
"""

BYPASS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
BYPASS_CHROME_MAJOR = "146"
BYPASS_CHROME_FULL = "146.0.0.0"

# JavaScript to inject before any page scripts run, to mask automation signals.
STEALTH_JS = """
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
    Object.defineProperty(Navigator.prototype, 'platform', {
        get: () => 'Win32',
        configurable: true,
    });
}

// 7. Inject stealth overrides into Worker contexts
// Page.addScriptToEvaluateOnNewDocument only covers the main page; Workers get a
// clean global.  We intercept Blob construction and Worker creation to prepend
// stealth overrides into any JavaScript blob that might be used as a Worker script.
(function() {
    const WORKER_STEALTH = [
        '/* stealth */',
        'const navProto = Object.getPrototypeOf(navigator);',
        'if (navProto) {',
        '  Object.defineProperty(navProto, "platform", { get: () => "Win32", configurable: true });',
        '}',
        'if (typeof OffscreenCanvas !== "undefined") {',
        '  const _gc = OffscreenCanvas.prototype.getContext;',
        '  OffscreenCanvas.prototype.getContext = function(t, a) {',
        '    const c = _gc.call(this, t, a);',
        '    if (c && (t==="webgl"||t==="webgl2"||t==="experimental-webgl")) {',
        '      const _gp = c.getParameter.bind(c);',
        '      c.getParameter = function(p) {',
        '        if (p===0x9245) return "Intel Inc.";',
        '        if (p===0x9246) return "Intel Iris OpenGL Engine";',
        '        return _gp(p);',
        '      };',
        '    }',
        '    return c;',
        '  };',
        '}',
    ].join('\\n');

    // Patch Worker/SharedWorker constructors for URL-based Workers.
    // DIAGNOSTIC: Log Worker creation, capture blob source, monitor lifecycle.
    window.__workerDiag = { created: 0, blobSources: [], errors: [] };

    function patchWorkerCtor(Orig, name) {
        const Patched = function(scriptURL, options) {
            if (options && options.type === 'module') {
                return new Orig(scriptURL, options);
            }
            try {
                const url = String(scriptURL);
                if (url.startsWith('blob:')) {
                    window.__workerDiag.created++;
                    console.log('__DIAG_WORKER_CREATE__:blob:' + window.__workerDiag.created);
                    const w = new Orig(scriptURL, options);
                    // Monitor Worker lifecycle (use addEventListener to avoid
                    // overriding the page's own onmessage/onerror handlers).
                    w.addEventListener('error', function(e) {
                        var msg = e && e.message ? e.message : String(e);
                        console.log('__DIAG_WORKER_ERROR__:' + msg);
                        window.__workerDiag.errors.push(msg);
                    });
                    w.addEventListener('message', function(e) {
                        console.log('__DIAG_WORKER_MESSAGE__:' + JSON.stringify(e.data).substring(0, 500));
                    });
                    return w;
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

    // DIAGNOSTIC: Intercept Blob constructor to capture Worker script sources.
    const _origBlob = window.Blob;
    window.Blob = function(parts, options) {
        if (parts && parts.length > 0 && options && /javascript/i.test(options.type || '')) {
            try {
                var src = '';
                for (var i = 0; i < parts.length; i++) {
                    if (typeof parts[i] === 'string') src += parts[i];
                }
                // Log first 2000 chars of any JS blob (likely Worker scripts)
                console.log('__DIAG_BLOB_JS__:' + src.substring(0, 2000));
                window.__workerDiag.blobSources.push(src.substring(0, 2000));
            } catch(e) {}
        }
        return new _origBlob(parts, options);
    };
    window.Blob.prototype = _origBlob.prototype;
    Object.defineProperty(window.Blob, 'name', { value: 'Blob' });
})();

// 8. Spoof WebGL renderer to hide SwiftShader
// Chrome falls back to SwiftShader in Docker (no GPU). The renderer string
// "SwiftShader" is a known headless signal. We override getParameter to
// return a common integrated GPU string instead.
(function() {
    const SPOOFED_VENDOR = 'Intel Inc.';
    const SPOOFED_RENDERER = 'Intel Iris OpenGL Engine';
    const getParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        // UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246
        if (param === 0x9245) return SPOOFED_VENDOR;
        if (param === 0x9246) return SPOOFED_RENDERER;
        return getParam.call(this, param);
    };
    if (typeof WebGL2RenderingContext !== 'undefined') {
        const getParam2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            if (param === 0x9245) return SPOOFED_VENDOR;
            if (param === 0x9246) return SPOOFED_RENDERER;
            return getParam2.call(this, param);
        };
    }
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
"""

# Default config path baked into the scanner Docker image.
DEFAULT_CONFIG_PATH = "/opt/app/phishkit_config.yaml"


@dataclass
class PhishkitConfig:
    skip_body_ext: list
    skip_body_url_patterns: list
    handlers: dict
    bypasses: list


def _load_config(config_path: str) -> PhishkitConfig:
    """Load phishkit config from a YAML file.

    Returns a PhishkitConfig with skip_body_ext, skip_body_url_patterns,
    handlers, and bypasses.  Raises on missing or invalid config.
    """
    with open(config_path, "r") as f:
        data = safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"config at {config_path} is not a YAML mapping")

    config = PhishkitConfig(
        skip_body_ext=data.get("skip_body_extensions", []),
        skip_body_url_patterns=data.get("skip_body_url_patterns", []),
        handlers=data.get("handlers", {}),
        bypasses=data.get("bypasses", []),
    )

    print(
        f"loaded config from {config_path}: {len(config.skip_body_ext)} extensions, "
        f"{len(config.skip_body_url_patterns)} URL patterns, "
        f"{len(config.handlers)} handlers, "
        f"{len(config.bypasses)} bypasses"
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

        config = _load_config(config_path)
        self.SKIP_BODY_EXT = config.skip_body_ext
        self.SKIP_BODY_URL_PATTERNS = config.skip_body_url_patterns
        self.HANDLERS = config.handlers
        self.BYPASSES = config.bypasses

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

    def check_dom_filter(self, url: str) -> bool:
        """Returns True if the URL's response body should be skipped when
        appending sub-request content to dom.html, False otherwise."""
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
            request = {
                "date": datetime.now().isoformat(),
                "type": "response",
                "url": event.response.url,
                "requestId": event.request_id,
                "headers": event.response.headers,
                "status_code": event.response.status,
                "encoded_data_length": event.response.encoded_data_length,
                "raw": event.response.to_json(),
            }
            self.requests.append(request)
            domain = urlparse(event.response.url).netloc
            if domain:
                self._get_domain_stats(domain)["response_count"] += 1
        except Exception as e:
            print(f"exception parsing network.ResponseReceived event: {event}: {e}")

    async def loading_finished_handler(self, event: mycdp.network.LoadingFinished):
        try:
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

        Target.setAutoAttach with waitForDebuggerOnStart=True pauses new targets
        before they execute. We inject stealth code and then resume execution.
        """
        info = event.target_info
        session = event.session_id
        print(f"DIAG target_attached: type={info.type_} url={info.url[:120] if info.url else '(none)'} session={session}")
        if info.type_ in ('worker', 'service_worker', 'shared_worker'):
            # DIAGNOSTIC: Run a quick check inside the Worker before stealth injection
            try:
                result = await self._cdp_tab.send(
                    mycdp.runtime.evaluate(
                        '(function() {'
                        '  var diag = {};'
                        '  diag.hasSubtle = typeof crypto !== "undefined" && typeof crypto.subtle !== "undefined";'
                        '  diag.isSecure = typeof isSecureContext !== "undefined" ? isSecureContext : "unknown";'
                        '  diag.webdriver = navigator.webdriver;'
                        '  diag.platform = navigator.platform;'
                        '  diag.hwConcurrency = navigator.hardwareConcurrency;'
                        '  diag.type = typeof self !== "undefined" ? self.constructor.name : "unknown";'
                        '  return JSON.stringify(diag);'
                        '})()'
                    ),
                    session_id=str(session),
                )
                print(f"DIAG worker_env ({info.type_}): {result}")
            except Exception as e:
                print(f"DIAG worker_env check failed for {info.type_}: {e}")
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.evaluate(SW_STEALTH_JS),
                    session_id=str(session),
                )
                print(f"DIAG stealth_inject OK for {info.type_}")
            except Exception as e:
                print(f"SW stealth inject failed for {info.type_}: {e}")
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.run_if_waiting_for_debugger(),
                    session_id=str(session),
                )
                print(f"DIAG worker_resumed for {info.type_}")
            except Exception as e:
                print(f"SW resume failed for {info.type_}: {e}")
        else:
            print(f"DIAG non-worker target: type={info.type_}, resuming")
            # Non-worker target (e.g. iframe) — just resume
            try:
                await self._cdp_tab.send(
                    mycdp.runtime.run_if_waiting_for_debugger(),
                    session_id=str(session),
                )
            except Exception:
                pass

    async def diag_console_handler(self, event: mycdp.runtime.ConsoleAPICalled):
        """DIAGNOSTIC: Print all console messages from the page, especially __DIAG_* ones."""
        try:
            if not event.args:
                return
            text = str(event.args[0].value) if event.args[0].value else ""
            if text.startswith("__DIAG_"):
                print(f"DIAG console: {text[:500]}")
            elif text.startswith("__POW") or "worker" in text.lower() or "challenge" in text.lower():
                print(f"DIAG console (other): {text[:300]}")
        except Exception as e:
            print(f"DIAG console handler error: {e}")

    async def send_handler(self, event: mycdp.network.RequestWillBeSent):
        # print(f"send handler callback received event {event}")
        try:
            request = {
                "date": datetime.now().isoformat(),
                "type": "request",
                "requestId": event.request_id,
                "method": event.request.method,
                "url": event.request.url,
                "headers": event.request.headers,
                "raw": event.request.to_json(),
            }
            self.requests.append(request)
            domain = urlparse(event.request.url).netloc
            if domain:
                stats = self._get_domain_stats(domain)
                stats["request_count"] += 1
                if stats["first_request_time"] is None:
                    stats["first_request_time"] = time.time()
        except Exception as e:
            print(f"exception parsing network.ResponseReceived event: {event}: {e}")

    def bypass_recaptcha(self, sb: SB):
        searches = ["Please complete the security check to access the website."]
        recaptcha_detected = False
        for search in searches:
            if search in sb.cdp.get_page_source():
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
        for bypass in self.BYPASSES:
            bypass_type = bypass.get("type")
            searches = bypass.get("searches")

            if not bypass_type or not searches:
                print(
                    f"Invalid bypass. Missing a required key (searches, type): {bypass}"
                )
                continue

            for search in searches:
                if search in sb.cdp.get_page_source():
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

    def visual_checkbox_bypass(self, sb: SB, config: dict):
        # This one is always changing and requires special handling: https://github.com/seleniumbase/SeleniumBase/issues/2842
        print("visual checkbox bypass handler")
        sb.wait(
            5
        )  # wait a few sec for the turnstile loading symbol to be replaced by a check box
        checkbox_pngs = config.get("checkbox_pngs", [])
        checkboxes = [Image.open(BytesIO(base64.b64decode(png))) for png in checkbox_pngs]

        # Use CDP screenshot instead of pyautogui.screenshot() because
        # headless2 mode renders via CDP, not to the Xvfb display (which is black).
        result = sb.execute_cdp_cmd("Page.captureScreenshot", {
            "format": "png",
            "fromSurface": True,
            "captureBeyondViewport": False,
        })
        screenshot = Image.open(BytesIO(base64.b64decode(result["data"])))
        pre_bypass_path = os.path.join(self._output_dir, "pre_bypass_screenshot.png")
        screenshot.save(pre_bypass_path)
        print(f"saved pre-bypass screenshot to {pre_bypass_path} (size={screenshot.size})")

        # Convert screenshot to grayscale numpy array for template matching
        screenshot_gray = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2GRAY)

        match_loc = None
        match_size = None
        confidence = 0.88
        for checkbox in checkboxes:
            # Convert needle to grayscale numpy array
            if checkbox.mode == "RGBA":
                needle_gray = cv2.cvtColor(np.array(checkbox.convert("RGB")), cv2.COLOR_RGB2GRAY)
            else:
                needle_gray = cv2.cvtColor(np.array(checkbox), cv2.COLOR_RGB2GRAY)

            if needle_gray.shape[0] > screenshot_gray.shape[0] or needle_gray.shape[1] > screenshot_gray.shape[1]:
                print(f"skipping {checkbox.size}: larger than screenshot")
                continue

            # cv2.matchTemplate is what pyautogui.locate delegates to internally
            result = cv2.matchTemplate(screenshot_gray, needle_gray, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, max_loc = cv2.minMaxLoc(result)
            print(f"template match for {checkbox.size}: score={max_val:.4f} (threshold={confidence})")
            if max_val >= confidence:
                match_loc = max_loc
                match_size = (needle_gray.shape[1], needle_gray.shape[0])
                break

        if match_loc and match_size:
            x = match_loc[0] + match_size[0] // 2
            y = match_loc[1] + match_size[1] // 2
            print(f"Visual match — clicking checkbox at ({x},{y})")
            # Use CDP mouse events instead of pyautogui (which requires a display).
            # Coordinates from the CDP screenshot are already in viewport space.
            # Simulate mouse movement toward the checkbox first — phishing pages
            # track mousemove events and flag clicks with no prior movement as bots.
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
            # redirecting to the credential-harvesting page).
            max_wait = 60
            poll_interval = 1
            waited = 0
            print(f"waiting up to {max_wait}s for navigation after click")
            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval
                # DIAGNOSTIC: Every 5 seconds, query Worker diagnostic state from page
                if waited % 5 == 0:
                    try:
                        diag = sb.execute_cdp_cmd("Runtime.evaluate", {
                            "expression": "JSON.stringify(window.__workerDiag || 'not set')",
                            "returnByValue": True,
                        })
                        print(f"DIAG [{waited}s] workerDiag: {diag.get('result', {}).get('value', '?')}")
                    except Exception as e:
                        print(f"DIAG [{waited}s] workerDiag query failed: {e}")
                try:
                    url_now = sb.cdp.get_current_url()
                except Exception:
                    continue
                if url_now != url_before:
                    print(f"navigation detected after {waited}s: {url_now}")
                    sb.wait_for_ready_state_complete(timeout=5)
                    break
            else:
                # DIAGNOSTIC: Final dump of Worker state
                try:
                    diag = sb.execute_cdp_cmd("Runtime.evaluate", {
                        "expression": "JSON.stringify(window.__workerDiag || 'not set')",
                        "returnByValue": True,
                    })
                    print(f"DIAG [final] workerDiag: {diag.get('result', {}).get('value', '?')}")
                except Exception:
                    pass
                print(f"no navigation after {max_wait}s")
        else:
            print("Failed to find checkbox visually")

    def scan(
        self,
        url: str,
        output_dir: str,
        additional_wait: Optional[float] = None,
        proxy: Optional[str] = None,
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
            # ask Jeremy about this
            sb.activate_cdp_mode("about:blank")
            self._cdp_tab = sb.cdp.page  # nodriver Tab for sending CDP commands from handlers
            sb.cdp.add_handler(mycdp.network.RequestWillBeSent, self.send_handler)
            sb.cdp.add_handler(mycdp.network.ResponseReceived, self.receive_handler)
            sb.cdp.add_handler(
                mycdp.network.LoadingFinished, self.loading_finished_handler
            )
            sb.cdp.add_handler(mycdp.network.LoadingFailed, self.loading_failed_handler)

            # Auto-attach to Worker/ServiceWorker targets to inject stealth code.
            # DIAGNOSTIC: Disable waitForDebuggerOnStart to test hypothesis that
            # paused Workers are never resumed because AttachedToTarget events
            # don't reach our handler. Without the pause, Workers should run
            # immediately and complete their PoW computation.
            sb.cdp.add_handler(mycdp.target.AttachedToTarget, self.target_attached_handler)
            sb.execute_cdp_cmd('Target.setAutoAttach', {
                'autoAttach': True,
                'waitForDebuggerOnStart': False,
                'flatten': True,
            })

            # DIAGNOSTIC: Enable Runtime domain and listen for console messages
            # to capture __DIAG_* output from our instrumented stealth JS.
            sb.execute_cdp_cmd('Runtime.enable', {})
            sb.cdp.add_handler(mycdp.runtime.ConsoleAPICalled, self.diag_console_handler)

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
                        "brands": [
                            {"brand": "Chromium", "version": BYPASS_CHROME_MAJOR},
                            {"brand": "Not(A:Brand", "version": "99"},
                            {"brand": "Google Chrome", "version": BYPASS_CHROME_MAJOR},
                        ],
                        "fullVersionList": [
                            {"brand": "Chromium", "version": BYPASS_CHROME_FULL},
                            {"brand": "Not(A:Brand", "version": "99.0.0.0"},
                            {"brand": "Google Chrome", "version": BYPASS_CHROME_FULL},
                        ],
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

            self.bypass_recaptcha(sb)
            self.bypass_warnings(sb)

            # NOTE for local files we need to wait a little longer

            if additional_wait:
                # give the file time to load
                print(f"waiting for additional {additional_wait} seconds")
                time.sleep(additional_wait)

            screenshot_path = os.path.join(output_dir, "screenshot.png")

            # get the screenshot
            try:
                print(f"saving screenshot to {screenshot_path}")
                sb.save_screenshot(screenshot_path, selector="body")
                print(f"screenshot saved to {screenshot_path}")

            except Exception as e:
                print(f"failed to save screenshot: {e}")

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

            # append reponse content data to dom.html unless filtered out
            for request in self.requests:
                if "requestId" in request and "url" in request:
                    if self.check_dom_filter(request["url"]):
                        continue

                    print(f"grabbing response body for {request['url']}")

                    # see https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json
                    try:
                        response_data = sb.execute_cdp_cmd(
                            "Network.getResponseBody",
                            {"requestId": request["requestId"]},
                        )["body"]
                        appended_data = (
                            "\n\nMARKER URL: " + request["url"] + "\n\n" + response_data
                        )
                        with open(dom_path, "ab") as fp:
                            fp.write(appended_data.encode("utf-8", errors="ignore"))
                    except Exception as e:
                        print(
                            f"failed to grab response body for requestId {request.get('requestId', -1)}: {e}"
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
        default=3,
        help="The additional time to wait for the page to load.",
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
    result = scanner.scan(
        target, args.output_dir, args.additional_wait, proxy=args.proxy
    )
    print(result)
    sys.exit(0)
