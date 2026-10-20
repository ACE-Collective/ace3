#!/usr/bin/env python3
"""Take the screenshots the SVS training guides use (app/help/content/svs/images/).

Run it against a GUI served from the checkout, so the screenshots show the code being documented,
after bin/training/svs_demo_seed.py has seeded the demo data:

    ace gui start --port 5050 --api-v2 &
    bin/training/svs_guide_screenshots.py                 # every shot
    bin/training/svs_guide_screenshots.py run-live tests  # only the named ones

Each shot is a page, a persona to view it as, and optionally an element to crop to and steps to
take first (open a modal, pick a tab). A page that logs a console error or gets an HTTP error
fails its shot instead of being saved, so a broken page never ends up in a guide. The ids the
pages need come from the seed's manifest (data/svs-training/manifest.json).
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from playwright.sync_api import Page, sync_playwright

SAQ_HOME = Path(os.environ.get("SAQ_HOME", "/opt/ace"))
MANIFEST_PATH = SAQ_HOME / "data" / "svs-training" / "manifest.json"
IMAGES = SAQ_HOME / "app" / "help" / "content" / "svs" / "images"
GUI = os.environ.get("SVS_TRAINING_GUI", "https://localhost:5050/ace")
VIEWPORT = {"width": 1440, "height": 900}
# a full-page shot grows the viewport to the page's content, up to this
MAX_FULL_HEIGHT = 2600


@dataclass
class Shot:
    name: str
    # the GUI path, formatted with the manifest (e.g. "/svs/runs/{runs[sam]}")
    path: str
    persona: str = "alice"
    # crop to this element (a CSS selector); otherwise the viewport, or the whole page when full
    element: str | None = None
    full: bool = False
    # wait for this selector before anything else; most pages draw their data after loading
    ready: str | None = None
    before: Callable[[Page], None] | None = None
    # text the page must show, so a shot of the wrong state fails
    expect_text: str | None = None
    # HTTP errors the page is known to make and that the shot may ignore
    allow_status: tuple[str, ...] = field(default_factory=tuple)


def click(selector: str, wait: str | None = None):
    def step(page: Page):
        page.locator(selector).first.click()
        if wait:
            page.locator(wait).first.wait_for(state="visible")
        page.wait_for_timeout(400)
    return step


def steps(*fns):
    def step(page: Page):
        for fn in fns:
            fn(page)
    return step


def hide(selector: str):
    def step(page: Page):
        page.add_style_tag(content=f"{selector} {{ display: none !important; }}")
    return step


def only_rows_matching(pattern: str):
    """Hide the table rows whose text doesn't match: for a list with no filter of its own."""
    def step(page: Page):
        page.evaluate("(p) => { const re = new RegExp(p); document.querySelectorAll('table tbody tr')"
                      ".forEach(tr => { if (!re.test(tr.innerText)) tr.style.display = 'none'; }); }", pattern)
    return step


BATCH = "f=batch:training-2026-10"
RUN_ROWS = "table tbody tr"

SHOTS = [
    # the Documentation area itself
    Shot("help-index", "/help/"),
    # the runs list and batches
    Shot("runs-list", f"/svs/runs?{BATCH}", ready=RUN_ROWS),
    Shot("runs-needs-attention", f"/svs/runs?{BATCH}&f=needs_attention:true", ready=RUN_ROWS),
    Shot("runs-batches", f"/svs/runs/batches?{BATCH}", ready=RUN_ROWS),
    Shot("runs-actions", f"/svs/runs?{BATCH}", ready=RUN_ROWS,
         before=steps(click("table tbody tr input[type=checkbox]"), click("button:has-text('Actions')"))),
    # run pages
    Shot("run-live", "/svs/runs/{runs[service_live]}", ready="#svs_run_facts", element="#svs_run_page",
         expect_text="started"),
    Shot("run-needs-review", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_facts", full=True),
    Shot("run-review-blockers", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_review", element="#svs_run_review"),
    Shot("run-result-candidates", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_result",
         element="section:has(#svs_run_result)"),
    Shot("run-candidates", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_candidates",
         element="section:has(#svs_run_candidates)"),
    Shot("run-expected-modal", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_candidates",
         before=click("#svs_run_candidates button:has-text('Expected')", wait=".modal.show"),
         element=".modal.show .modal-dialog"),
    Shot("run-close-modal", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_facts",
         before=click("button:has-text('Close')", wait=".modal.show"), element=".modal.show .modal-dialog"),
    Shot("run-alerts", "/svs/runs/{runs[kerberoast]}", ready="#svs_run_alerts", element="section:has(#svs_run_alerts)"),
    Shot("run-reviewed", "/svs/runs/{runs[sam]}", ready="#svs_run_facts", full=True),
    Shot("run-failing-result", "/svs/runs/{runs[netuser_rerun]}", ready="#svs_run_result",
         element="section:has(#svs_run_result)"),
    Shot("run-history", "/svs/runs/{runs[sam_rerun]}", ready="#svs_run_result", element="section:has(#svs_run_result)"),
    Shot("run-logs", "/svs/runs/{runs[netuser_rerun]}", ready="#svs_run_logs", element="section:has(#svs_run_logs)"),
    Shot("run-comments", "/svs/runs/{runs[netuser_rerun]}", ready="#svs_run_comments", element="section:has(#svs_run_comments)"),
    Shot("run-events", "/svs/runs/{runs[sam]}", ready="#svs_run_events", element="section:has(#svs_run_events)"),
    Shot("run-error", "/svs/runs/{runs[bits]}", ready="#svs_run_facts", element="#svs_run_page"),
    # test alerts on the alert page
    Shot("alert-test", "/analysis?direct={alerts[sam]}", ready="#svs_alert_banner", element="#svs_alert_banner"),
    Shot("alert-context", "/analysis?direct={alerts[context]}", ready="#svs_alert_banner",
         element="#svs_alert_banner"),
    Shot("alert-partial", "/analysis?direct={alerts[partial]}", ready="#svs_alert_banner",
         element="#svs_alert_banner"),
    Shot("alert-mismatch", "/analysis?direct={alerts[mismatch]}", ready="#svs_alert_banner",
         element="#svs_alert_banner"),
    Shot("alert-page-test", "/analysis?direct={alerts[sam]}", ready="#svs_alert_banner"),
    # tests
    Shot("tests-list", "/svs/tests?f=repository:atomic_red_team&f=technique:T1136,T1003,T1558,T1543,T1197,T1218,T1053",
         ready=RUN_ROWS),
    # the page asks for the test's settings, which 404s while the test has no override (finding U-1)
    Shot("test-page", "/svs/tests/{tests[netuser]}", ready="table", full=True, allow_status=("/settings",)),
    # coverage and the worklist
    Shot("coverage-list", "/svs/coverage?f=technique:T1003,T1136,T1543,T1558,T1197,T1218,T1053,T1033,T1059",
         ready=RUN_ROWS),
    Shot("coverage-technique", "/svs/coverage/T1136.001", ready="table", full=True),
    Shot("worklist", "/svs/worklist?f=signature:{worklist_signatures}", ready=RUN_ROWS),
    Shot("worklist-resolve", "/svs/worklist?f=signature:{worklist_signatures}", ready=RUN_ROWS,
         before=click("tr:has-text('T1552.002') button:has-text('Keep')", wait=".modal.show"),
         element=".modal.show .modal-dialog"),
    Shot("worklist-signature", "/svs/worklist/{rules[netuser]}", ready="table", full=True),
    # the YARA half, in the Signatures area
    Shot("signatures-hub", "/signatures/"),
    Shot("samples-list", "/signatures/samples?f=signature:{sample_signatures}", ready=RUN_ROWS),
    Shot("sample-conflicted", "/signatures/samples/{samples_by_name[deploy_agent.ps1]}", ready="table", full=True),
    Shot("validations-list", "/signatures/validations?f=repository:detection_rules", ready=RUN_ROWS),
    Shot("validation-regression", "/signatures/validations/{validations[tune-sam-reg-exe]}", ready="table",
         full=True),
    Shot("validation-new-fp", "/signatures/validations/{validations[broaden-kerberoast-encoded]}", ready="table",
         full=True),
    Shot("validation-failed", "/signatures/validations/{validations[fix-service-binpath]}", ready="h2"),
    Shot("yara-qa", "/signatures/yara-qa", ready=RUN_ROWS),
    # administration
    # the page lists every test host; the shot keeps the lab's, leaving out a dev stack's others
    Shot("test-hosts", "/svs/test-hosts", persona="dana", ready=RUN_ROWS, before=only_rows_matching(r"-art-0\d")),
    Shot("test-host-add", "/svs/test-hosts", persona="dana", ready=RUN_ROWS,
         before=click("button:has-text('Add a test host')", wait=".modal.show"), element=".modal.show .modal-dialog"),
    Shot("alert-refused", "/analysis?direct={alerts[refused]}", persona="dana"),
]


def manifest_values() -> dict:
    m = json.loads(MANIFEST_PATH.read_text())
    m["worklist_signatures"] = ",".join(m["rules"].values())
    m["sample_signatures"] = ",".join(m["rules"].values())
    m["samples_by_name"] = {s["file"]: f"{s['sha256']}/{s['rule_uuid']}" for s in m.get("samples", []) if s.get("file")}
    return m


class Browser:
    def __init__(self, playwright, password: str):
        self.browser = playwright.chromium.launch()
        self.password = password
        self.pages: dict[str, Page] = {}
        self.problems: list[str] = []

    def page(self, persona: str) -> Page:
        if persona not in self.pages:
            ctx = self.browser.new_context(ignore_https_errors=True, viewport=VIEWPORT)
            page = ctx.new_page()
            page.on("console", lambda m: m.type == "error" and self.problems.append(
                f"console: {m.text[:300]} ({m.location.get('url', '')})"))
            page.on("pageerror", lambda e: self.problems.append(f"pageerror: {str(e)[:300]}"))
            page.on("response", lambda r: r.status >= 400 and self.problems.append(f"HTTP {r.status} {r.url}"))
            page.goto(f"{GUI}/login")
            page.fill("#username", persona)
            page.fill("#password", self.password)
            page.locator("button.btn-lg[type=submit]").click()
            page.wait_for_load_state("networkidle")
            if "/login" in page.url:
                raise RuntimeError(f"login failed for {persona}")
            self.pages[persona] = page
        return self.pages[persona]

    def take(self, shot: Shot, values: dict) -> Path:
        page = self.page(shot.persona)
        page.set_viewport_size(VIEWPORT)
        self.problems.clear()
        page.goto(GUI + shot.path.format(**values))
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass  # a page that polls (a started run) never goes idle
        if shot.ready:
            page.locator(shot.ready).first.wait_for(state="visible", timeout=20000)
        page.wait_for_timeout(700)
        if shot.before:
            shot.before(page)
        if shot.expect_text and shot.expect_text not in page.inner_text("body"):
            raise RuntimeError(f"{shot.name}: the page does not show {shot.expect_text!r}")
        problems = [p for p in self.problems if not any(a in p for a in shot.allow_status)]
        if problems:
            raise RuntimeError(f"{shot.name}: " + "; ".join(problems))
        out = IMAGES / f"{shot.name}.png"
        if shot.element:
            page.locator(shot.element).first.screenshot(path=str(out))
        elif shot.full:
            # the GUI scrolls inside #content_area, so a full-page screenshot is a taller viewport
            height = page.evaluate("() => { const c = document.getElementById('content_area');"
                                   " return c ? c.scrollHeight + c.getBoundingClientRect().top + 16"
                                   " : document.body.scrollHeight; }")
            page.set_viewport_size({"width": VIEWPORT["width"], "height": min(int(height), MAX_FULL_HEIGHT)})
            page.wait_for_timeout(300)
            page.screenshot(path=str(out))
        else:
            page.screenshot(path=str(out))
        return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="only these shots (default: all)")
    parser.add_argument("--list", action="store_true", help="list the shots and exit")
    args = parser.parse_args()
    if args.list:
        for shot in SHOTS:
            print(f"{shot.name:28} {shot.persona:6} {shot.path}")
        return
    unknown = set(args.names) - {s.name for s in SHOTS}
    if unknown:
        sys.exit(f"no such shot: {', '.join(sorted(unknown))}")
    values = manifest_values()
    IMAGES.mkdir(parents=True, exist_ok=True)
    failed = []
    with sync_playwright() as p:
        browser = Browser(p, values["password"])
        for shot in SHOTS:
            if args.names and shot.name not in args.names:
                continue
            try:
                print(f"{shot.name}: {browser.take(shot, values).relative_to(SAQ_HOME)}")
            except Exception as e:
                failed.append(shot.name)
                print(f"{shot.name}: FAILED {e}", file=sys.stderr)
    if failed:
        sys.exit(f"{len(failed)} shot(s) failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
