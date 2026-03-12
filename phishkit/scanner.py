#!/usr/bin/env python

import argparse
import base64
from io import BytesIO
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
from urllib.parse import urlparse

from seleniumbase import SB  # type: ignore
import mycdp  # type: ignore
from selenium_recaptcha_solver import RecaptchaSolver  # type: ignore
from PIL import Image # type: ignore

BYPASS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"


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
    def __init__(self):
        self.requests = []
        self.bytes_downloaded = 0
        self.domain_stats = {}  # domain -> {bytes_downloaded, request_count, response_count, first_request_time, last_finished_time}

        self.BLOCKED_EXT = ['.png', '.jpg', 'jpeg', '.gif', '.svg', '.mp4', '.mkv', '.avi', '.apk', '.woff2', '.img', '.css', '.ico']
        self.BLOCKED_URLS = [
            'googleapis.com',
            'google-analytics',
            'gstatic.com',
            'r.bing.com',
            'th.bing.com',
            'bing.com/th?',
            'bing.com/fd/',
            'assets.msn.com',
            'bing.com/rewardsapp',
            'bing.com/hp/',
            'browser.events.data.msn.com',
            'img-s-msn-com',
            'doubleclick.net',
            'gvt1.com',             # The GVT in the gvt1.com domain stands for Google Video Transcoding, and is used as a cache server for content and downloads used by Google services and applications
            'disney-plus.net',      # Idk why this was showing up, but a lot of our traffic quota was being eaten up by this domain
            'squarespace.com',      # Part of top 10 domains by traffic usage in SmartProxy statistics
            'apple-mapkit.com',     # Part of top 10 domains by traffic usage in SmartProxy statistics
            'squarespace-cdn.com',  # Part of top 10 domains by traffic usage in SmartProxy statistics
            'parastorage.com',      # Part of top 10 domains by traffic usage in SmartProxy statistics
            'website-files.com',    # Part of top 10 domains by traffic usage in SmartProxy statistics
            'wixstatic.com',        # Part of top 10 domains by traffic usage in SmartProxy statistics
            'shopify.com',          # Part of top 10 domains by traffic usage in SmartProxy statistics
            'redd.it',              # High bandwidth usage the week of 2024-04-08
            'ggcdashboard.com',     # High bandwidth usage the week of 2024-04-15
            'hd.pics',              # High bandwidth usage the week of 2024-04-08
            'ibb.co',               # High bandwidth usage the week of 2024-04-08
            'c.pub.network',        # High bandwidth usage of week 2024-08-27
            'm.media-amazon.com',   # High usage 2024-09-30
            'cdn.flashtalking.com'  # High usage 2024-09-30
        ]

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
                entry["duration_seconds"] = round(stats["last_finished_time"] - stats["first_request_time"], 2)
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
        """Returns True if the URL should NOT be collected, False otherwise."""
        for blocked_url in self.BLOCKED_URLS:
            if blocked_url in url:
                return True

        if url.startswith('data:') or url.startswith('blob:'):
            return True
        else:
            ext = url.split('.')[-1].lower() # grab just the ext from urls like data:image/png;base64,<b64data>

        if '.' + ext in self.BLOCKED_EXT:
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
                if entry.get("requestId") == event.request_id and entry.get("type") == "response":
                    entry["encoded_data_length"] = encoded_bytes
                    domain = urlparse(entry["url"]).netloc
                    if domain:
                        stats = self._get_domain_stats(domain)
                        stats["bytes_downloaded"] += encoded_bytes
                        stats["last_finished_time"] = now
                    break
        except Exception as e:
            print(f"exception parsing network.LoadingFinished event: {event}: {e}")

    async def send_handler(self, event: mycdp.network.RequestWillBeSent):
        # print(f"send handler callback received event {event}")
        try:
            request = {
                "date": datetime.now().isoformat(),
                "type": "request",
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
        KEY_TYPE = "type"
        KEY_SEARCHES = "searches"
        KEY_SELECTORS = "selectors"
        KEY_HANDLER = "handler"

        bypasses = [
            {
                KEY_TYPE: "CloudFlare Phishing",
                KEY_SEARCHES: [
                    "flagged as phishing",
                    "This website has been reported for potential phishing",
                    "Phishing is when a site attempts to steal sensitive",
                ],
                KEY_SELECTORS: [
                    "#cf-error-details > div.cf-section.cf-wrapper > div > div > form > button",
                    "button.cf-btn",
                ],
            },
            {
                KEY_TYPE: "CloudFlare Antibot",
                KEY_SEARCHES: [
                    "Please complete the security check to access the website.",
                    "Verify you are human by completing the action below",
                    "Verifying you are human",
                    "needs to review the security of your connection",
                    "challenges.cloudflare.com/turnstile",
                ],
                KEY_HANDLER: self.cloudflare_bypass,
            },
            {
                KEY_TYPE: "Fake Ivan CloudFlare",
                KEY_SEARCHES: [
                    #'needs to review the security of your connection before proceeding',
                    '"buttonLabel":"Verify",'
                ],
                KEY_SELECTORS: [
                    "#richEditor > div.GuidedModeInstructions__container > div > span"
                ],
            },
        ]

        for bypass in bypasses:
            if KEY_TYPE not in bypass or KEY_SEARCHES not in bypass:
                print(
                    f"Invalid bypass. Missing a required key (searches, type: {bypass}"
                )
                return

            bypass_type = bypass[KEY_TYPE]

            for search in bypass[KEY_SEARCHES]:
                if search in sb.cdp.get_page_source():
                    print(f"detected bypass type {bypass_type} with search {search}")
                    if bypass_type == "CloudFlare Antibot":
                        # special handling for this one. We need to bail out of this entire capture and rerun with different options
                        self.cloudflare_bypass(sb)
                        return True

                    # does this bypass have a handler?
                    elif KEY_HANDLER in bypass:
                        try:
                            bypass[KEY_HANDLER]()
                            return True
                        except Exception as e:
                            print(f'handler {bypass[KEY_HANDLER]} failed: {e}')
                            return False

                    # does this bypass use selectors?
                    elif KEY_SELECTORS in bypass:
                        selectors = bypass[KEY_SELECTORS]
                        for selector in selectors:
                            print(f"trying selector {selector}")
                            try:
                                sb.driver.uc_click(selector, 2)
                                return True
                            except Exception as e:
                                print(f"exception attempting to bypass {bypass_type} with {selector}: {e}")
                            print(
                                f"Successfully bypassed {bypass_type} with selector {selector}"
                            )
                        print(f"failed to bypass {bypass_type}")
                    else:
                        print(
                            f"Invalid bypass. Must define selectors or handler: {bypass}"
                        )
                        return False

            print(f"no bypasses found for {bypass_type}")

        return False

    def cloudflare_visual_bypass(self, sb: SB):
        import pyautogui # type: ignore
        sb.wait(5) # wait a few sec for the turnstile loading symbol to be replaced by a check box
        cf_checkbox_pngs = [base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAB4AAAAdCAYAAAC9pNwMAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAACdSURBVEhL7ZbBCQMhEEVTi5agdSjYm4JYkdqBzUz4wgYXdnPJEAOZw7uN73n8D6017eA3wtZaSilRrZXGGCzABSfca+sULqVcPuYA7rV1Cvfe55FzjpRSLHjvp7O1dh8+fncl+ITDu7YkLGEWJAwkLGEWJAwkvCeMeYIDzukTQpjOt9Nn29jDBM05v0YfB5i3MUYyxtyHv8m/hTU9Ad+2Lz6J6lqSAAAAAElFTkSuQmCC'), base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAB4AAAAfCAYAAADwbH0HAAAABHNCSVQICAgIfAhkiAAAABl0RVh0U29mdHdhcmUAZ25vbWUtc2NyZWVuc2hvdO8Dvz4AAADNSURBVEiJ7dexDYMwEIXhPygdgikM04DEJAzjSVywhgtKsKfAQEGTVERYEVUsEil+nV9xn64737Zte/CFJN9AI3xp7sfHNE10Xcc4jjjnggBZllGWJVVVkef5q/c2VkqhtQ6GAjjn0FqjlPJ6b2NjDABt2yKECAJba5FSYq31em/jdV0BgqHHWcuynMNXJsIRjnCEIxzhCP8YnKYpwNuZ8kmGYfBm7/FuLiEEfd8jpQwG7ymK4hxumoYkSTDGMM9zEHA/b+u69vrb333anrLARsXk3WtJAAAAAElFTkSuQmCC'),base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAACMAAAAiCAYAAADVhWD8AAAABHNCSVQICAgIfAhkiAAAABl0RVh0U29mdHdhcmUAZ25vbWUtc2NyZWVuc2hvdO8Dvz4AAAEISURBVFiF7dfNaYVAFEDh80I22oBag26sQmEq0YpsZECxCBGLGHXvD7hIFsGQQG5A3yPmwZytw/VDZmC8bdv2xj/p5WrA1yxGymKkXn972LYtdV3T9z3Lspx+ieM4+L5PmqZEUSSuu0lHu+s6iqI4DZDKskwEiV+mqioA4jhGKUUQBKcBxhi01jRNQ1mWIkbcM+M4AtwNAQiCAKUUAMMwiOtEzDRNn4Me0T5nnufjmCuyGCmLkbIYKYuRshgpi5F6DozrusDHxegR7XP2uYcwnucBoLWm7/u7IVrrb3N/6s/vwHmeE4bhMcwOqqoKYwzrup4GuK6L7/skSXLu7+CKnuM0XZHFSL0D8Ydjznm/9PUAAAAASUVORK5CYII=')]
        cf_checkboxes = [Image.open(BytesIO(png)) for png in cf_checkbox_pngs]
        screenshot = pyautogui.screenshot()
        rect = None
        for checkbox in cf_checkboxes:
            try:
                rect = pyautogui.locate(checkbox, screenshot, grayscale=True, confidence=.88)
            except pyautogui.ImageNotFoundException:
                print(f"no match found for {checkbox}")
            if rect:
                break

        if rect:
            print(f'Visual match at {rect}')
            #Visual match at Box(left=218, top=487, width=30, height=29)
            x = rect.left + rect.width//2
            y = rect.top+rect.height//2
            print(f'Clicking CF checkbox at ({x},{y})')
            sb.uc_gui_click_x_y(x,y)
        else:
            print('Failed to find CF checkbox visually')

    def cloudflare_bypass(self, sb, max_attempts=3):
        # This one is always changing and requires special handling: https://github.com/seleniumbase/SeleniumBase/issues/2842
        print('CloudFlare AntiBot bypass Handler')
        try:
            self.cloudflare_visual_bypass(sb)
        except Exception as e:
            import traceback
            print(f'Exception during visual/pyautogui CF bypass: {e}\n{traceback.format_exc()}')

    def scan(
        self, url: str, output_dir: str, additional_wait: Optional[float] = None, proxy: Optional[str] = None
    ) -> ScanResult:

        # output directory must already exist
        if not os.path.isdir(output_dir):
            raise Exception(f"output_dir {output_dir} does not exist")

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
            headless2=True,  # Use Chromium's new headless mode. (Has more features)
        )
        if proxy:
            sb_kwargs["proxy"] = proxy
            # redact credentials for logging
            if '@' in proxy:
                prefix, suffix = proxy.rsplit('@', 1)
                if '://' in prefix:
                    scheme = prefix.split('://', 1)[0]
                    redacted = f"{scheme}://****:****@{suffix}"
                else:
                    redacted = f"****:****@{suffix}"
            else:
                redacted = proxy
            print(f"using proxy: {redacted}")

        with SB(**sb_kwargs) as sb:

            # ask Jeremy about this
            sb.activate_cdp_mode("about:blank")
            sb.cdp.add_handler(mycdp.network.RequestWillBeSent, self.send_handler)
            sb.cdp.add_handler(mycdp.network.ResponseReceived, self.receive_handler)
            sb.cdp.add_handler(mycdp.network.LoadingFinished, self.loading_finished_handler)

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
                            {"brand": "Chromium", "version": "133"},
                            {"brand": "Not(A:Brand", "version": "99"},
                            {"brand": "Google Chrome", "version": "133"},
                        ],
                        "fullVersionList": [
                            {"brand": "Chromium", "version": "133.0.0.0"},
                            {"brand": "Not(A:Brand", "version": "99.0.0.0"},
                            {"brand": "Google Chrome", "version": "133.0.0.0"},
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
                if "requestId" in request:
                    if self.check_dom_filter(request['url']):
                        continue

                    print(f'grabbing response body for {request["url"]}')

                    # see https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json
                    try:
                        response_data = sb.execute_cdp_cmd('Network.getResponseBody', {'requestId': request['requestId']})['body']
                        appended_data = "\n\nMARKER URL: " + request["url"] + "\n\n" + response_data
                        with open(dom_path, "ab") as fp:
                            fp.write(appended_data.encode('utf-8', errors='ignore'))
                    except Exception as e:
                        print(f'failed to grab response body for requestId {request.get("requestId", -1)}: {e}')

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
                    downloads.append(os.path.relpath(target_file_path, start=output_dir))

        return ScanResult(
            url=url, screenshots=screenshot_path, downloads=downloads, dom=dom_path, requests=requests_path
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
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir, exist_ok=True)

    if args.file:
        target = Path(args.target).as_uri()
    else:
        target = args.target

    scanner = Scanner()
    result = scanner.scan(target, args.output_dir, args.additional_wait, proxy=args.proxy)
    print(result)
    sys.exit(0)
