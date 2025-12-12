import logging
import re
import urllib
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

from urlfinderlib import find_urls
from saq.constants import F_URL
from saq.util.strings import decode_base64

PROTECTED_URLS = ['egnyte.com', 'fireeye.com', 'safelinks.protection.outlook.com', 'dropbox.com', 'drive.google.com', '.sharepoint.com',
                  'proofpoint.com', 'urldefense.com']


def fang(url):
    """Re-fangs a url that has been de-fanged.
    If url does not match the defang format, it returns the original string."""
    _formats = ['hxxp', 'hXXp']
    for item in _formats:
        if url.startswith(item):
            return f"http{url[4:]}"
    return url

def find_all_url_domains(analysis):
    from saq.analysis import Analysis
    assert isinstance(analysis, Analysis)
    domains = {}
    for observable in analysis.find_observables(lambda o: o.type == F_URL):
        hostname = urllib.parse.urlparse(observable.value).hostname
        if hostname is None:
            continue

        if hostname not in domains:
            domains[hostname] = 1
        else:
            domains[hostname] += 1

    return domains


def extract_param(query: str, keys: tuple) -> str | None:
    qs = parse_qs(query, keep_blank_values=True)
    for key in keys:
        if key in qs and qs[key]:
            return qs[key][0]

    return None

def sanitize_protected_url(url: str) -> str:
    """Is this URL protected by another company by wrapping it inside another URL they check first?"""
    extracted_url = url
    for _ in range(128):
        parsed_url = urlparse(extracted_url)

        # egnyte links
        if parsed_url.netloc.lower().endswith('egnyte.com'):
            if parsed_url.path.startswith('/dl/'):
                extracted_url = extracted_url.replace('/dl/', '/dd/')
                continue

        # fireeye links
        elif parsed_url.netloc.lower().endswith('fireeye.com'):
            if parsed_url.netloc.lower().startswith('protect'):
                qs = parse_qs(parsed_url.query)
                if 'u' in qs:
                    extracted_url = qs['u'][0]
                    continue

        # "safelinks" by outlook
        elif parsed_url.netloc.lower().endswith('safelinks.protection.outlook.com'):
            qs = parse_qs(parsed_url.query)
            if 'url' in qs:
                extracted_url = qs['url'][0]
                continue

        # dropbox links
        elif parsed_url.netloc.lower().endswith('.dropbox.com'):
            qs = parse_qs(parsed_url.query)
            modified = False
            if 'dl' in qs:
                if qs['dl'] == ['0']:
                    qs['dl'] = '1'
                    modified = True
            else:
                qs['dl'] = '1'
                modified = True

            if modified:
                # rebuild the query
                extracted_url = urlunparse((parsed_url.scheme,
                                            parsed_url.netloc,
                                            parsed_url.path,
                                            parsed_url.params,
                                            urlencode(qs),
                                            parsed_url.fragment))
                continue

        # sharepoint download links
        elif parsed_url.netloc.lower().endswith('.sharepoint.com'):
            # user gets this link in an email
            # https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD
            # needs to turn into this link
            # https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ

            # so the URL format seems to be this
            # https://SITE.shareponit.com/:b:/g/PATH/ID?e=DATA
            # not sure if NAME can contain subdirectories so we'll assume it can
            regex_sharepoint = re.compile(r'^/:b:/g/(.+)/([^/]+)$')
            m = regex_sharepoint.match(parsed_url.path)
            parsed_qs = parse_qs(parsed_url.query)
            if m and 'e' in parsed_qs:
                extracted_url = urlunparse((parsed_url.scheme,
                                            parsed_url.netloc,
                                            '/{}/_layouts/15/download.aspx'.format(m.group(1)),
                                            parsed_url.params,
                                            urlencode({'e': parsed_qs['e'][0], 'share': m.group(2)}),
                                            parsed_url.fragment))
                continue

        # google drive links
        regex_google_drive = re.compile(r'drive\.google\.com/file/d/([^/]+)/view')
        m = regex_google_drive.search(extracted_url)
        if m:
            # sample
            # https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view
            # turns into
            # https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download

            google_id = m.group(1)

            extracted_url = 'https://drive.google.com/uc?authuser=0&id={}&export=download'.format(google_id)
            continue

        if parsed_url.netloc.lower().endswith('urldefense.com'):
            regex_ud = re.compile(r'^https://urldefense\.com/v3/__(.+?)__.+$')
            m = regex_ud.match(extracted_url)
            if m:
                extracted_url = m.group(1)
                continue

        if parsed_url.netloc.lower().endswith('.proofpoint.com'):
            extracted_url_set = find_urls(extracted_url)
            if extracted_url_set:
                # loop through all extrected URLs to remove any nested protected URLs
                for possible_url in extracted_url_set.copy():
                    if any(url in possible_url for url in PROTECTED_URLS):
                        extracted_url_set.remove(possible_url)

                # make sure that the set still has URLs in it
                if extracted_url_set:
                    extracted_url = extracted_url_set.pop()
                    continue
        
        if parsed_url.netloc.lower().endswith("secure-web.cisco.com"):
            # extract last segment after the final '/'
            last_segment = parsed_url.path.split("/")[-1]
            candidate = urllib.parse.unquote(last_segment)
            if candidate:
                extracted_url = candidate
                continue

        
        if ".protection.sophos.com" in parsed_url.netloc.lower():
            u_val = extract_param(parsed_url.query, ("u",))
            if u_val:
                extracted_url = urllib.parse.unquote(decode_base64(u_val).decode('utf-8'))
                continue

        
        if parsed_url.netloc.lower().endswith("cudasvc.com") or parsed_url.netloc.lower().endswith("linkprotect.cudasvc.com"):
            a_or_u = extract_param(parsed_url.query, ("a", "u"))
            if a_or_u:
                return unquote(a_or_u)


        # if we got to this point then nothing else matched, so return what we have so far
        return extracted_url