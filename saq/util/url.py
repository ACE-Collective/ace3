from enum import Enum
import logging
import re
import urllib
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

from urlfinderlib import find_urls
from saq.constants import F_URL
from saq.util.strings import decode_base64

import requests

PROTECTED_URLS = ['egnyte.com', 'fireeye.com', 'safelinks.protection.outlook.com', 'dropbox.com', 'drive.google.com', '.sharepoint.com',
                  'proofpoint.com', 'urldefense.com']

# Compiled regex patterns for better performance
REGEX_SHAREPOINT = re.compile(r'^/:b:/g/(.+)/([^/]+)$')
REGEX_GOOGLE_DRIVE = re.compile(r'drive\.google\.com/file/d/([^/]+)/view')
REGEX_URLDEFENSE = re.compile(r'^https://urldefense\.com/v3/__(.+?)__.+$')


def strip_url_credentials(url: str) -> str:
    """The url without a user or password in it (https://token@host/... is common for git), so it
    can be shown to someone who mustn't see them. A url without a scheme, such as git@host:repo, is
    returned unchanged: its user is not a secret."""
    parsed = urlparse(url)
    if not parsed.scheme or "@" not in parsed.netloc:
        return url
    return urlunparse(parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[1]))


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
        hostname = urlparse(observable.value).hostname
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


class ProtectionType(Enum):
    """Enum representing the type of protection applied to a URL."""
    UNPROTECTED = 'unprotected'
    EGNYTE = 'egnyte'
    FIREEYE = 'fireeye'
    SAFELINKS_OUTLOOK = 'safelinks_outlook'
    DROPBOX = 'dropbox'
    GOOGLE_DRIVE = 'google_drive'
    SHAREPOINT = 'sharepoint'
    PROOFPOINT = 'proofpoint'
    URLDEFENSE = 'urldefense'
    CISCO = 'cisco'
    SOPHOS = 'sophos'
    CUDASVC = 'cudasvc'
    ONE_DRIVE = 'one_drive'


def extract_protected_url(url: str) -> tuple[ProtectionType, str]:
    """Is this URL protected by another company by wrapping it inside another URL they check first?
    
    Args:
        url: The URL to extract from protection wrapper
        
    Returns:
        A tuple of (ProtectionType, extracted_url) where extracted_url is the unwrapped URL
        
    Raises:
        ValueError: If url is None, empty, or invalid
    """
    # Input validation
    if not url:
        raise ValueError("URL cannot be None or empty")
    
    if not isinstance(url, str):
        raise ValueError(f"URL must be a string, got {type(url).__name__}")
    
    # Basic URL format validation
    if not url.strip():
        raise ValueError("URL cannot be whitespace only")
    
    try:
        parsed_url = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {e}") from e
    
    # Validate that we have at least a scheme or netloc
    if not parsed_url.scheme and not parsed_url.netloc:
        raise ValueError("URL must have at least a scheme or netloc")

    # egnyte links
    if parsed_url.netloc.lower().endswith('egnyte.com'):
        if parsed_url.path.startswith('/dl/'):
            return (ProtectionType.EGNYTE, url.replace('/dl/', '/dd/'))

    # fireeye links
    elif parsed_url.netloc.lower().endswith('fireeye.com'):
        if parsed_url.netloc.lower().startswith('protect'):
            qs = parse_qs(parsed_url.query)
            if 'u' in qs:
                return (ProtectionType.FIREEYE, qs['u'][0])

    # "safelinks" by outlook
    elif parsed_url.netloc.lower().endswith('safelinks.protection.outlook.com'):
        qs = parse_qs(parsed_url.query)
        if 'url' in qs:
            return (ProtectionType.SAFELINKS_OUTLOOK, qs['url'][0])

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
            return (ProtectionType.DROPBOX, urlunparse((parsed_url.scheme,
                                        parsed_url.netloc,
                                        parsed_url.path,
                                        parsed_url.params,
                                        urlencode(qs),
                                        parsed_url.fragment)))

    # sharepoint download links
    elif parsed_url.netloc.lower().endswith('.sharepoint.com'):
        # user gets this link in an email
        # https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD
        # needs to turn into this link
        # https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ

        # so the URL format seems to be this
        # https://SITE.shareponit.com/:b:/g/PATH/ID?e=DATA
        # not sure if NAME can contain subdirectories so we'll assume it can
        m = REGEX_SHAREPOINT.match(parsed_url.path)
        parsed_qs = parse_qs(parsed_url.query)
        if m and 'e' in parsed_qs:
            return (ProtectionType.SHAREPOINT, urlunparse((parsed_url.scheme,
                                        parsed_url.netloc,
                                        '/{}/_layouts/15/download.aspx'.format(m.group(1)),
                                        parsed_url.params,
                                        urlencode({'e': parsed_qs['e'][0], 'share': m.group(2)}),
                                        parsed_url.fragment)))

    # google drive links
    m = REGEX_GOOGLE_DRIVE.search(url)
    if m:
        # sample
        # https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view
        # turns into
        # https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download

        google_id = m.group(1)

        return (ProtectionType.GOOGLE_DRIVE, 'https://drive.google.com/uc?authuser=0&id={}&export=download'.format(google_id))

    if parsed_url.netloc.lower().endswith('urldefense.com'):
        m = REGEX_URLDEFENSE.match(url)
        if m:
            return (ProtectionType.URLDEFENSE, m.group(1))

    if parsed_url.netloc.lower().endswith('.proofpoint.com'):
        extracted_url_set = find_urls(url)
        if extracted_url_set:
            # loop through all extracted URLs to remove any nested protected URLs
            for possible_url in extracted_url_set.copy():
                if any(protected_url in possible_url for protected_url in PROTECTED_URLS):
                    extracted_url_set.remove(possible_url)

            # make sure that the set still has URLs in it
            if extracted_url_set:
                extracted_url = extracted_url_set.pop()
                return (ProtectionType.PROOFPOINT, extracted_url)
    
    if parsed_url.netloc.lower().endswith("secure-web.cisco.com"):
        # extract last segment after the final '/'
        last_segment = parsed_url.path.split("/")[-1]
        candidate = urllib.parse.unquote(last_segment)
        if candidate:
            return (ProtectionType.CISCO, candidate)

    
    if ".protection.sophos.com" in parsed_url.netloc.lower():
        u_val = extract_param(parsed_url.query, ("u",))
        if u_val:
            return (ProtectionType.SOPHOS, urllib.parse.unquote(decode_base64(u_val).decode('utf-8')))

    
    if parsed_url.netloc.lower().endswith("cudasvc.com") or parsed_url.netloc.lower().endswith("linkprotect.cudasvc.com"):
        a_or_u = extract_param(parsed_url.query, ("a", "u"))
        if a_or_u:
            return (ProtectionType.CUDASVC, unquote(a_or_u))

    # one drive links
    if parsed_url.netloc.lower().endswith('1drv.ms'):
        # need the final url from HTTP redirections

        #
        # example:
        # https://1drv.ms/b/s!AvqIO0JVRziVa0IWW7c6GG3YkdU
        # redirects to https://onedrive.live.com/redir?resid=95384755423B88FA!107&authkey=!AEIWW7c6GG3YkdU&ithint=file%2cpdf
        # transform to https://onedrive.live.com/download?authkey=!AEIWW7c6GG3YkdU&cid=95384755423B88FA&resid=95384755423B88FA!107&parId=root&o=OneUp
        #

        try:
            logging.info("fetching final url for one drive link {}".format(url))
            resp = requests.get(url, allow_redirects=True, timeout=8)
            final_url = resp.url
        except Exception as e:
            logging.info("unable to fetch final url for one drive link {}: {}".format(url, e))
            return (ProtectionType.UNPROTECTED, url)

        # parse the final url for OneDrive pattern
        parsed_final_url = urlparse(final_url)
        qs = parse_qs(parsed_final_url.query)

        # Check if we have necessary params
        authkey = qs.get('authkey', [None])[0]
        resid = qs.get('resid', [None])[0]
        if authkey and resid:
            extracted_url = 'https://onedrive.live.com/download?authkey={}&resid={}&parId=root&o=OneUp'.format(authkey, resid)
            return (ProtectionType.ONE_DRIVE, extracted_url)

        # fallback if not a proper OneDrive link
        return (ProtectionType.UNPROTECTED, url)

    # if we got to this point then nothing else matched, so return what we have so far
    return (ProtectionType.UNPROTECTED, url)