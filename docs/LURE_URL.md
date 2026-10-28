# Lure URL

In a phish with a large analysis tree, the URL that matters is the one the email asks its
recipient to click. Every MIME part is URL-extracted and protected URLs are unwrapped, and
QR codes, attachments and crawls each add more URLs, so that one link is hard to find. The
`lure_url_analyzer` module (`saq/modules/email/lure.py`) picks it out. The alert page shows it
in the **Lure URL** section and marks it with a `lure` badge in the Analysis Overview.

Extracted URLs are volatile, and the tree hides volatile observables unless they lead to a
detection. Every node the Lure URL and Crawl Chains sections link to is therefore made visible,
along with the path to it (`_reveal` in `app/analysis/views/index.py`), so the links always have
a node to jump to.

## How it works

The module is in the `correlation` module group, so it runs only once an email is an alert,
never on every collected email in `email` mode, where crawling each primary URL would detonate
the links of benign mail. It runs on every file that has an `EmailAnalysis`, in final analysis,
after every part has had its URLs extracted. It saves a `LureURLAnalysis` on the email that
holds the primary URL (or none), up to `max_candidates` ranked candidates, each with its score
and the reasons behind it, and the email's subject for the alert page.

The analysis is never sealed: the module scores again on every final pass, because a module
that also works in final analysis (`xlmdeobfuscator`) adds URLs after the first one. It keeps
`completed` false and returns INCOMPLETE, as `ObservableModifierAnalyzer` does. A pass that
changes nothing adds nothing, so the engine still stops, and the lure is logged only when it
changes. A URL `urlparse` rejects (`http://[x/`) is never a candidate. The values a reason is about (the link's text, the attachment it was found
in, the URLs it carries) are recorded with it as `highlights`, and the alert page shows them in
bold.

### Candidates

The module walks the email's subtree for URL observables and labels each one by where it was
found:

| Source | Where |
|---|---|
| `body` | an unnamed `text/html` or `text/plain` part (`*.unknown_text_html*`, `*.unknown_text_plain*`) |
| `qr` | anything under a `QRCodeAnalysis`, in the body or an attachment |
| `attachment` | any other part: PDF, HTML, Office, archives |

The walk does not go into:

- A `PhishkitAnalysis`. Those URLs are what the page loaded after the click, not the lure.
- An attached email, or the copies of its parts that `EmailAnalyzer` also extracts into the
  outer email. An attached email gets its own `LureURLAnalysis`.

A URL with a `ProtectedURLAnalysis` (safelinks, urldefense and so on) is replaced by the URL
it wraps. The wrapper is kept as a reason.

The lure is the link the attacker put in the email, not wherever it redirects. A click tracker
often carries its destinations in its query string, for example `?rUrl=https%3A%2F%2F...`, and
urlfinderlib extracts those as URLs of their own. A URL that another candidate carries is folded
into that candidate: it is not ranked, and the carrier gets the reason "carries N URLs: ...". A
carried URL is always shorter than its carrier, so this cannot loop. In a chain (a tracker
carrying a tracker carrying a page), only the outermost link is left. Where the lure actually
leads is what its crawl shows, in the Crawl Chains section.

URLs from a PDF's link annotations (the `document.pdf.annotation_uris` file `pdf.py` writes)
are the PDF's equivalent of `<a href>`, so they count as clickable links.

The HTML body is re-parsed to separate links (`<a href>`, `<area href>`, `<form action>`) from
images and other resources, and to read each link's text and whether it is styled as a button.
A body over 5 MB is not parsed. If parsing fails, a warning is logged and the URLs are still
scored, without their anchors.

### Scoring

| Signal | Weight (key under `weights:`) |
|---|---|
| decoded from a QR code | +35 (`qr`) |
| found in the email body | +20 (`body`) |
| found in an attachment (when not also in the body) | +15 (`attachment`) |
| clickable link in the body, or a PDF link annotation | +25 (`clickable`) |
| styled as a button (`role=button`, a `btn`/`button` class, a background, padding or border-radius style, or a `bgcolor` cell) | +15 (`button`) |
| link text contains a `call_to_action_keywords` entry | +20 (`call_to_action`) |
| the only linked domain that is not the sender's | +10 (`only_domain`) |
| unwrapped from a protected URL | +5 (`unwrapped`) |
| has detection points | +30 (`detection`) |
| in a parsed HTML body, but not as a link | -15 (`not_a_link`) |
| same registered domain as the From or Return-Path address | -20 (`sender_domain`) |
| URL or link text contains a `noise_keywords` entry | -30 (`noise`) |
| path ends in an image, font or stylesheet extension | -40 (`static`) |
| host is in `benign_domains` | -50 (`benign`) |

The highest score wins. A tie goes to the link that comes first in the body, and then to the URL
that sorts first. The order URLs were extracted in is never used, because urlfinderlib does not
keep it stable. A winner that scores
below `min_primary_score` (default 1) is not called a lure, so a newsletter whose only links are footer links has no primary
URL. Only `http` and `https` URLs are candidates.

When `crawl_primary` is on, the primary URL gets the `crawl` directive. Adding the directive
puts the URL back on the engine's work stack, so phishkit scans it (its deny patterns still
apply) and its landing page shows up in the Crawl Chains section.

### Reported emails

When a user forwards a phish as an attachment, the outer email is the report and the inner
email holds the lure. Each email has its own result. The alert page lists emails that do not
carry another email first, so the inner email's lure comes before the reporter's.

## Configuration

The module block, `analysis_module_lure_url_analyzer` in `etc/saq.default.yaml` (in the
`correlation` module group), has one setting of its own: `config_path`, the analyst-editable
settings file. Everything that tunes the scoring is in that file, so analysts can change it
without an ACE release.

The default is `etc/lure_url.yaml`, which holds ACE's built-in values and documents each key. A
deployment copies it to the analysts' repository and points the module at the copy, as it does
for phishkit and email thread analysis:

```yaml
analysis_module_lure_url_analyzer:
  config_path: signatures/analyst_data/lure_url.yaml
```

The path is relative to `SAQ_HOME`. A blank `config_path` uses the built-in values and reads no
file.

| Key | Meaning |
|---|---|
| `call_to_action_keywords` | words in link text that ask for a click (case-insensitive substring) |
| `noise_keywords` | words in a URL or link text that mark a footer link |
| `benign_domains` | domains (and subdomains) that are never the lure |
| `max_candidates` | how many ranked candidates to keep, the primary included (default 5, at least 1) |
| `crawl_primary` | add the `crawl` directive to the primary URL (default true) |
| `min_primary_score` | the lowest score that is called the lure (default 1) |
| `weights` | the weight of each signal in the scoring table: `qr`, `body`, `attachment`, `clickable`, `button`, `call_to_action`, `only_domain`, `unwrapped`, `detection`, `not_a_link`, `sender_domain`, `noise`, `static`, `benign` |

A key left out of the file, or a weight left out of `weights`, keeps its built-in value. A list
in the file replaces the built-in list; it does not add to it.

The file is watched and reloaded on change, so an edit applies on the module's next final
pass without a restart; a successful load is logged at INFO with its path. A file that does not
parse or validate, including one with an unknown or misspelled key, is rejected whole: the
settings already in effect stay, and the error is logged at ERROR with its traceback and `path`.
Those settings are kept only in the running worker's memory: a worker that starts while the
file is invalid (an engine restart, or a worker replaced after a timeout, memory limit or
refresh) runs on the built-in values until the file is fixed, so while a bad file is in place
the workers of one engine can score differently.
A `config_path` that does not exist is logged at ERROR with a traceback once, and the module runs
on the built-in values until the file appears.
