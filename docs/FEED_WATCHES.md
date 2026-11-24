# Feed watches

Analysts subscribe to RSS and Atom feeds and create *watches* over them. A watch runs one *definition*
from a git repository against each new entry of its feeds and delivers each match to one alert queue.
Several watches can read the same feed. A team could, for example, watch vendor advisories for reports
of active exploitation of the products it runs.

The pieces:

| What | Where |
|---|---|
| polling, matching, asking the LLM, delivery, replays | `service_feed_watch` (`saq/feeds/service.py`), primary node only |
| feeds and their entries | `/api/v2/feeds` (`aceapi_v2/feeds/`) |
| watches, definitions, decisions, replays, labels, evaluation | `/api/v2/feed-watches` (`aceapi_v2/feed_watches/`) |
| GUI | **Feeds** in the nav bar (`app/feeds/`, `app/static/js/feeds.js`), pages over the API |
| the alert | alert type `feed_watch`, rendered by `app/templates/analysis/custom/feed_watch.html` |
| stale feed monitor | `feeds` in `service_monitoring.monitors` (`saq/monitoring/monitors/feed_monitor.py`) |

## Permissions

| Permission | Grants |
|---|---|
| `feed:read` | list feeds, their status and their entries |
| `feed:write` | add, change and delete feeds, including their credentials |
| `feed_watch:read` | see every watch, the definitions, decisions, replays and evaluations |
| `feed_watch:write` | create and edit watches, switch delivery on or off, replay drafts, label entries |

Delivery has no permission of its own: switching a watch between shadow and delivering is an edit.

## Feeds

Anyone with `feed:write` adds a feed, with any http or https URL. A feed has no authentication, basic
auth, or a custom header (for a bearer token). The password or header value is stored encrypted with
`saq.crypto.encrypt_chunk` in `feeds.auth_secret`. The API accepts it and never returns it.

### Polling

Each feed is fetched once per `poll_interval_seconds`, however many watches read it, and never more often
than `feeds.min_poll_interval_seconds`. The request is conditional: the `ETag` and `Last-Modified` of the
last 200 go back as `If-None-Match` and `If-Modified-Since`. feedparser parses the body. Only
`saq/feeds/poller.py` imports it, so only this service loads it. HTML in the title, summary and content
is stripped to text before anything matches.

A poll that fails (no connection, an HTTP error, a body over `max_feed_bytes`, a response still arriving
after `fetch_deadline_seconds`, a document that is not a feed) is logged at WARNING and recorded on the feed as `last_failure_at` and `last_error`. The Feeds page
shows these next to `last_success_at`. The feed monitor in `service_monitoring` emits a `feeds.stale`
event, and logs a WARNING, for each enabled feed with no successful poll for `feeds.stale_after_minutes`,
so a dead feed reaches the operator.

A feed's first successful poll is a baseline, and so is the first after its URL changes: its entries can
be previewed on the Feeds page but are never evaluated. Delivery starts with the entries a feed carries after that, and a watch sees only entries first
evaluated after it exists. Use replay to see what a definition makes of older entries.

### Entries

An entry is identified by its `guid` (RSS) or `id` (Atom), else its link, else a hash of its title and
link. Each stored row is one *version*: its `content_hash` covers the title, link, summary, content and
categories, and leaves the entry's timestamps out. A vendor that edits an advisory in place makes a new
row with the same identity. The rows persist the identity across restarts.

Every poll moves `last_seen_at` forward on the versions the feed still carries. A 304 does the same for
every version the last 200 carried: those whose `last_seen_at` is not before the feed's `last_content_at`,
which is why a poll reads the database's clock once and writes that one time to both. A version not seen for `feeds.entry_retention_days` (90) is deleted in
primary-key batches of `feeds.prune_batch_size`, with its decisions, labels and replay results. Deleting
a feed stops it at once; the service then deletes its entries in batches, and then the feed.

## Definitions

Definitions live in git repositories of their own, separate from `signatures`. Each is an ordinary
`git_repo_*` section, which `service_git` keeps checked out, named in `feeds.repositories`:

```yaml
git_repo_feed_definitions:
  name: feed_definitions
  description: feed watch definitions
  local_path: data/git/feed_definitions
  git_url: https://git.example/feed-definitions.git
  update_frequency: 300
  branch: main

feeds:
  repositories: [feed_definitions]
```

A definition is a YAML file anywhere under `definitions/`:

```yaml
name: exploited-products
yara: |
  rule exploited
  {
      strings:
          $a = "actively exploited" nocase
          $b = "exploitation in the wild" nocase
      condition:
          any of them
  }
question: Does this entry report active exploitation of Widget Server or Gadget Gateway?
```

`name` is required and is persisted: watches name it. A definition needs `yara`, `question`, or both:

- a rule alone is a pattern watch and asks no LLM;
- a rule and a question run the rule first, and ask the question only of the entries it matched;
- a question alone asks the LLM about every entry. The GUI and the API warn about it when a watch is
  created with one.

Names must be unique across the repositories. When two files share one, the first read keeps it and the
error is logged and shown. The LLM system prompt is `system_prompt.md` at the root of
`feeds.prompt_repository` (the first repository by default). Its version is the hash of the file.

The service reads the repositories again whenever a commit moves and copies what it read into
`feed_definitions`, which is all the API and the GUI read. A definition whose file is gone keeps its row
with `present` false. A file that can't be used (bad YAML, no name, a rule that does not compile) is
logged at ERROR and listed with its error. A watch whose definition is missing or unusable is flagged in
the GUI and matches nothing.

A name in `feeds.repositories` that no `git_repo_*` section has is refused when the configuration loads.
While a repository has no checkout, no entry is evaluated, since an entry evaluated without its
definitions would never be evaluated again: the service logs it at ERROR when it reads the
repositories, and again every hour once it has waited an hour.

### Matching

The service compiles each rule itself with yara-python. Rules never go into the yara service's ruleset,
where they would run against every file ACE scans. Each field (`title`, `summary`, `content`,
`categories`) is scanned on its own, with the external variable `field` set to the field's name, so a
rule can require a string in the title:

```
condition: $a and field == "title"
```

The supporting excerpt is the first matched string with 120 characters either side. A rule that times
out on an entry fails that decision, at WARNING; any other failure to run a rule is a bug, logged at
ERROR with its traceback, and fails the decision too.

## Watches

A watch is created in the GUI and stored in `feed_watches`. It names one definition, its feeds and one
destination queue, and it is in shadow mode (decisions are recorded, nothing is delivered) or delivering.
Shadow mode is available but not required before delivery. Watches are disabled, not deleted, so their
decisions stay for evaluation.

`version` counts the edits of the row: every edit makes a new version. The *watch version* a decision
records is that number plus the content hash of the definition at the commit that matched, shown as
`v3:1a2b3c4d5e6f`.

## Decisions

Each new version of an entry (one that is not a baseline) gets a row in `feed_decisions` for every
enabled watch of its feed whose definition is usable, keyed by (entry version, watch, watch version,
definition hash, model, prompt hash):

- a definition without a question is decided at once by its rule;
- with a question, a version the rule turned away is decided `no_match` at once, and every other is
  `pending` until the LLM answers;
- a version of an entry that already alerted to the watch's queue gets no row: the update is ignored for
  that queue. A version that did not alert is treated as a new entry, so an edit that now says a flaw is
  exploited alerts as a first match.

`yara_matched` keeps the rule's own answer, which the evaluation scores as "YARA only".

### LLM

ACE does not run the model. It posts to the one OpenAI-compatible chat completions endpoint
`service_feed_watch.llm` names: a local server (llama.cpp, Ollama, vLLM) or a hosted router such as
OpenRouter. The evaluation starts with the instruction-tuned Gemma 4 E4B.

```yaml
service_feed_watch:
  llm:
    base_url: http://llm:8080            # ACE posts to <base_url>/v1/chat/completions
    model: google/gemma-4-E4B-it
    api_key: env:FEED_WATCH_LLM_API_KEY  # env: or file:; never logged or stored
    proxy: null                          # a named proxy_<name>, through saq/proxy.py
    connect_timeout_seconds: 10
    read_timeout_seconds: 120
    max_tokens: 512
    temperature: 0
    response_format: json_schema         # json_schema, json_object or none
    disable_thinking: true               # chat_template_kwargs.enable_thinking=false
    max_entry_chars: 8000
    max_attempts: 3
    retry_after_cap_seconds: 300
    batch_size: 20
    extra_body: {}                       # e.g. a router's provider preferences
    headers: {}                          # e.g. a router's attribution headers; none by default
```

With a hosted endpoint, every question and the text of every entry it is asked of leave the network,
and a question can reveal which products a team runs. There is no per-watch endpoint. The client is a
plain `requests` POST. It sends no identifying headers unless `headers` lists them. Without an `llm`
section no question is asked and those decisions stay pending. The rule prefilter is the cost control on
a paid endpoint: there is no separate cap on calls.

The request is one call per (entry, watch). The system message is the repository's prompt, then the
question, then the output contract, which ACE owns: the repository can rewrite the prompt but not what a
valid reply is. The user message carries the entry's title and text in a delimited block marked as
untrusted data, the text cut to `max_entry_chars` (the decision records `truncated`). The model only ever
decides whether an entry matches; the queue is the watch's.

A valid reply is the JSON object `{decision, excerpt, rationale}` with `decision` one of `match`,
`no_match` and `insufficient_evidence`. ACE asks for the schema through `response_format` and validates
the reply itself, because backends differ in whether they enforce it. A match must quote an excerpt found
verbatim in the entry's title or text after NFKC and whitespace normalization; one that is not found is
an invalid reply.

What a failure does:

| Failure | Effect |
|---|---|
| no connection, a timeout, a 5xx | logged through `log_peer_unavailable()` (or at WARNING for a 5xx); the decision stays pending, no attempt counted, the rest of the batch waits for the next pass |
| a certificate that does not verify, a missing CA bundle | logged at ERROR with its traceback; the decision stays pending, as for no connection |
| 429 | classification pauses for `Retry-After`, capped at `retry_after_cap_seconds`; the rest of the batch waits |
| 401, 403 | logged at ERROR; nothing more is asked until `service_feed_watch.llm` changes |
| an invalid reply, or another 4xx | an attempt: retried later, and after `max_attempts` the decision is `failed`, logged at ERROR and listed under *Failed decisions* on the Watches page |
| the configured model or the prompt changed while it was pending | a watch's question is asked under the configuration of the time, which the decision records; a replay's is `failed`, with the reason, since its answers are found again by (question, prompt, entry, model) |

The classifier runs on its own thread, so a slow endpoint never holds up polling. Every call is bounded
by its timeouts and every loop checks for shutdown.

## Delivery

A match a watch made while it was delivering becomes an alert of type `feed_watch` on the queue the
watch had then, as long as the watch is still enabled and delivering. An edit of the watch since does not
drop it: the entry was evaluated under that version and is never evaluated again. Alert routers can still move it. There is one alert per entry identity and
queue: every watch that matched the entry for that queue is on the same root, with its evidence. A match
waits up to `feeds.delivery_wait_seconds` for the other delivering watches of the queue to decide on the
same version, so they arrive together.

The alert shows the publisher (the feed's own title), the source link, the matched excerpt, the
rationale and each match's watch version. ACE extracts no observables from the entry, not even the link.

`feed_deliveries` makes it once. The row is written, with the decisions it delivers pointing at it,
before the root is staged, in one transaction. A later version of the entry finds it and is ignored. A
crash before the root is staged leaves the row `pending`, and the next pass stages it again with the
same root uuid, or only marks it staged when the root is already there. The root is staged into the
service's own collector (`saq/collectors/`), with a submission key derived from the feed, the entry
identity and the queue, and the collector checks the key with the `DuplicateSubmissionFilter` before it
schedules anything.

## Replay

The Replay page takes a pasted rule and question, and never saves them: committing the definition to its
repository is what makes it live. The API queues a replay; the service runs the rule over the entries of
the chosen feeds first seen in the last `feeds.replay_days` days (the newest `feeds.replay_max_entries`)
and, for each entry the rule matched (every entry without a rule), asks the question through a replay
decision keyed on (question, prompt, entry, model). Replaying the same draft again reuses the answers it
already has. The page polls the replay and shows its progress, its matches and misses with their
supporting text, and lets an analyst label each entry relevant or not relevant for a chosen watch.
A replay that fails while it runs is `failed`
with the error, and one a stopped or killed service left running is queued again when the service starts.
Replays are deleted after `feeds.replay_retention_days`.

## Dispositions

`alert_type_dispositions` keeps some dispositions to some alert types:

```yaml
alert_type_dispositions:
  feed_watch: [OPEN, IGNORE, RELEVANT, NOT_RELEVANT]
```

An alert type with a list has only the dispositions on it. A disposition named in any list is hidden from
every alert type without one, so RELEVANT and NOT_RELEVANT stay off the other alerts with no more
configuration. OPEN and IGNORE are the exception: ACE gives every alert those (the disposition an alert
starts with, and the one the cleanup deletes), so naming them in a list hides them from nobody. The alert
page offers only the alert's own dispositions; the manage page offers all of them, and the server refuses
a disposition an alert's type may not have (`DispositionNotAllowed`, from `set_dispositions` and
`set_disposition_reviews`), changing none of the selected alerts. RELEVANT classifies `tp` and
NOT_RELEVANT `fp`.

## Evaluation

The evaluation page of a watch (`/api/v2/feed-watches/{id}/evaluation`) scores each configuration of
the watch (watch version, model, prompt) against the entries analysts labeled: on the replay page, or by
dispositioning the alert a watch's decision delivered RELEVANT or NOT_RELEVANT. A replay label wins over
a disposition. For each configuration it counts true matches, false alerts (matches on entries labeled
not relevant), missed relevant posts, true misses, insufficient evidence, and what is still pending or
failed; for a definition with both a rule and a question it scores the rule alone ("YARA only") on the
same entries. Latency, token usage and the models that answered cover every question the configuration
asked.

The intended procedure: run new watches in shadow mode, label what they and their replays find (including
negations, lab demonstrations and advisories covering several products), compare the model with the
YARA-only score, and switch delivery on once missed relevant posts and false alerts are where the team
wants them.
