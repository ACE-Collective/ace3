# Alert Search

`saq/search/` serves four needs from one index:

1. an analyst types a loose term into the manage-page search box ("docusign invoice",
   "powershell download", "vendor mailer false positive");
2. an analyst *names* a specific thing (`ipv4:1.2.3.4`, `tag:phish`, `uuid:...`) and expects
   every alert containing it, newest first;
3. something asks for every alert matching a filter, with no query at all -- "every alert
   carrying this signature uuid observable";
4. an agentic triage system asks ACE, through the AI API, "has anything like this been seen,
   and how was it dispositioned".

The design is a **hybrid**: qdrant holds a dense vector (sentence embedding) and a sparse vector
(a lexical bag of terms) for every chunk of every document, and mysql serves exact matches over
the columns it already indexes. The lanes are fused into one ranking *before* pagination.

Which lanes run at all is decided by parsing the query (section 2).

## 1. Write path

```
engine (correlation / dispositioned pass, no outstanding work)
   orchestrator sets ctx.search_index_requested
   Worker.execute() releases the lock, THEN submit_index_task(uuid)
GUI comment add / delete ..................... submit_index_task
set_dispositions / set_disposition_reviews ... submit_payload_task (submit_index_task when a comment was written)
cleanup_ignored_alerts, ace alert delete ..... submit_delete_task
ace search index [-u | --all | dir] .......... submit_index_task (or --sync in-process)
                    │
                    ▼   redis list "search_index_tasks" (db 6), dead letter "search_index_tasks_failed"
   search_indexer service: worker_count processes, each holding one copy of the model
     index   → take alert lock → load alert → extract documents → chunk → encode → upsert → delete stale points
     payload → set_payload(disposition, queue, tags) on the alert's points (no re-encode)
     delete  → delete the alert's points
                    ▼
               qdrant collection  <qdrant.collection_prefix>-<model slug>-v<SCHEMA_VERSION>
```

Retries: an error requeues the task at the tail up to `MAX_TASK_ATTEMPTS` (3); a locked alert
defers it up to `MAX_TASK_DEFERRALS` (10); both then dead-letter. `ace search status` shows
both queue depths.

### Documents (`saq/search/documents.py`, `extractors.py`)

An alert yields a handful of documents, each with a stable `(kind, key)`:

| kind | key | text |
|---|---|---|
| `alert` | `header` | description, alert type, tool, tool instance, queue, root `instructions`, root summary details |
| `comment` | `<comment_id>` | one per analyst comment (title = the analyst) |
| `detection` | `detections` | every distinct detection-point description on the tree |
| `analysis` | `<analysis uuid>` | one per text-bearing analysis, via the extractor registry |
| `context` | `<node uuid>:<n>` | anything a module attached with `add_llm_context_document()` |

Built-in extractors (register more with `@register_extractor(AnalysisClass)`, including from
integrations): `EmailAnalysis` (From/To/Cc/Reply-To/Subject/Date/Message-ID plus the plain body, or
the html body through `html2text`), `CommandLineAnalysis` (the command line and its file paths),
`QRCodeAnalysis`, olevba macro source, `XMLPlainTextAnalysis`, `RdapAnalysis` whois text, the three
encrypted-archive `email_body` analyses, and the file-backed text of `OCRAnalysis`,
`PDFTextAnalysis` and `JavaScriptDeobfuscationAnalysis` (read from the file observable up to
`search.max_document_bytes`). Analysis details are loaded per node unless `details_size` exceeds
the cap. Because extraction reads `details` at index time, analysis-cache replays (which carry
`details` but not `llm_context_documents`) are indexed like everything else.

**Nothing is emitted for the observable graph.** Identifiers are served exactly by the lexical
lane; a sentence encoder cannot tell `1.2.3.4` from `1.2.3.5`.

### Chunks, vectors, payload (`chunking.py`, `sparse.py`, `model.py`, `index.py`)

- Only titles that carry content (an email subject) are embedded with chunk 0; generic labels
  ("command line", "OCR text") are for display only, and the alert header leads with the
  description rather than repeating it. Boilerplate that every alert shares (tool instance,
  queue, the deobfuscator's comment banner) is kept out of the embedded text.
- Documents are split with the model's own tokenizer into `search.chunk_tokens` windows
  (clamped to the model's maximum, 254 for MiniLM) overlapping by `search.chunk_overlap`, at most
  `search.max_chunks_per_document` per document. The title is prepended to chunk 0 only. Chunks
  are slices of the original text, so the stored snippet is verbatim.
- `dense`: `search.embedding_model` (default `all-MiniLM-L6-v2`, 384 dims, cosine, normalized).
  `search.query_prefix` is prepended to queries for models that expect an instruction.
- `sparse`: every identifier (url, email, ip, hash, domain, path) as one term *and* split into
  parts, plus plain words minus a small stopword list; term id = blake2b-32 of the term; weight = saturated tf; **IDF is applied
  by qdrant** (`SparseVectorParams(modifier=IDF)`), so no vocabulary or corpus statistics live in ACE.
- Point id = `uuid5(alert uuid, "kind:key:chunk")`: identical on every node, so re-indexing is an
  idempotent upsert and stale points are removed by a filtered delete *after* the upsert (a
  failure leaves a superset, never nothing).
- Payload: `root_uuid, kind, key, chunk, text, title, alert_type, tool, queue, disposition,
  insert_date, location, tags, analysis_uuid, observable_uuid`. Keyword indexes on `root_uuid,
  kind, alert_type, queue, disposition, location, tags`; a datetime index on `insert_date`.
- The collection name embeds the model slug and `SCHEMA_VERSION`; changing the model (or the
  layout) lands in a new collection. Run `ace search index --all` afterwards and drop the old one.

## 2. Query syntax (`syntax.py`)

A query is a mix of **field terms** and **free text**. Free text goes to the semantic lanes and
nowhere else; a literal is only looked up when it was named by a term.

```
tag:phish                        the tag, exactly
ipv4:10.20.30.40                 an observable, by type shorthand
signature_id:6f3a…               ditto -- ANY registered observable type works as a prefix
observable:url:https://evil.com  the explicit form, for values containing colons
file:<sha256 hex>                a file observable, by content hash
uuid:1f2e3d4c-…                  an alert uuid (a prefix of at least 8 characters also works)
queue:default                    a narrowing filter
disposition:DELIVERY,IGNORE      one term, values ORed
alert_date:-7d                   a relative window (saq/util/relative_time.py)
owner:jdoe  description:invoice  the rest of the manage-page filter vocabulary
-tag:whitelisted                 inverted (! works too)
tag:"vendor mailer"              quoted, for a value containing a space or a comma
docusign invoice                 free text
```

The field names are the permanent URL slugs from `saq/gui/filter_names.py` (`FILTER_SLUGS` --
the same ones a share link uses) plus every registered observable type
(`saq.observables.type_hierarchy.get_all_valid_types`). Separate terms are ANDed and values
inside one term are ORed -- except that repeating a *field* means "either", so `queue:a queue:b`
is merged into one term rather than asking a single alert to be in two queues.

**A prefix that resolves to neither is not a term.** `https://evil.com`, `C:\windows\cmd.exe`
and `foo:bar` stay free text, verbatim.

**A bare word or indicator never runs an exact lookup.** Free text goes to the semantic lanes
only. Pasting a bare ip or hash therefore returns semantic matches (or none); the GUI and the
CLI answer that with a "did you mean `ipv4:...`?" line (`ParsedQuery.hint()`).

Two deliberate differences from `saq/gui/filter_url.py`, which encodes the same filters into a
share link:

- **Values are literal.** A link is machine-generated and percent-encodes `:`, `,` and `%`; a
  search box is typed by hand and must not demand that. Quote instead: `url:"https://x/a,b"`.
- **`uuid:` is the alert uuid.** `uuid` is also a registered observable type, so *that* has to
  be written `observable:uuid:<value>`.

Where each term goes:

| term | applied as |
|---|---|
| `observable:`/`<type>:`, `tag:`, `uuid:` (not inverted) | an exact lookup in the lexical lane -- a hit, the `exact` tier, hoisted to the front |
| `queue:`, `disposition:`, `alert_type:`, `alert_date:` | a pre-filter: a qdrant payload filter *and* a SQL condition |
| everything else, plus any **inverted** or wildcard form of the above | a SQL filter list run through `saq/gui/filter_query.py` |

Inversion and wildcards fall out of the exact lane on purpose: "alerts *without* this tag" is a
narrowing condition, and there is no hit to report for it.

A term that cannot be honored -- `alert_date:-7dd`, `ipv4:not-an-ip`, an inverted `uuid:` -- is
an **error**, returned in `SearchResponse.errors` with nothing searched. It is never dropped:
a dropped filter silently returns *more* alerts than were asked for.

## 3. Read path (`query.py`, `lexical.py`)

```
query ──► parse (syntax.py)
      │
      ├─► field terms, no free text ──► LISTING: newest-first SQL, no ranking, tier = null
      │                                 (saq/gui/filter_query.py::build_alert_query)
      │
      ├─► lexical lane (mysql)   exact observable (type, sha256) / tag / alert uuid (+prefix)
      ├─► dense lane (qdrant)    cosine over the embedding of the FREE TEXT ONLY, grouped by
      │                          root_uuid, FLOORED at search.score_threshold (default 0.3)
      └─► sparse lane (qdrant)   IDF-weighted term overlap, grouped by root_uuid
                                 (skipped when the query is only stopwords)
          payload pre-filters from the request on both qdrant lanes
          weighted RRF (lexical_weight > semantic_weight), then EXACT MATCHES FIRST in the
          lexical lane's newest-first order, everything else in fused order
          cap at search.max_results → SQL filter list → caller's post_filter (node scoping,
          GUI filters) → total → page slice
```

**The semantic lanes do not run without free text.** `encode_query("")` is a perfectly valid
vector and the dense lane always has a nearest neighbour, so running them for `tag:phish` alone
would attach unrelated alerts to an exact lookup.

**The floor matters.** The dense lane always has a nearest neighbour, so without an absolute
floor every query, including nonsense, returns the whole corpus. On the evaluation corpus junk
queries top out near cosine 0.23 while genuine matches score 0.37 to 0.83 or share a term, so
0.3 separates them; a query with no evidence returns zero results, which the GUI reports as such.

`search_alerts(SearchRequest, post_filter=...)` returns a `SearchResponse` of ranked alert uuids
with per-alert `SearchHit`s (lane, kind, title, text, score), the alert's best `dense_score` and
`sparse_score`, and a **tier** derived from that evidence, never from position in the result set:

| tier | evidence |
|---|---|
| `exact` | a field term matched an observable, tag or uuid verbatim |
| `strong` | dense ≥ `strong_threshold` (0.55), or dense ≥ floor *and* a term in common |
| `good` | dense ≥ floor only |
| `weak` | a term in common, but the text is not similar |
| `null` | a filter-only listing -- there is no evidence of a match to report |

Raw cosine values are not shown to analysts: cosine similarity is neither a probability nor a
confidence.

`similar_alerts(alert_uuid, ...)` recommends from the alert's own dense vectors (alert, analysis,
detection, comment and context documents), excluding the alert itself.

Pre-filters (`SearchFilters`): alert date ranges, alert types, dispositions, queues, tags (each
invertible), node locations, excluded uuids. They are applied inside qdrant *and* in the lexical
SQL, so the retrieval budget is spent on alerts the caller can see. `SearchFilters.filter_list`
carries the rest of the manage-page vocabulary in the canonical
`[{"name", "inverted", "values"}]` shape; it has no qdrant equivalent, so it narrows in SQL --
as the whole query on the listing path, and as a post-filter otherwise. The caller's own
`post_filter` runs last and is authoritative: the GUI passes its full filter query, the API
passes node scoping.

**Observables are matched on `(type, sha256)`** -- the `i_type_sha256` unique key -- with the
value first normalized by its own observable class (`resolve_observable_identity`).
`email_address:Bob@Example.com` therefore matches the stored `bob@example.com`.

## 4. Consumers

**GUI.** `POST /ace/search` (`alert:read`) stores `{"mode": "query", "query": ...}` in the
session; `GET /ace/search/similar/<uuid>` stores `{"mode": "similar", ...}` (the "Similar alerts"
button on the alert page). `build_manage_list_context()` maps the effective filters to
`SearchFilters` (`app/analysis/views/session/search_filters.py`: Alert Date, Alert Type,
Disposition, Queue, non-wildcard Tag; the rest stay SQL-only, already enforced by the
post-filter), runs the search with the page size/offset, loads the page's `GUIAlert` rows and orders them by rank. Under each alert row the
table shows the tier as plain colored text (bold green for `exact`, green for `strong`, black for
`good`, light grey for `weak`) followed by up to five hits, each a line with a kind-colored left
rule, a muted kind label, the title and the snippet. None of this is a badge on purpose: the alert
row directly above uses badges for tags and disposition, and a badge here read as a tag (the
styling lives under `.search-tier*` / `.search-hit*` in `app/static/css/saq.css`). A result with
no tier and no hits -- a filter-only listing -- gets no evidence row at all. Auto-refresh is
off during a search; Clear resets it. Query-language errors and the "did you mean" hint are
rendered above the result count as `search_notices`.

**API v2** (`aceapi_v2/search/`, `alert:read`):

```
POST /api/v2/search/alerts
{"query": "docusign invoice tag:phish", "filters": {"dispositions": ["DELIVERY"], "insert_date_start": "2026-06-01T00:00:00Z"}, "limit": 10}

# filters only -- a newest-first listing, every tier null. This is how you ask for every alert
# carrying a signature's uuid observable.
POST /api/v2/search/alerts
{"filters": {"observables": [{"type": "signature_id", "value": "6f3a…"}]}, "limit": 50}

POST /api/v2/search/similar
{"alert_uuid": "…", "limit": 5}

→ {"query": "…", "total": 7, "offset": 0, "limit": 10, "lanes_used": ["lexical", "semantic"], "timings_ms": {…},
   "errors": [],
   "results": [{"alert": {"uuid": "…", "description": "…", "alert_type": "…", "disposition": "DELIVERY",
                          "disposition_time": "…", "insert_date": "…", "owner": "…", "queue": "…", "tags": […]},
                "rank": 1, "tier": "exact", "score": 0.033, "lanes": ["lexical"],
                "hits": [{"lane": "lexical", "kind": "observable", "title": "ipv4", "text": "10.20.30.40", "score": 1.0}]}]}
```

`query` is optional; either it or a non-empty `filters` is required (422 otherwise). Filters:
`insert_date_start/end` (timezone-aware), `alert_types`, `dispositions`, `queues`, `tags`,
`exclude_alert_uuids`, `observables` (a list of `{type, value}` -- ANDed, so an alert must carry
all of them, values normalized on the way in and 400 if one is impossible for its type), and
`filters` (the raw `{name, inverted, values}` entries for the rest of the manage-page
vocabulary, validated against `FILTER_NAMES`). `lanes` selects `semantic` and/or `lexical`;
`include_hits`. `errors` is non-empty when the query language rejected something, and then
nothing was searched.

**AI API** (`aceapi_ai/search/`, permission `ai:search`): the same two routes at
`/ai/v1/search/alerts` and `/ai/v1/search/similar`, rate limited by `ai_api.search_limits`
(concurrency slot first, then per-minute/hourly; 429 with `Retry-After`, 503 when the limiter is
unavailable, 504 on timeout) and audited (`AI_AUDIT` lines with the full query, filters and the
returned uuids). This is the RAG surface for agentic triage: each result carries the alert's
disposition, and `GET /ai/v1/alerts/{uuid}` fetches the full tree for anything worth a closer look.

**CLI.** `ace search index [-u UUID | --all | STORAGE_DIR] [--sync] [-v]`,
`ace search query "<text or field terms>" [--lane semantic|lexical] [--limit N] [--json]`
(exits 1 and prints the reason to stderr when the query cannot be parsed),
`ace search similar <uuid>`, `ace search status`, `ace search reset [--yes]`.

## 5. Configuration

```yaml
search:
  embedding_model: all-MiniLM-L6-v2   # changing it changes the collection name -> `ace search index --all`
  query_prefix: ""                    # e.g. bge: "Represent this sentence for searching relevant passages: "
  model_cache_dir: search/models      # relative to the data dir
  chunk_tokens: 200 / chunk_overlap: 32 / max_chunks_per_document: 16 / max_document_bytes: 262144
  semantic_limit: 100 / semantic_group_size: 3 / lexical_limit: 200
  rrf_k: 60 / semantic_weight: 1.0 / lexical_weight: 2.0 / max_results: 500
  score_threshold: 0.3                # dense floor; raise it if junk queries still match, lower it if paraphrases are missed
  strong_threshold: 0.55              # dense score reported as a strong match

service_search_indexer:
  enabled: true
  worker_count: 2                     # each worker holds a copy of the model

qdrant:
  url / use_ssl / ssl_ca_path / api_key
  collection_prefix: ace3-alerts
  timeout: 30 / search_timeout: 10

ai_api:
  search_limits: { max_concurrency, requests_per_minute, hourly_budget, max_query_timeout }
```

The unittest overlay disables the service and uses the `ace3-alerts-unittest` prefix.

## 6. Operations

The indexer logs one INFO line per event, with the fields in `extra={}` (see `saq/logging.py`)
so they are searchable in Splunk rather than buried in message text. Each worker process gets
its own `transactionId`, so a single worker's lines can be followed end to end.

| event | level | when | fields worth reading |
|---|---|---|---|
| `search_indexer_starting` | INFO | service start, before forking | `worker_count`, `model`, `collection` |
| `search_indexer_loading_model` / `search_indexer_worker_ready` | INFO | once per worker | `model`, `collection`, `model_load_ms`, `elapsed_ms` |
| `search_index_task_complete` | INFO | once per task | `op`, `alert_uuid`, `documents`, `points`, `updated`, `skipped`, `elapsed_ms`, `queue_depth` |
| `search_index_task_deferred` | INFO | the alert was locked | `deferrals`, `max_deferrals` |
| `search_index_task_requeued` | WARNING | the task errored and will retry | `attempt`, `max_attempts` |
| `search_index_task_error` | ERROR | what actually went wrong | `error`, `attempt` |
| `search_index_task_dead_lettered` | ERROR | giving up on the task | `reason` (`error` or `locked`), `queue` |
| `search_index_task_invalid` | ERROR | an unparseable queue entry | `payload` |
| `search_indexer_worker_error` | ERROR | the worker loop itself failed | `ready` — `false` means it never started (qdrant down, model download blocked) |
| `search_indexer_worker_exiting` | INFO | shutdown | `tasks_completed`, `tasks_failed`, `tasks_deferred` |

A rising `queue_depth` on `search_index_task_complete` is the backlog signal; `elapsed_ms` on
the same line is the per-alert cost. `search_index_task_start` is DEBUG only — raise the level
to attribute a hung worker to a specific alert.

- `ace search status` — collection name, existence, point count, payload indexes, queue and
  dead-letter depths. Points appear a few seconds after an alert finishes analysis.
- A dead-lettered task (`search_index_tasks_failed`) is an alert whose indexing failed three
  times; `ace search index -u <uuid> --sync` shows the error directly.
- Model change: set `search.embedding_model`, restart the indexer, `ace search index --all`, then
  delete the old collection from qdrant. Queries against the new collection return nothing until
  the re-index has run.
- Deleting an alert (`ace alert delete`, the ignored-alert cleanup) removes its points; archiving
  keeps the row and the index.

## 7. Tests

- `tests/saq/search/` — unit tests for the query language (`test_syntax.py`), the tokenizer,
  chunker, extractors, index writes, filter translation, fusion/tiering/pagination and the
  service; `test_lexical.py` and `test_listing.py` run against mysql. `test_lexical.py` asserts
  that a phrase containing a word that is also a tag matches nothing in the exact lane.
- `tests/saq/search/test_retrieval.py` (`integration`, `slow`) — the retrieval regression: eight
  synthetic alerts indexed into a throw-away collection on the real qdrant with the real model,
  a labeled query set asserting recall@3 and rank-1 for exact identifiers, similar-alert
  recall, filter behaviour, idempotent re-indexing and payload updates. Skips when qdrant or the
  model is unavailable. **Run it before and after any change to documents, chunking, the sparse
  encoder, fusion or the model.**
- `tests/saq/engine/test_worker_search_submit.py` — the task is submitted only after the lock is released.
- `tests/saq/gui/test_filter_query.py` — the filter query builder outside Flask, including the
  `(type, sha256)` observable match and the inverted `EXISTS` paths.
- `tests/aceapi_v2/search/`, `tests/aceapi_ai/test_search.py`, `tests/app/analysis/views/test_manage.py`.
