# Alert Search

`saq/search/` serves three needs from one index:

1. an analyst types a loose term into the manage-page search box ("docusign invoice",
   "powershell download", "vendor mailer false positive");
2. an analyst types a specific thing (an ip, a hash, a url, an email address, a tag, an alert
   uuid) and expects every alert containing it, newest first;
3. an agentic triage system asks ACE, through the AI API, "has anything like this been seen,
   and how was it dispositioned".

The design is a **hybrid**: qdrant holds a dense vector (sentence embedding) and a sparse vector
(a lexical bag of terms) for every chunk of every document, and mysql serves exact matches over
the columns it already indexes. The lanes are fused into one ranking *before* pagination.

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

**Nothing is emitted for the observable graph.** The old index embedded one templated
"X observed Y while analyzing Z" record per edge, thousands per alert, and a sentence encoder
cannot tell `1.2.3.4` from `1.2.3.5`. Identifiers are served exactly by the lexical lane.

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

## 2. Read path (`query.py`, `lexical.py`)

```
query ──► lexical lane (mysql)   exact observable value / sha256 / tag / alert uuid (+prefix)
      ├─► dense lane (qdrant)    cosine over the embedding, grouped by root_uuid,
      │                          FLOORED at search.score_threshold (default 0.3)
      └─► sparse lane (qdrant)   IDF-weighted term overlap, grouped by root_uuid
                                 (skipped when the query is only stopwords)
          payload pre-filters from the request on both qdrant lanes
          weighted RRF (lexical_weight > semantic_weight), then EXACT MATCHES FIRST in the
          lexical lane's newest-first order, everything else in fused order
          cap at search.max_results → caller's SQL post_filter (node scoping, GUI filters)
          → total → page slice
```

**The floor matters.** The dense lane always has a nearest neighbour, so without an absolute
floor every query, including nonsense, returns the whole corpus. On the evaluation corpus junk
queries top out near cosine 0.23 while genuine matches score 0.37 to 0.83 or share a term, so
0.3 separates them; a query with no evidence returns zero results, which the GUI reports as such.

`search_alerts(SearchRequest, post_filter=...)` returns a `SearchResponse` of ranked alert uuids
with per-alert `SearchHit`s (lane, kind, title, text, score), the alert's best `dense_score` and
`sparse_score`, and a **tier** derived from that evidence, never from position in the result set:

| tier | evidence |
|---|---|
| `exact` | an observable value, hash, tag or uuid matched verbatim |
| `strong` | dense ≥ `strong_threshold` (0.55), or dense ≥ floor *and* a term in common |
| `good` | dense ≥ floor only |
| `weak` | a term in common, but the text is not similar |

Raw cosine values are still not shown to analysts: cosine similarity is neither a probability
nor a confidence, and the old "38%" badge taught analysts to ignore the number.

`similar_alerts(alert_uuid, ...)` recommends from the alert's own dense vectors (alert, analysis,
detection, comment and context documents), excluding the alert itself.

Pre-filters (`SearchFilters`): alert date ranges, alert types, dispositions, queues, tags (each
invertible), node locations, excluded uuids. They are applied inside qdrant *and* in the lexical
SQL, so the retrieval budget is spent on alerts the caller can see. The `post_filter` callback
runs on the fused list before pagination and is authoritative: the GUI passes its full filter
query, the API passes node scoping.

## 3. Consumers

**GUI.** `POST /ace/search` (`alert:read`) stores `{"mode": "query", "query": ...}` in the
session; `GET /ace/search/similar/<uuid>` stores `{"mode": "similar", ...}` (the "Similar alerts"
button on the alert page). `build_manage_list_context()` maps the effective filters to
`SearchFilters` (`app/analysis/views/session/search_filters.py`: Alert Date, Alert Type,
Disposition, Queue, non-wildcard Tag; the rest stay SQL-only), runs the search with the page
size/offset, loads the page's `GUIAlert` rows and orders them by rank. The table shows a tier
badge per alert and up to five hits (kind badge, title, snippet). Auto-refresh is off during a
search; Clear resets it.

**API v2** (`aceapi_v2/search/`, `alert:read`):

```
POST /api/v2/search/alerts
{"query": "docusign invoice", "filters": {"dispositions": ["DELIVERY"], "insert_date_start": "2026-06-01T00:00:00Z"}, "limit": 10}

POST /api/v2/search/similar
{"alert_uuid": "…", "limit": 5}

→ {"query": "…", "total": 7, "offset": 0, "limit": 10, "lanes_used": ["lexical", "semantic"], "timings_ms": {…},
   "results": [{"alert": {"uuid": "…", "description": "…", "alert_type": "…", "disposition": "DELIVERY",
                          "disposition_time": "…", "insert_date": "…", "owner": "…", "queue": "…", "tags": […]},
                "rank": 1, "tier": "exact", "score": 0.033, "lanes": ["lexical"],
                "hits": [{"lane": "lexical", "kind": "observable", "title": "ipv4", "text": "10.20.30.40", "score": 1.0}]}]}
```

Filters: `insert_date_start/end` (timezone-aware), `alert_types`, `dispositions`, `queues`,
`tags`, `exclude_alert_uuids`; `lanes` selects `semantic` and/or `lexical`; `include_hits`.

**AI API** (`aceapi_ai/search/`, permission `ai:search`): the same two routes at
`/ai/v1/search/alerts` and `/ai/v1/search/similar`, rate limited by `ai_api.search_limits`
(concurrency slot first, then per-minute/hourly; 429 with `Retry-After`, 503 when the limiter is
unavailable, 504 on timeout) and audited (`AI_AUDIT` lines with the full query, filters and the
returned uuids). This is the RAG surface for agentic triage: each result carries the alert's
disposition, and `GET /ai/v1/alerts/{uuid}` fetches the full tree for anything worth a closer look.

**CLI.** `ace search index [-u UUID | --all | STORAGE_DIR] [--sync] [-v]`,
`ace search query "<text>" [--lane semantic|lexical] [--limit N] [--json]`,
`ace search similar <uuid>`, `ace search status`, `ace search reset [--yes]`.

## 4. Configuration

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

## 5. Operations

- `ace search status` — collection name, existence, point count, payload indexes, queue and
  dead-letter depths. Points appear a few seconds after an alert finishes analysis.
- A dead-lettered task (`search_index_tasks_failed`) is an alert whose indexing failed three
  times; `ace search index -u <uuid> --sync` shows the error directly.
- Model change: set `search.embedding_model`, restart the indexer, `ace search index --all`, then
  delete the old collection from qdrant. Queries against the new collection return nothing until
  the re-index has run.
- Deleting an alert (`ace alert delete`, the ignored-alert cleanup) removes its points; archiving
  keeps the row and the index.

## 6. Tests

- `tests/saq/search/` — unit tests for the tokenizer, chunker, extractors, index writes, filter
  translation, fusion/tiering/pagination and the service; `test_lexical.py` runs against mysql.
- `tests/saq/search/test_retrieval.py` (`integration`, `slow`) — the retrieval regression: eight
  synthetic alerts indexed into a throw-away collection on the real qdrant with the real model,
  a labeled query set asserting recall@3 and rank-1 for exact identifiers, similar-alert
  recall, filter behaviour, idempotent re-indexing and payload updates. Skips when qdrant or the
  model is unavailable. **Run it before and after any change to documents, chunking, the sparse
  encoder, fusion or the model.**
- `tests/saq/engine/test_worker_search_submit.py` — the task is submitted only after the lock is released.
- `tests/aceapi_v2/search/`, `tests/aceapi_ai/test_search.py`, `tests/app/analysis/views/test_manage.py`.
