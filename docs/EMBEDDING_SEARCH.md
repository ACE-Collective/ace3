# Embeddings and Alert Search — Reference and Critique

Status: evaluation written 2026-08-31 against the code on `jd/engine-bugfixes`.
No code changed as part of this write-up. Every claim below was checked against
the source at that commit; line numbers are cited so they can be re-verified.

This document has three parts:

- **Part I — How it works today.** The missing reference for the subsystem. There
  was no `docs/` page for it before this one.
- **Part II — Critique.** Severity-ranked, most consequential first.
- **Part III — Recommendation and roadmap.** What to do about it, in an order
  that makes each step measurable.

The short version, for anyone who reads no further:

> The plumbing is good. The retrieval is not. Roughly 95% of what ACE currently
> embeds is structured data — observable types, values, module names — rendered
> as English sentences, and a general-purpose sentence encoder is close to the
> worst available tool for retrieving that. The 5% that genuinely warrants
> embedding (analyst prose, email bodies, command lines) is either not embedded
> at all or reaches the index through an extension point that has **zero
> producers**. The fix is not a bigger vector system; it is a much smaller one,
> paired with an ordinary SQL lookup for the identifier half of the problem.

---

# Part I — How it works today

## 1. Shape of the system

```
WRITE PATH
                                                               submit_embedding_task(alert_uuid)
  engine post-analysis (correlation, no outstanding work) ─┐             │
  GUI add / delete comment                                 ├────────────►│
  ace llm service vectorize [-u UUID | --all]              ┘             ▼
                                                     redis list "embedding_tasks" (DB 6)
                                                                         │
                                                     EmbeddingWorker × cpu_count() (forked)
                                                     acquire_lock → load_alert → vectorize()
                                                                         │
                                   get_context_records() → model.encode() → upload_points()
                                                          → filtered delete of stale points
                                                                         │
                                                                         ▼
                                                                    ┌─────────┐
                                                                    │ Qdrant  │
                                                                    └─────────┘
READ PATH                                                                ▲
                                                                         │
  manage-page search box → session["search"] → search() ─ query_points ──┘
                                                    │      (limit=30, no filter)
                                                    ▼
                        payload["root_uuid"] → GUIAlert.uuid IN (...) → SQL sort/paginate
                                                    → re-sort page by score → rendered rows
```

There is no HTTP API for any of this. The feature is reachable from exactly two
places: the Flask alert-management page and one `ace llm` CLI subcommand.
Nothing in `aceapi/`, `aceapi_v2/`, `aceapi_ai/`, or `ace_api.py` touches Qdrant.

## 2. Files

| Concern | Path |
|---|---|
| Context-record extraction + Qdrant write | `saq/llm/embedding/vector.py` (189 lines) |
| Service, workers, Redis queue, retry / dead-letter | `saq/llm/embedding/service.py` (222 lines) |
| Query side | `saq/llm/embedding/search.py` (22 lines) |
| Model download / load / cache | `saq/llm/embedding/model.py` (48 lines) |
| Qdrant client factory | `saq/qdrant_client.py` (29 lines) |
| CLI (`ace llm ...`) | `saq/cli/commands/llm.py` |
| GUI — stores the query in the session | `app/analysis/views/search.py` |
| GUI — runs the query, joins to alerts, ranks | `app/analysis/views/manage.py:124-146, 213-215` |
| GUI — renders score badge + snippet | `app/templates/analysis/_manage_alert_table.html:97-108` |
| Config schema | `saq/configuration/schema.py` — `LLMConfig:98`, `QdrantConfig:151` |
| Config values | `etc/saq.default.yaml:146-157`, `:227-237` |
| Engine hook | `saq/engine/analysis_orchestrator.py:568-585` |
| Tree walk used to build records | `saq/analysis/search.py:64` `recurse_tree` |

## 3. The model

`etc/saq.default.yaml:146-148` selects it by bare name:

```yaml
llm:
  # the embedding model to use for vectorization
  embedding_model: all-MiniLM-L6-v2
```

Properties that matter downstream, read off the cached model in
`<data_dir>/llm/cache/all-MiniLM-L6-v2`:

| Property | Value |
|---|---|
| Dimensions | **384** (`hidden_size` in `config.json`) |
| Max sequence length | **256 word-pieces** (`model_max_length` in `tokenizer_config.json`) |
| Pooling | mean, then L2 `Normalize` (`modules.json`) |
| Distance | cosine (set at collection creation, `vector.py:140`) |
| Device | CPU only — `SentenceTransformer(..., device="cpu")`, `model.py:33,46` |

`sentence-transformers` is installed CPU-only in `Dockerfile:197-205` and is
deliberately *not* in `installer/requirements.txt`. The import is deferred inside
`model.py`'s functions because it drags in torch. Loaded models are cached in a
process-global dict `_loaded_models` and on disk under the data dir.

## 4. What gets embedded

`get_context_records(target)` (`vector.py:66-123`) builds a flat `list[str]`.
Each string becomes exactly one Qdrant point. There is no chunker, no token
counting, no length limit, and no explicit dedup.

Records, in order:

1. **`# ALERT SUMMARY`** block — description, tool, tool instance, alert type,
   plus `disposition` and `owner` when set. Alert targets only.
2. **One record per analyst `Comment`**, ordered by `insert_date` ascending:
   `f"user {gui_display} commented {comment}\n"`.
3. **`# ROOT ANALYSIS SUMMARY`** block — description, tool, tool instance,
   analysis mode. Always emitted.
4. **A full tree walk** via `recurse_tree(root, _callback)`. Per `Analysis` node:
   - `f"{obs.type} {obs.display_value} {analysis.summary}"` when both exist
   - per child observable, one record per **edge**:
     `f"{module} observed {type} {value} while analyzing {type} {value}"`
   - every entry of `analysis.llm_context_documents`

   Per `Observable` node: every entry of `observable.llm_context_documents`.

Two things are worth stating explicitly because they are easy to miss:

- **Analysis `details` are never embedded.** Only `analysis.summary` — the GUI
  one-liner — plus the observable edges. The substance of an analysis (email
  subject and body, command lines, deobfuscated JS traces, file content) does not
  reach the index by any path.
- **`llm_context_documents` has no producers.** `Analysis.add_llm_context_document`
  (`saq/analysis/analysis.py:361`) and `Observable.add_llm_context_document`
  (`saq/analysis/observable.py:750`) exist and are serialized
  (`analysis_serializer.py:18,47,109`, `observable_serializer.py:21,51,111`), but
  **nothing in `saq/`, `app/`, or `integrations/` calls either method.** They are
  deliberately excluded from analysis-cache snapshots (`saq/analysis/snapshot.py:522`),
  so a cache-replayed analysis would lose them if they existed.

## 5. Writing to Qdrant

`vectorize(target)` (`vector.py:125-189`):

```python
vectors = model.encode(context_records, show_progress_bar=False)
```

One `encode` call for the whole list; internal batching only
(`sentence-transformers` default `batch_size=32`). No explicit batch size, no
truncation handling.

The collection is created lazily on first write:

```python
client.create_collection(
    collection_name=get_alert_collection_name(),
    vectors_config=VectorParams(size=model.get_sentence_embedding_dimension(),
                                distance=Distance.COSINE),
)
create_root_uuid_index(client, wait=True)
```

Dimensions come from the model at runtime; nothing is hardcoded. A `KEYWORD`
payload index is built on `root_uuid` — without it every filtered delete is a
full collection scan. On a collection that already exists the index is *not*
backfilled automatically; `ace llm create-index [--wait] [--status]` does that.

Point ids are deterministic (`vector.py:27-30`):

```python
key = f"{root.storage_dir}/{context_document}"
digest = hashlib.sha256(key.encode("utf-8")).digest()
return str(uuid.UUID(bytes=digest[:16]))
```

so re-vectorizing is an idempotent upsert. The payload is exactly two fields:

```python
payload={ROOT_UUID_FIELD: target.uuid, "text": context_record}
```

Write ordering is upsert-then-delete, deliberately and with a regression test:

```python
client.upload_points(..., points=points, wait=True)

client.delete(..., points_selector=FilterSelector(filter=Filter(
    must=[FieldCondition(key=ROOT_UUID_FIELD, match=MatchValue(value=target.uuid))],
    must_not=[HasIdCondition(has_id=[point.id for point in points])],
)), wait=True)
```

A partial failure therefore leaves a mix of old and new points rather than none.
A non-`COMPLETED` delete raises `VectorizeError`. **Re-analysis does not create
duplicates** — same text, same storage dir, same id, upsert wins.

## 6. The service

`saq/llm/embedding/service.py`. An `ACEServiceInterface` implementation running
in its own container (`docker-compose.yml:531-543`, `ace service start llm_embedding`).

- Queue: Redis list `embedding_tasks` in `REDIS_DB_BG_TASKS` (DB 6,
  `saq/constants.py:662`). Dead-letter list `embedding_tasks_failed`.
- `submit_embedding_task(alert_uuid)` no-ops when the service is disabled;
  otherwise `rpush`es a JSON `EmbeddingTask{alert_uuid, attempt, deferrals}`.
- `EmbeddingManager` forks `worker_count` processes (default
  `multiprocessing.cpu_count()`); each `blpop`s with a 1s timeout.
- `execute_task` takes the ACE alert lock, `load_alert()`, `vectorize(alert)`,
  releases in `finally`.
- Retries: `MAX_TASK_ATTEMPTS = 3` for errors (requeued at the **tail**, to avoid
  a hot retry loop, then dead-lettered); `MAX_TASK_DEFERRALS = 60` for
  `AlertLockUnavailable`. Alert-not-found is consumed, not requeued.

Submitters:

| Trigger | Location |
|---|---|
| Engine, end of a `correlation` pass with no outstanding work | `saq/engine/analysis_orchestrator.py:568-585` |
| Analyst adds a comment | `app/analysis/views/edit/comment.py:59-61` |
| Analyst deletes a comment | `app/analysis/views/edit/comment.py:96-97` |
| CLI, queued | `ace llm service vectorize [-u UUID \| --all]` |
| CLI, synchronous in-process | `ace llm vectorize [--all] [storage_dir]` |

## 7. The query path

`saq/llm/embedding/search.py` in its entirety is one function:

```python
def search(search_term: str) -> list[ScoredPoint]:
    model = load_model(get_embedding_model())
    vector = model.encode(search_term).tolist()
    client = get_qdrant_client(timeout=get_config().qdrant.search_timeout)
    results = client.query_points(
        collection_name=get_alert_collection_name(),
        query=vector,
        query_filter=None,
        limit=30
    ).points
    return results
```

Top-k is hardcoded at 30. There is no filter, no score threshold, and no paging.

The GUI wraps it in `build_manage_list_context()` (`app/analysis/views/manage.py`):

1. `search_query = session.get("search")` — set by `POST /ace/search`
   (`app/analysis/views/search.py`), which stores the term and returns 204; the
   JS then navigates to `/ace/manage`.
2. Points are mapped by `payload["root_uuid"]` to alert UUIDs, keeping at most
   **5 snippets per alert** (`manage.py:141`, `# for now we'll limit these to 5 max`).
3. `query.filter(GUIAlert.uuid.in_(...))` (`:146`) — intersected with whatever
   session filters the analyst already has.
4. SQL `ORDER BY` (alert date by default) then `LIMIT`/`OFFSET` (`:156-176`).
5. `alerts = sorted(alerts, key=lambda x: max(...scores...), reverse=True)` (`:215`).

Rendering (`_manage_alert_table.html:97-108`) inserts a row under each match
showing `score * 100.0` with a `%` suffix, followed by `payload["text"]`.

Auto-refresh is suppressed while a search is active (`manage.html:49-57`) because
re-running the embedding search on every poll is expensive.

## 8. Configuration

```yaml
llm:
  embedding_model: all-MiniLM-L6-v2          # etc/saq.default.yaml:146-148

service_llm_embedding:                       # :150-157
  name: llm_embedding
  python_module: saq.llm.embedding.service
  python_class: EmbeddingService
  enabled: true
  #worker_count: 4                           # defaults to cpu_count()

qdrant:                                      # :227-237
  url: https://qdrant:6333
  use_ssl: true
  ssl_ca_path: ssl/ca-chain.cert.pem
  api_key: file:/auth/passwords/qdrant
  collection_alerts: ace3-alerts
  timeout: 30                                # background operations
  search_timeout: 10                         # analyst-facing, fails fast
```

Disabled globally for tests (`etc/saq.unittest.default.yaml:802-803`) and
re-enabled per-directory by `tests/saq/llm/embedding/conftest.py`.

## 9. Tests

65 tests: `tests/saq/llm/embedding/test_vector.py` (18),
`test_service.py` (21), `test_model.py` (12), `test_search.py` (10),
`tests/saq/test_qdrant_client.py` (4). Plus the engine-hook assertions in
`tests/saq/engine/test_orchestrator_outstanding_work.py:82,110,141,178` and one
GUI test (`tests/app/analysis/views/test_manage.py:171-188`).

**Every one of them mocks both Qdrant and the SentenceTransformer.** See §II.9
for why that matters.

---

# Part II — Critique

## 1. The corpus is structured data wearing a sentence costume

*This is the root problem. Most of what follows is downstream of it.*

The overwhelming majority of context records are machine-generated from a
template. Reconstructed from the format strings at `vector.py:105,110,112` (these
are the shapes the code emits, not samples pulled from a live collection):

```
ipv4 1.2.3.4 Crawlphish Analysis - 3 URLs
CrawlphishAnalysis observed url https://evil.example/x while analyzing ipv4 1.2.3.4
observed file_name invoice_scan.pdf
```

Embedding this with a general-purpose sentence encoder fails in three
independent ways.

**Embeddings destroy identifiers.** MiniLM tokenizes with a ~30k WordPiece
vocabulary. An IP address, a SHA-256, or a domain is shattered into subword
fragments that carry no meaning — `1.2.3.4` and `1.2.3.5` land essentially on top
of each other in the embedding space, as do two entirely unrelated domains that
happen to share a TLD and a length. An analyst searching for a specific indicator
will get back a list of *other* indicators that look typographically similar.
The "find this specific thing" intent is **structurally** unserved. No amount of
tuning, reranking, or threshold-fiddling repairs it, because the information was
discarded at tokenization.

**Template text dominates the signal.** Every record emitted by a given module
shares most of its tokens with every other record from that module — the
`"X observed Y while analyzing Z"` scaffolding is the bulk of the string.
Mean-pooled embeddings of templated text cluster by *template*, not by content.
The practical consequence is that a query's nearest neighbours skew toward
"records whose boilerplate most resembles the query" rather than "records that
are about the same thing."

**Cardinality explosion.** One record is emitted per analysis→observable *edge*.
An alert with a few hundred observables across a dozen modules therefore produces
on the order of thousands of near-duplicate 384-dimensional vectors, against a
handful — the alert summary and the analyst comments — that carry real
information. The edge records crowd the useful ones out of both the index and any
top-k result set. (The ratio is an estimate from the emission rules, not a
measurement; quantifying it on a real collection is a Phase 0 task, and it is the
number that most directly sizes the win from §III.2.)

Meanwhile the content that *would* justify a vector store is absent:

- Analysis `details` are never embedded (§I.4).
- `llm_context_documents`, the purpose-built hook for exactly this, has **zero
  producers**. The extension point for the only content that justifies the
  feature was built, serialized, tested for round-tripping, and never wired up.

So the feature is doing a great deal of work to index the part of the data that
least needs it, and none at all on the part that most does.

## 2. Ranking is applied after pagination

In `app/analysis/views/manage.py`, the order of operations is:

| Line | Operation |
|---|---|
| 146 | `query.filter(GUIAlert.uuid.in_(search_result_uuids))` |
| 163-165 | `ORDER BY` — alert date by default, or whatever the sort filter says |
| 171-176 | `LIMIT` / `OFFSET` |
| 179 | `alerts = query.all()` |
| 215 | `sorted(alerts, key=max score, reverse=True)` |

By line 215 `alerts` is already just the current page. SQL decides *which* alerts
the analyst sees, using recency; Qdrant's relevance score only reorders the ones
that survived. When a search matches more alerts than fit on a page, the best
match can be on page 2 — and the pager gives no hint of that, because
`total_alerts` is computed against the filtered set and looks perfectly normal.

The vector store should be the ranking authority: fetch ordered UUIDs, paginate
*that* list, then fetch and order the SQL rows to match (`ORDER BY FIELD(uuid, ...)`
or an equivalent CASE expression).

There is also a latent crash on the same line:

```python
sorted(alerts, key=lambda x: max([_.score for _ in search_result_mapping[x.uuid]]), ...)
```

`max([])` raises `ValueError` and a missing key raises `KeyError`. This holds
today only because the `IN` filter guarantees the invariant — but the guard on
line 214 tests `search_result_uuids` (the list), not `search_result_mapping` (the
dict actually being indexed). The invariant is implicit rather than enforced.

## 3. `limit=30` counts points, not alerts

Because one alert produces hundreds of points, a single verbose alert can consume
the entire top-30. An analyst searches for something that genuinely matches
twenty past alerts and gets back one.

There is no grouping and no per-alert cap at query time. The 5-snippets-per-alert
cap at `manage.py:141` runs *after* the fact and **discards** results rather than
fetching more, which makes the collapse worse rather than better.

Qdrant has the exact primitive for this — `query_points_groups(group_by="root_uuid",
group_size=5, limit=N)` — and it is close to a drop-in replacement. There is also
no `score_threshold`, so a query with no good matches still returns 30 arbitrary
points, which the UI then presents with confident-looking percentages (§II.8).

## 4. No filters are pushed into the vector query

`query_filter=None`, unconditionally. The analyst's date range, disposition,
owner, and alert-type filters are applied only in SQL, *after* the vector search
has already committed to its 30 points. "Alerts like this one, from the last
week" therefore finds the 30 globally-nearest records — most of them old — and
then filters those down to the two that happen to be recent.

The payload carries only `root_uuid` and `text`, so there is nothing to filter on
even if the code wanted to. Adding `insert_date`, `disposition`, `alert_type`,
and `company_id` to the payload, with matching indexes, turns these into
pre-filters, which is where they belong.

Two related notes:

- **Tenancy isolation here is incidental, not designed.** The vector query is
  unscoped by company, node, or ACL. It is safe today only because the SQL
  intersection re-applies scoping downstream. That is a correct outcome reached
  by accident, and it will stop being true the moment anything consumes
  `search()` without the SQL join — the `ace llm search` CLI already does exactly
  that.
- `POST /ace/search` (`app/analysis/views/search.py`) is `@login_required` only,
  while every other alert-list route uses `@require_permission('alert', 'read')`.

## 5. Silent truncation at 256 tokens

`all-MiniLM-L6-v2` has `model_max_length: 256`. Anything longer is silently
truncated by the tokenizer — no warning, no exception, no chunking. The call
succeeds and returns a perfectly plausible vector representing the first ~40% of
a paragraph.

This is harmless today only because every record is short. It is a landmine
sitting precisely on the intended growth path: the first time someone calls
`add_llm_context_document()` with an email body, a command line, or a JS
deobfuscation trace — the whole point of that API — most of the document is
discarded and nothing anywhere reports it.

## 6. Stale and destructive index states

**Dispositions never update.** `set_dispositions` (`saq/database/util/alert.py:110`)
reschedules the alert under `ANALYSIS_MODE_DISPOSITIONED`, but
`_submit_alert_for_embedding_if_complete` only fires for `ANALYSIS_MODE_CORRELATION`
(`analysis_orchestrator.py:570`). So the `- disposition:` line in the ALERT
SUMMARY record holds whatever the disposition was at correlation time — which is
almost always `None`.

This one deserves emphasis: *"what was this dispositioned as"* is the entire
payoff of the "find alerts like this one" intent. The feature indexes the field
and then never updates it. The right fix is not to re-embed on disposition — it
is to stop embedding mutable metadata at all and keep it in the payload, where
`set_payload` can update it with no re-encode.

**`ace llm vectorize <storage_dir>` is destructive.** It takes the `RootAnalysis`
branch, which emits no alert summary and no comment records, and then deletes
every point carrying that `root_uuid` that is not in the current set. Pointed at
an alert's storage directory it silently strips the alert summary and every
analyst comment out of the index. This is the path most likely to be reached for
manual debugging, which is the worst possible place for a silent data-loss
footgun.

**Point ids key on `storage_dir`**, a node-dependent path. The same alert
vectorized from a different node produces an entirely different id set. It
self-heals (the filtered delete removes the orphans) but rewrites the alert's
whole point set for no reason. Hashing on `root_uuid` + text instead is a
one-line change and is stable across nodes and archival moves.

**Nothing binds the collection to the model.** `embedding_model` is a bare name,
and no record is kept of which model produced the existing vectors. Changing that
config line silently mixes incompatible embeddings into one collection —
dimensions may even match, in which case there is no error at all, just quietly
meaningless results. The collection name should incorporate the model, or the
model should be recorded in the collection and checked at startup.

## 7. Service-level bugs and cost

Four outright bugs:

- `EmbeddingService.start_single_threaded()` (`service.py:213`) calls
  `worker.execute()`. `EmbeddingWorker` has `worker_loop`, `worker_execute`, and
  `execute_task` — no `execute`. `AttributeError` on any use.
- `started_event` is created (`service.py:64`) and waited on (`:80`, and via
  `EmbeddingManager.wait_for_start`) but **never `.set()`**. `wait_for_start()`
  therefore always burns its full timeout and returns `False`, telling every
  caller the service failed to start.
- `ace llm vectorize --clear` is declared (`cli/commands/llm.py:30`) and never
  read. `clear_vectors()` (`vector.py:40`) has no caller at all.
- `vector.py:41` docstring: *"Clears ALL vectors fro Qrant"*. `vector.py:134`
  still carries a commented-out `np.save("vectors.npy", ...)` debug line.

And three cost problems:

- **The engine submits the task while still holding the root lock**, so the first
  attempt is all but guaranteed to find the alert locked and defer. The keepalive
  is only stopped in `worker.py`'s `finally`, *after* `orchestrate_analysis` — and
  the submit happens inside that call. `service.py:26-29` acknowledges this
  explicitly ("the engine submits the task while it still holds the root lock, so
  finding the alert locked is expected"), which makes `MAX_TASK_DEFERRALS = 60` a
  documented workaround rather than an accident — but it is still a workaround for
  a self-inflicted ordering problem, and it burns a queue round-trip per alert.
  Submit after the lock is released, or drop the lock requirement entirely since
  the worker only reads.
- **`worker_count` defaults to `cpu_count()`, and each forked worker loads its own
  MiniLM and its own torch runtime.** On a 32-core box that is 32 torch processes
  doing CPU inference on ~200-token strings. Far fewer workers with real batching
  would be both faster and dramatically cheaper in memory.
- **`recurse_tree` (`saq/analysis/search.py:70`) is O(n²).** It uses a *list* for
  `visited` and `in` for membership, invoking `__eq__` on `Analysis`/`Observable`
  objects. `vectorize()` walks the entire tree on every re-embed — including on
  every single comment add and delete. Swapping to a set keyed on object identity
  or uuid is contained and benefits the function's other callers too.

Separately, `search()` runs `model.encode()` synchronously inside the Flask
request; on a cold worker that blocks for the full SentenceTransformer load.

## 8. The score badge is misleading

`_manage_alert_table.html:104` renders `score * 100.0` with a `%` suffix.

Cosine similarity is not a probability and not a confidence. With a normalized
MiniLM, two unrelated short strings routinely score 0.3–0.4, and a genuinely
excellent match might reach 0.65. The UI therefore displays "38%" beside noise
and "65%" beside the best answer it has — simultaneously overselling the garbage
and underselling the good result.

The effect is corrosive: analysts learn within a few searches that the number
means nothing, and generalize that to the feature. Either drop the number, bucket
it into relative labels, or normalize against the result set's own score
distribution.

## 9. The tests measure plumbing, not retrieval

The existing coverage is genuinely good at what it covers — lock acquisition and
release, requeue/defer/dead-letter caps, backward-compatible task
deserialization, the upsert-before-delete ordering (with an explicit regression
test asserting the call order), payload shape, and SSL/timeout handling.

But **every test mocks both Qdrant and the model**, so nothing in the suite
measures whether search works. There is no relevance fixture, no set of
query→expected-alert pairs, no recall@k or MRR, no integration test against a
real Qdrant, and no test that exercises `build_manage_list_context()` with a
non-empty result set (so the `root_uuid` join, the 5-snippet cap, and the score
sort at `manage.py:215` are all untested).

This is the most important gap in the whole subsystem, because it means **there
is currently no way to tell whether any change in Part III makes results better
or worse.** It is also why "just swap the model" is not a safe first move.

## 10. Smaller items

- `TODO.md:11` — *"when a search is executed, the filters should clear (or option
  to clear the filters)"*. A search intersected with a restrictive saved filter
  silently returns nothing, with no indication that the filter is the cause.
- `app/templates/analysis/search.html` is an orphaned ACE-1 keyword-search
  template (date range, "Search Analyst Comments", "Search Alert Files") whose
  expected context variables no view supplies. Nothing renders it.
- `manage.py:130-135` logs one line per search result at `INFO` on every request.

---

# Part III — Recommendation

## 1. The verdict

Not "rip it out", and not "it's fine". The accurate statement is:

> **Embeddings are the right tool for roughly 5% of what ACE currently embeds,
> and the wrong tool for the other 95%.**

The two analyst intents are different problems and want different mechanisms.
Trying to serve both from one dense-vector index is why neither is served well
today.

## 2. Two-lane search

**Lexical lane — "find this specific thing."** Observable values, tags, tools,
alert types, and dispositions already live in MySQL (`observables`,
`observable_mapping`, `tag_mapping`, plus the `alerts` columns). Exact and prefix
lookup there beats any embedding for identifiers, is essentially free, cannot go
stale, and needs no re-index. **Stop embedding the per-edge observation records
entirely** — they are the bulk of the collection and this lane does their job
strictly better.

**Semantic lane — "find alerts like this one."** Embed few, substantial,
human-meaningful documents per alert: the alert summary block, each analyst
comment, and — once producers exist — `llm_context_documents`. That is roughly
5–20 points per alert instead of thousands: a ~100× smaller collection, ~100×
cheaper encoding, and, critically, a neighbour set in which the nearest points
actually mean something.

**Fuse the two** with reciprocal rank fusion. RRF is about fifteen lines, has no
weights to tune, and is robust to the two lanes having incomparable score scales
— which they do. Then rank **before** pagination (§II.2).

Note what this is: the recommended system is materially **smaller** than the one
that exists today, not bigger.

## 3. What not to change

**Keep Qdrant.** It is not the problem. It is deployed, TLS-terminated, working,
and the code that touches it is 29 lines. Every defect in Part II is upstream of
the store. Moving to pgvector would save a container at the cost of a migration
and buy nothing; adding OpenSearch would add an operational burden far larger
than the lexical lane actually needs, which is a SQL query.

**Keep `sentence-transformers` for now.** `all-MiniLM-L6-v2` is a 2021 model and
`bge-small-en-v1.5` or `gte-small` are near drop-in upgrades — same 384
dimensions, similar CPU cost, 512-token windows instead of 256. But this is the
*least* of the problems on the list, and any swap forces a full re-index. It
should be a measured decision after Phase 0, not a first move.

**The write path's core design is sound and should be preserved.** Deterministic
point ids, idempotent upsert, upsert-before-delete ordering, Redis queueing with
dead-lettering, and the "only when analysis is complete" engine gate are all
correct choices. The critique above is about *what* is written and *how it is
queried*, not about the mechanics of writing it.

## 4. Highest-value single change

**Wire up `add_llm_context_document()` in the modules that hold real text** —
email subject and body (`saq/modules/email/`), command lines
(`saq/modules/command_line.py`), JS deobfuscation traces
(`saq/modules/file_analysis/js.py`), phishkit DOM captures. This is the content
that makes a vector index worth having, and the API for it already exists,
serializes, and is tested.

One decision has to be made alongside it: `llm_context_documents` is deliberately
excluded from analysis-cache snapshots (`saq/analysis/snapshot.py:522`,
`docs/ANALYSIS_CACHING.md`), so a cache-replayed analysis will produce no context
documents. Either they get captured in snapshots, or cached modules are excluded
from the semantic lane, or the index is knowingly incomplete for replayed
analysis. Doing nothing means the third option happens silently.

## 5. Roadmap

Ordered so that each phase is measurable and nothing depends on an unmeasured
guess.

### Phase 0 — Measure before changing anything

Build a small labeled evaluation set (queries → alerts that should match, drawn
from real analyst searches) and a `recall@k` / MRR harness that runs against a
real Qdrant rather than a mock. Without this, every phase below is guesswork, and
there is no way to detect a regression.

This is deliberately first. It is also the cheapest phase.

### Phase 1 — Fix what is plainly broken (no design change)

- The four service bugs — `worker.execute()`, `started_event`, the dead `--clear`
  flag, the docstring/debug-line litter (§II.7).
- Ranking before pagination, and an explicit guard for the `max([])` crash (§II.2).
- `@require_permission('alert', 'read')` on `POST /ace/search` (§II.4).
- Make `ace llm vectorize <storage_dir>` non-destructive (§II.6).
- Re-key point ids on `root_uuid` + text instead of `storage_dir` (§II.6).
- `recurse_tree` set membership (§II.7).

All independently shippable, all low-risk, none of them require Phase 0 — but
Phase 0 makes it possible to prove they changed nothing about relevance.

### Phase 2 — Fix retrieval mechanics within the current shape

- Group by alert at query time via `query_points_groups` (§II.3).
- Add a `score_threshold` (§II.3).
- Enrich the payload with `insert_date`, `disposition`, `alert_type`,
  `company_id`; index them; push the GUI filters into the vector query (§II.4).
- Move disposition out of the embedded text and into `set_payload` (§II.6).
- Bind the collection name to the model (§II.6).
- Fix or remove the score badge (§II.8).

### Phase 3 — Fix the corpus

- Stop emitting the per-edge observation records.
- Wire real `add_llm_context_document()` producers (§III.4), and settle the
  analysis-cache interaction.
- Add chunking so long documents are split rather than silently truncated (§II.5).
- Reduce `worker_count` and batch properly, now that there is far less to encode.

This is where relevance should move materially. Phase 0's numbers will say so.

### Phase 4 — Add the lexical lane

SQL lookup over observables/tags/alert columns, plus RRF fusion with the semantic
lane. Also address `TODO.md:11` (filters and search interacting silently) here,
since the search UX is being touched anyway.

### Phase 5 — Model upgrade (optional, measured)

Swap to `bge-small-en-v1.5` or `gte-small` and re-index, **only if** Phase 0's
harness shows it wins on the evaluation set. Gated last on purpose: it is the
most disruptive change and the least likely to be the bottleneck.
