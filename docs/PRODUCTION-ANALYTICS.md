# Production analytics

The main dashboard shows reported tokens today, measured first-content latency
today, and dispatch attempts in the user's current local hour. `/analytics` links
those measurements to provider activity, review cohorts and saved investigations.
`/analytics/data` is read-only, management-session authenticated and `no-store`.
The existing management-source restrictions still apply. No reporting token,
provider key, prompt or response body is exposed through this endpoint.

## Definitions and gaps

- Calendar-day tiles use the saved user timezone. Graphs use 24 fixed UTC hourly
  intervals displayed in that timezone; the last interval is partial. Provider
  aggregates and all graphs share the same boundaries. DST offsets remain visible
  in focused interval descriptions and local timestamp formatting.
- A dispatch is recorded at the HTTP call boundary, after input preparation. A
  connection failure is a failed attempt. Preparation and cache reuse are separate.
  Pending records can represent running or interrupted work; they are not success.
- First content is monotonic elapsed time from HTTP dispatch to receipt of the
  first complete nonfinal (`done: false`) streamed NDJSON message with nonempty
  `message.content`. A final-only response remains unmeasured, even with a
  trailing newline or preceding empty frames. It
  includes gateway/network transit and prompt processing. Headers, thinking-only
  frames, backend prompt time and final completion duration do not substitute for
  it. Nonstreaming gateway fallback remains unmeasured. Charts preserve gaps.
- Tokens use final provider input/output counters and completion time, including
  rejected outputs. Only complete valid token pairs are summed; unknown reports
  remain explicit. Existing assessment metadata supplies historical token reports,
  with request IDs preventing overlap with the new transport ledger. Historical
  completion timestamps do not establish dispatch times or first content.
- Acceptance means the complete output passed the existing schema, evidence,
  grounding, mapping and correlation validation. It does not establish accuracy or
  usefulness. Independent quality judgments retain the separate immutable review
  cohort and its coverage. No overall helpful/unhelpful rating is currently collected.
- Cache reads, writes, outbound attempts, local MISP queries and imports are
  different counters. Cache writes include in-flight and failed entries and cannot
  establish requests avoided. Positive plus negative successful reads divided by
  all reads is the hit ratio. Distinct IPs are deduplicated across the selected
  provider window; they are not obtained by summing hourly unique counts.
- Provider current-cache coverage is a snapshot, not a lookup history. MISP
  distinct retained indicator IDs are lower bounds because IP cache payloads keep
  at most 20 IDs each; independent report lineage and distinct event totals are
  unavailable. Copied feed matches are not independent corroboration.
- Client trends count each cited observation ID once in at most the latest 500
  saved packets. Activity trends count one latest cited time per displayed alert,
  with a disclosed 100-alert limit. Missing features remain unknown. Same-IP
  recurrence, cross-IP similarity and advisory patterns remain distinct. Links
  expose original citations, differences, provenance, review history and gaps in
  the existing workbench. Shared IPs/tools cannot identify a person. Advisory
  targeting cannot establish vulnerability or exploit success.
- Scoring plots use the last publication snapshot per hour. They show actual
  contribution points and AI-dependent published eligibility at that instant,
  never repeated builds summed as new attacks or verified firewall enforcement.

## Persistence and transport

`analytics.sqlite3`, beside the configured native database, holds scalar request
records and hourly per-provider/per-IP counters for 35 days. Native evidence,
scoring, retention and independent reviews are untouched. No raw request content,
provider bodies, credentials or reviewer text enters this ledger. Coverage begins
with the first instrumented event, without backfilling unmeasured history.

Telemetry is best effort. Failures are logged, native operations continue, and
missing records can leave coverage gaps. WAL connections are reused per store and
thread; `synchronous=NORMAL` means a power failure can lose recent telemetry.
Each live request keeps its actual dispatch identity and timestamp in memory. If
saving the pending row fails, completion can insert that same real request with
its first observed completion time and scalar measurements. Duplicate completion
saves preserve the first completed outcome. This recovers transient start-save
failures; it does not reconstruct requests lost across a process exit, guarantee
persistence during ongoing failure, or backfill history. Finish without a known
dispatch saves nothing. The existing 25 ms SQLite busy timeout remains for both
cache counters and request persistence; no retry loop or inference gate is added.

Existing schemas avoid repeated DDL on worker startup; concurrent fresh schema
initialization can fail within the bounded timeout and retry at a later observed
completion. Maintenance is marked complete only after commit. Unusable SQLite
handles are discarded so later operations can reopen them. Persistence warnings
contain fixed operation names and numeric SQLite/OS error codes, without exception
text, paths, request content or credentials. These diagnostics help establish an
actual cause; a busy-lock fixture does not establish the cause of an earlier
production failure.

Reads aggregate provider rows in SQLite before building the UI model. Pruning runs
at most once per process per UTC day, independently of evidence retention.

The gateway retains pinned TLS, source authorization, bearer authentication,
fixed loopback upstream, redirect/proxy/tool restrictions and existing inference
options. It relays NDJSON lines without buffering to completion. Transport is
bounded to 1 MiB (including repeated frame envelopes), individual lines and total
generated content to 128 KiB, and the existing timeout remains. Partial, foreign,
oversized or extra-after-final streams never become accepted assessments. Existing
complete-response validation is applied only after final aggregation.

No daily/per-cycle/GPU limit is added. Unlimited mode and edition defaults remain.
Community AI stays off by default, without private broker or lab configuration.

## Delivery and validation

Deploy only after independent Supervisor QA of the exact staged commits. Back up
both databases and replaced source, keep rollback source/settings, and preserve
the current Unlimited setting. Install all app modules/assets together while
workers are stopped; restart native ingestion/worker/AI timers afterward. Deploy
the streaming gateway before enabling the new client, backing up its source and
leaving its credentials, source ACL, service identity and separate AI Receptionist
unchanged. A nonstreaming client remains supported during rollback.

Private's external GreyNoise broker needs the matching staged broker source to
report real outbound outcomes. Its event uses the original dispatch timestamp;
result-delivery failure can still leave that telemetry uncollected. Never infer a
broker request from an in-flight cache claim. Community uses the direct provider
instrumentation only. Back up the existing broker before replacement.

After deployment, independently verify the actual main route and navigation,
versioned `production-analytics.css` and `.js` responses, desktop/narrow layouts,
keyboard interval details, tables and missing/error states. Reconcile a fixed
API capture with underlying request/token/provider records at the same boundaries.
Observe naturally scheduled requests for true first-content measurements, full
final validation and retained Unlimited settings. Do not fabricate traffic, labels,
threshold crossings or usage resets to populate a graph. Inspect all administrative
access paths if access settings ever change; no access changes are required here.

The collector cache-conflict repair, broad accuracy and calibration remain deferred
and incomplete. This UI patch does not incorporate the preserved collector branch.
