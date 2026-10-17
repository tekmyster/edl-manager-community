# Derived AI retention and performance

This implementation is available for review before deployment. It does not change
native scoring, evidence retention, publication, qualified permanent-offense IDs,
replay protection, pilot eligibility, whitelist/crawler protections or daily quotas.
Wazuh remains an input; EDL Manager owns scoring. Community AI remains disabled by
default. The separate AI Receptionist is outside this implementation.

## Retention policy

Analysis limits on Behavioral intelligence configure saved observations, expired
assessments and operational metrics independently: 90 days by default, 30–3,650
days supported. Cleanup scans 100 candidates per table per enabled worker pass
(configurable 1–500). It never opens the native database. The existing redacted
event-history cache keeps its separate 30-day policy and 5,000-row cleanup limit.

Current packets, unexpired assessments, retained assessment input/output packet
references, pending queued packets and live job leases prevent packet removal.
Reviewed accepted **and rejected** relationships, reviews, current group members,
all historical group revisions and their immutable packet citations are preserved.
Groups/revisions have no automatic expiration because they represent saved review
history. A packet's feature indexes and correlation diagnostics are removed only
with that packet; proposed links and their stored evidence expire together.

Use **Keep for investigation** on a saved observation before expiration to preserve
it and its assessments. The hold is permanent and requires a reason; no public
unpin endpoint is provided. Administrators can also use
`behavior_retention.hold(brain, kind, id, reason)` for packet, assessment or link
holds. Ordinary browser bookmarks are not visible to the server and do not pin
data. Reviewed/grouped references are automatic; unheld expired observations may
return 404. An assessment hold keeps all its indexed packet references; a link
hold keeps its endpoints and immutable relationship evidence.

Reference indexes are populated by insert/delete triggers for new immutable rows.
Legacy assessments and revisions are backfilled in restartable bounded chunks;
no retention deletion starts before both backfills finish. Malformed legacy JSON
fails closed. Date/ID sweep cursors advance past protected pages rather than
repeatedly scanning the oldest pinned rows. Deletions, dependent indexes and cursor
updates commit together; interruptions roll back and the next pass resumes.
The current UTC usage day is never pruned. Retention settings do not invalidate
the model cache. Changing a retention period cannot restore deleted information.

This is an age policy with reference exemptions, not an absolute disk-size cap.
Current addresses and retained investigations can grow without expiration. Cleanup
frees SQLite pages for reuse; it does not shrink the filesystem file. No automatic
VACUUM, forced WAL truncation, production fixtures or timer pauses are introduced.
Back up both databases consistently before deployment; retain the original source
archive and database backup for rollback. Schema additions are additive and older
code ignores them. Restoring older code alone does not restore expired data.

## Scheduling and resource bounds

Half an indexing batch prioritizes new addresses or native event times newer than
the current packet; the remaining slots keep the existing round-robin sweep.
Same-timestamp counter/context changes are eventually revisited by that sweep.
The inference queue is separate: oldest first, at most one latest pending packet
per address, up to 10,000 addresses, at most 100 entries examined and two actual
model attempts per pass. Replacing queued evidence retains its original queue age.
When full, new entries wait for a later indexing pass; native ingestion continues.
Current packet pointers refresh pending content before dispatch. Empty packets
are not queued. Queued windows without any in-window event expire without a
model request. Index-only mode may prepare a queue but never dispatches it.

Quota exhaustion stops model dispatch for that pass; it does not clear pending
work or reset the UTC budget. Cached/leased entries do not consume request slots.
Provider failures use persisted endpoint/model-specific exponential backoff from
60 seconds to 15 minutes, while existing per-packet cache/retry checks remain.
Completed inference clears that provider's backoff. The worker remains separate
and single-flight, with its existing timeout, CPU, memory and process restrictions.
No inference is added to native ingestion or atomic publication. The overview
shows pending count and oldest enqueue time; quota is a real throughput limit,
and a growing backlog must not be presented as prompt inspection.

## Measurement

Run `python benchmarks/retention_performance.py` on Linux with application
dependencies. It creates temporary databases and does not contact sensors, the
model, origin or firewall. It measures 10,000 packet/index/link inserts, 100 indexed
retrievals, bounded cleanup/reusable pages, the actual durable scheduler using an
explicit 10 ms terminal-failure stub, and real native event-to-atomic-local-list
publication across 30 offline events. Membership checks understand CIDR coverage.
The service stub creates no assessment/verdict; its queue times exclude the real
timer interval and are not small-GPU performance.

Production observations must remain separate. Retained legacy request wall times
and output tokens per wall second do not establish current-prompt sustained GPU
throughput, GPU generation speed, memory use, accuracy or reliability. Packet
preparation-to-request-start estimates have timestamp precision and reuse bias.
Native event-time-to-recorded-list-transition intervals include upstream clock,
retention and backfill ambiguity; they are not detector-arrival-to-firewall latency.
Origin sync/firewall fetch/drop latency requires separate authentic evidence.

At the initial read-only observation, the daily quota remained exhausted and no behavior-3.4
inference had occurred. Observe a natural quota reset when available; never reset
or override it or manufacture telemetry, verdicts, threshold crossings or labels.
Current-prompt sustained GPU/tokenization/memory/reliability measurement remains
an explicit dependency. Browser visual/focus/narrow-screen redesign debt remains
separate; server-rendered controls alone do not establish visual acceptance.


## Measurement diagnostics awaiting separate deployment approval

The follow-up diagnostics patch retains the backend response fields
`total_duration`, `load_duration`, `prompt_eval_duration` and `eval_duration` as
validated integer nanoseconds in assessment metadata, alongside existing actual
token counts. Missing/invalid values remain unknown. Backend evaluation timing
is not device kernel timing, and prompt evaluation is not standalone tokenizer
time. No extra inference request, gateway route, model option, quota or prompt
change is introduced. Existing assessments are not rewritten.

Cache accounting is required before interpreting prompt evaluation throughput.
`prompt_eval_count` is total prompt tokens; optional `prompt_eval_cached_count`
reports prompt tokens reused from cache. `prompt_eval_duration` covers uncached
prompt evaluation under the documented protocol. Cached counts accept only whole
integers from 0 through 10,000,000, with booleans rejected. Missing or invalid
cached/total counts leave accounting unknown. A validated cached count greater
than the total is retained as reported and flagged inconsistent; no uncached
count is derived. Consistent counts yield the arithmetic difference as
`uncached_input_tokens`; no rate is computed or asserted by capture code.

Never divide total prompt tokens by uncached evaluation duration to claim
uncached evaluation throughput. A rate may be interpreted only when the actual
backend version/provenance and its field semantics are established for the
observed cohort, cache accounting is consistent, and the matching duration is
known and positive. Its numerator is total minus cached tokens. Unknown cache
counts or backend semantics require abstention from that rate; retain raw counts
and duration only. An absent cached field does not mean no cache reuse, and the
current online API documentation alone does not prove an installed version's
semantics. Correlate a separately timestamped read-only `/api/version` observation
with genuine request context; the chat response does not provide backend version
provenance. Fully cached/zero-uncached cases must not be presented as uncached
token evaluation capacity. Prompt evaluation still is not standalone tokenizer
or GPU-kernel timing.

For native pipeline observation, the worker records first/last normalized
`Store.evidence` input receipt timestamps and monotonic times only for changed
non-Palo upserts in that cycle. Exact duplicate replays do not increment them.
Successful worker status reports bounds from those receipts to the real atomic
local EDL publication (bounded by build start/return). Deferred builds and cycles
without changed native evidence report availability explicitly without latency.
While a cycle is tracked, any native Store transaction rollback invalidates the
entire diagnostic cohort, including earlier buffered calls on a shared worker
transaction. The report becomes `unmeasurable` with reason
`transaction_rollback`; it contains no cohort count, input timestamps or published
latency. Later caught failures, successful inputs or a successful build do not
revive that cycle. Earlier committed inputs are conservatively omitted too.
Invalidation changes no native transaction, commit, rollback, scoring or
publication behavior. Only a newly initialized worker cycle starts a new cohort.

This measures Manager-normalized-input-to-local-publication for a batch cohort,
not source detector/network arrival, per-address threshold crossing, origin sync,
firewall acceptance or dropped traffic. Source event time never replaces receipt.

These aggregate diagnostics extend existing worker status only: no receipt table,
new database dependency, per-event ledger, extra query, raw traffic field, IP/path
or scoring/retention change. Source/sensor detection-to-Manager transport timing
and independent source clock bounds still require authentic upstream evidence.
The patch must pass independent QA before deployment; code alone supplies no
production timing evidence. Device observations must separate the independent
Receptionist and desktop workload from the EDL model's own allocation.

Backend field definitions follow the [Ollama chat response documentation](https://docs.ollama.com/api/chat). That format reference does not establish that the installed backend emitted any measured value; only genuine retained responses can do so.

Rejected assessments keep status `failed` and error `invalid_assessment`. Optional
`metadata.validation_diagnostic` identifies the JSON-content, response-schema,
correlation-field or evidence-validation stage with a fixed reason code. Schema
failures also report a schema-defined field path (array positions use `*`, at
most 120 characters). Diagnostics never retain model text, unexpected field
names, rejected values, citation IDs or exception messages. Validation, citation
and taxonomy requirements remain unchanged. Earlier failures without these
diagnostics cannot retrospectively identify the rejected field or validation
stage from token/timing metadata alone; they must remain unresolved failures.

Prompt `behavior-3.5` uses generation schema `taxonomy-choices-1`. Taxonomy
entries on the provider wire contain only `support_id` and a short explanation.
Each offered ID denotes one explicit technique plus its complete eligible event
bundle printed in `allowed_mappings`; the bounded bundle has at most two native
event IDs, including both sampled failures for T1110. Context-only references
and events supporting another technique cannot be substituted. The model can
return empty mapping arrays when the listed observations do not warrant a claim.
Eligibility remains unconfirmed telemetry, never a maliciousness/accuracy label.

The wire uses ordinary object/array/string enums, without union schema features.
Its choices are checked against recomputed eligibility before offering them.
After strict wire validation, a selected ID decodes to exactly its published
technique/event bundle, then unchanged canonical result/citation/taxonomy and
correlation validation runs. Unknown, malformed, duplicate or altered choices
reject the whole assessment; no partial verdict is salvaged or arbitrary cited
event relabelled. The stored canonical schema remains `behavior-3`; prompt and
generation-schema versions participate in cache identity. Older assessments are
retained, not reinterpreted as current-version output. These protocol tests and
schema compilation checks do not establish decoder enforcement or model accuracy;
actual output checks require QA-approved deployment and natural requests.
