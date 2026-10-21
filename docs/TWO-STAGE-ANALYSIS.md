> Historical prompt 3.29 topology only. New assessments use the [one-request joint contract](JOINT-ANALYSIS.md). Existing durable outcomes remain recoverable; interrupted old generation is fenced and never resumed.

# Two-stage behavioral analysis

Prompt 3.29 uses one assessment with two serialized model requests. The first
request selects typed source accounts. The second selects a verdict, findings,
mappings and relationship hypotheses against the validated, frozen accounts.
Both requests carry the complete bounded packet, offered statements, context
and selected historical window. Legal abstention and poor but legal selections
remain visible. Neither a valid schema nor copied source detail proves accuracy.

The first stage cannot publish an assessment, award points or create a repeat
milestone. Only the complete final composition passes the existing grounding
and scoring validators. The native scoring, whitelist, crawler, source-role,
retention and separate-service boundaries remain in effect.

## Required input verification

Inspection fails closed before reserving quota when verified tokenizer metadata
is absent or mismatched. The advanced settings require an absolute metadata file
and its SHA256. Provision this file through the normal controlled deployment
process; no automatic downloads or model-metadata requests occur at runtime.
Do not put API keys, private packet examples or machine inventory in this file.

`behavior_tokens.export(show, model_name, model_digest, runtime_digest)` converts
an independently verified verbose model metadata response to the supported
format. Save the returned JSON as a file owned by the application account,
without group or other write permission, and record the exact file SHA256.
The supplied model name, model digest, runtime digest and template must match the
serving deployment. This configuration does not remotely attest the server.
Reverify it when the server, template, model or tokenizer changes.

The current implementation supports the pinned Qwen2 ASCII byte-BPE and ChatML
template family only. JSON escapes source Unicode losslessly. Unsupported raw
non-ASCII framing, templates and options are refused. Each complete prompt plus
the full 1,800-token output allowance and one spare token must fit 8,192 tokens;
the user message must fit 18,000 bytes. All legal account selections and group
key orders are checked before the first request. No input truncation, history
withholding, output repair, fallback or model retry is used to obtain a fit.
Backend-reported prompt counts, when present, must match the verified count.
Missing backend token reports remain unknown in usage metrics.

## Quota and deadline

Each assessment reserves two request units atomically. A budget of one cannot
start a new assessment. Each irreducible stage claim charges one unit before
transport; an unknown dispatch outcome keeps that charge. Only never-claimed
reservations are released. The dispatch day's UTC quota is checked again for
each claim, including midnight rollover and a reduced limit. Unlimited retains
historical usage and removes only the configured request ceilings.

Quota is checked again at entry. If the UTC day changes between a claim and
entry, the consumed claim remains on its original day and no request is sent.
A limit reduced below already consumed claims cannot refund them; it prevents
another dispatch. Local configuration, ownership and quota refusals do not
create a provider outage backoff.

One configured deadline (default 120 seconds, maximum 180) covers preparation,
both requests, admission, streaming and validation. Stage two receives the time
remaining. Preparation/file checks and full decoding run under the same bounded
controller; late returns cannot claim another stage or publish a result. The 180-second setting preserves the existing 15-second gateway
admission header. There is no POST retry. Cancellation closes local connections
and rejects late output; it cannot prove that a remote backend immediately
stopped computation. An injected transport that ignores cancellation may finish
its daemon thread later, but cannot acquire another stage or publish its result.

## Durable state and compatibility

Version-one additive SQLite tables record plans, two unique stage claims,
request hashes, dispatch-entry state, source receipts and held reservations.
Short FULL-synchronous writer transactions contain no network calls. The
existing assessment and telemetry stores remain separate. A singleton active
plan prevents concurrent local assessments; the gateway's own permit remains
independent.

The receipt binds the complete input, configuration, registry, client sources,
model metadata and topology. Ownership, current packet, stored packet content,
configuration, source generation, registry and metadata are checked before
dispatch and final acceptance. Stage two cannot alter the frozen accounts.

The final checks run again after each boundary hook and immediately before the
short writer transaction. Packet content and the expected frozen-receipt digest
are also compared inside claim, entry and final acceptance transactions. File
reads and configuration checks remain outside the writer transaction.

After a process dies, an unfinished plan becomes uncertain and blocks another
attempt for that packet, including a new configuration alias. It is never
resumed from stage one. Only an already validated final outcome can be persisted
idempotently after restart, without inference. Existing one-pass history and
pending dispatches are preserved and are not treated as new final cache hits.
Known failed plans also require review rather than automatic retry.

Completed and failed plans retain their full journal while their assessments
remain retained. After the configured assessment retention period, the bounded
cleanup cursor removes the full outcome and stage payloads only when the
assessment is gone. Compact claim tombstones remain; a failed or uncertain
packet cannot acquire a replacement attempt through an alias. Uncertain plans
retain packet references and payloads as an investigation barrier. This version
does not automatically resolve uncertainty or discard its evidence. Operators
must account for tombstone and investigation disk growth. Existing native
retention and the earning window are not extended by stage-one success.

If SQLite cannot commit an already validated final outcome, a private sibling
`.pipeline-review` directory retains it when the filesystem remains writable.
These files require review and are never automatically accepted or dispatched.
An active plan past its deadline becomes uncertain even if its process remains
alive, so a returned or uncooperative transport cannot hold the local permit
forever. Simultaneous database and filesystem failures can prevent retention;
no success or refund is inferred in that case.

Legacy marker cleanup tolerates bounded concurrent deletion, rechecking the owner before retrying. Completed-result cleanup rechecks the full frozen result. Genuine permission failures remain visible; cleanup never changes ACLs.

Request telemetry records each stage separately. Assessment outcomes and total
assessment latency remain assessment measures. Assessment duration covers coordinator start through final validation and outcome preparation; delayed persistence is separate. Pipeline totals never create a
third request or a synthetic first-response sample. Reported token totals are
known only when all required stage reports are known; measured stage reports
remain available independently.

This source change requires independent implementation review and controlled
evaluation before deployment. Offline mocks establish protocol and durability
properties; they do not establish semantic improvement, live grammar behavior,
operational throughput or independently calibrated confidence.

## Final dispatch gate

After entry hooks finish, each request rechecks the live master/model switches,
configuration, source generation, packet, frozen receipt, ownership, quota and
UTC day. A final read-only SQLite snapshot checks the entered request hash and
claimed units. It closes before request instrumentation and transport begin;
no database transaction is held during file checks or network I/O. Disabling
analysis prevents another request and final acceptance without resetting claims
or creating provider backoff.

This is a last dispatch check, not atomic configuration-to-network delivery.
An unrelated writer can still change state after the check while instrumentation,
DNS/TLS setup or socket transmission occurs. A process-wide/distributed update
protocol would be needed to eliminate that residual window. The entry hooks
cannot bypass the new gate; later changes cannot authorize a different request
body, reuse a consumed claim or accept a changed final context.
