# Behavioral intelligence — initial shadow release

EDL Manager owns evidence comparison, AI requests, validation, assessment storage and policy decisions. Wazuh is a telemetry source and may host the application. It does not accept AI scoring decisions. The model server supplies assessments only.

This release adds bounded evidence packets, structured intelligence and block history, cached Palo traffic context, deterministic fingerprint comparison, historical observation comparison, reviewed activity groups, background model assessments, validated ATT&CK/D3FEND mappings, relationship review, optional score simulations and read-only reporting. It does **not** activate AI scoring. Native scores, exceptions, expiry and EDL publication remain authoritative.

## Use

Open **System settings → Behavioral intelligence**. Enable evidence collection and, optionally, similarity matching. Configure the private HTTPS model endpoint, exact Ollama model name, dedicated key and trusted certificate file before enabling AI inspection. Keys are stored separately with mode 0600 and are never returned to the browser. Leave the key field blank to retain it.

IP details show the assessment, evidence coverage and possible similar activity. **Prepare evidence** refreshes a packet using saved source samples. The background worker performs model calls. A similar fingerprint is not proof that IPs share an operator. Accepting or rejecting a relationship records an investigation decision without changing policy.

The proposed maximum adjustment is optional and affects a simulation only. No production maximum, calibrated confidence mapping or enforcement promotion is selected by this release. A malicious assessment can have an illustrative adjustment; benign or inconclusive assessments cannot. Applied adjustments remain zero.

## Background service

Run `EDL_CONFIG=/private/config.json python behavior_worker.py` once per minute using a separate service/timer. Community Docker Compose includes the `behavior` worker; collection and model inspection start disabled. Do not run inference inside the ingestion or web request path.

Initial operational defaults: 30-day evidence window, 25 IPs per indexing pass, at most two model requests per pass, 24 requests per UTC day, 120-second request timeout and 24-hour assessment validity. Optional Palo traffic refresh starts disabled in portable installs and has a separate 100-query daily budget and two-query pass limit. It reuses the existing five-minute investigation cache and respects pending work. These conservative test limits do not provide comprehensive coverage of a busy deployment. Raise budgets only after measuring workload and accuracy. Cache hits do not consume requests. Failures retry after one hour, with at most three attempts per UTC day. Successful assessments may refresh after expiry. Expired findings are not displayed as current.

## Model endpoint

This initial adapter supports private HTTPS Ollama-compatible endpoints at `/api/chat`; it does not send logs to a public cloud API. `model_gateway.py` is an optional standard-library gateway for loopback Ollama. Supply its private JSON configuration outside the repository:

```json
{
  "bind": "192.168.20.10",
  "port": 11435,
  "model": "your-installed-model:tag",
  "allowed_sources": ["192.168.10.10/32"],
  "key": "replace-with-a-dedicated-random-secret-of-at-least-32-characters",
  "cert": "/private/tls/server.crt",
  "cert_key": "/private/tls/server.key"
}
```

Run `python model_gateway.py /private/gateway.json`. Protect the configuration and key files using the host's access controls. The gateway authenticates and restricts sources, accepts one inference at a time, fixes the upstream to loopback Ollama, limits input/output and exposes no tools or management actions. Authenticated `/health` returns the source address seen by the gateway. Restrict the host firewall to the EDL Manager source. Validate a separate fresh authenticated connection before closing an existing administrative session after access changes.

The gateway supplies an 8,192-token context, deterministic sampling and an 1,800-token output ceiling. Timeouts, busy responses, invalid references and truncated or mismatched model replies produce unavailable assessments without affecting EDL generation. TLS verification is required; there is no skip-verification option. A log's contents are untrusted data even when returned by a trusted collector.

## Taxonomy import

See [Evidence-supported MITRE mappings](MITRE-COVERAGE.md) for current hash-pinned
versions, required legacy-registry reimport, supported telemetry, candidate bounds
and uncertainty. This section is the original release runbook; current scoring
configuration and code remain authoritative.

Download versioned datasets from [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) and [MITRE D3FEND](https://d3fend.mitre.org/resources/ontology/), subject to their respective terms. Import into the application's private data directory:

```sh
python behavior_taxonomy.py --attack enterprise-attack-VERSION.json \
  --d3fend d3fend.json --attack-version VERSION --d3fend-version VERSION \
  --output /private/data/behavior-taxonomy.json
```

The registry records source hashes and versions. Only a bounded, relevant subset of imported identifiers is supplied per request. Without a registry, taxonomy output must be empty. Generated identifiers and evidence references are validated independently of model output formatting.

## Evidence and storage

Evidence packets contain source/timestamp provenance, stable sample IDs, normalized paths and parameter names, methods, status codes, ports, source counts and bounded intelligence summaries. Query values, raw bodies, cookies, authorization headers and internal destination addresses are omitted. Path identifiers are normalized/redacted. Redaction reduces exposure; free-form path text must still be treated as potentially sensitive. Saved samples are explicitly labeled as incomplete. Source counts are sampled observations, not independent attack counts.

Derived evidence, immutable assessment history, work leases, usage and reviewable pair relationships use `behavior.sqlite3` beside the native database. Native scoring and retention do not read this database. Include it in encrypted backups using SQLite's online backup API. No existing repeat-offender retention policy is changed. Automated derived-history cleanup and a configurable retention policy remain follow-up work; monitor database size during this bounded trial.

Fingerprints contain normalized paths, parameter names, actions, methods, sensors and ordered path pairs. A local feature index stores up to 64 selected path/action/parameter/sequence tokens per window. Candidate retrieval searches saved windows from the preceding 365 days, ranks up to 2,000 windows by shared indexed features, requires at least two shared path/parameter/action features and a Jaccard similarity of 0.6, and returns up to three matches from distinct peer IPs. Existing fingerprints backfill in batches of 200 per worker pass. These are initial retrieval settings, not calibrated attribution probabilities. Matching does not establish maliciousness. Pair review and persistent activity-group merging/splitting are available; groups do not assert a shared actor identity.

## Reporting

Use an existing read-only reporting token with:

* `GET /api/v1/behavior` — indexing, assessment and request counts; explicitly reports inactive AI scoring.
* `GET /api/v1/ips/<ip>/behavior` — current assessment, coverage, sanitized evidence and related activity.

Existing management source restrictions apply. Cookie authentication cannot substitute for a reporting token. No model credentials, raw prompts or unvalidated provider responses are returned.

## Evaluation before enforcement

Review independently labeled legitimate, malicious and borderline traffic. Measure classification precision, false positives, evidence coverage, latency, queue delay, failed outputs and hypothetical threshold crossings. Do not interpret model confidence or feature similarity as calibrated probability. Shared scanners, NAT, proxies and reused public tools require explicit negative examples.

The remaining proposal work includes representative labeled evaluation, an independent-evidence overlap policy, calibrated and bounded scoring promotion, retention cleanup and aggregate evaluation reports. The shadow implementation must not be described as having activated AI enforcement.

## Structured context and reviewed groups

The behavior-2 evidence contract includes cached provider facts with separate cache and observation freshness. MISP supplies actionable/contextual counts, original source labels, attribute/event references and available snapshot provenance. Warning-list filtering is distinguished from explicit warning-list hit details, which the current sync does not provide. No match, missing data and stale data are separate states. GreyNoise preserves benign/malicious classification, noise, RIOT, actor and observation dates. Crawler verification and ASN ownership are independent context, not additional maliciousness signals. Reused feeds are not asserted to be independent sources.

Existing block records and saved returns are summarized over 30, 60, 90, 180 and 365 days. Exact-IP policy/list events provide chronology. These are historical policy observations, not evidence of a new attack or proof of firewall enforcement.

Palo context comes from the current configured investigation-cache scope. If enabled, the separate worker refreshes bounded exact-IP queries. It includes actions, ports, applications, rules, zones, reasons and sampled destinations. Internal addresses use stable pseudonymous asset references in model inputs; they are not a cryptographic anonymity guarantee. Original authorized investigation views retain their existing destination details. Cache failure or unavailable configuration does not interrupt ingestion or publication.

Similarity retrieval returns up to three candidate windows with supporting historical observations; model input considers only the strongest one. Correlation assessments must cite events from the current and candidate windows and retain alternative explanations. The behavior-3.17 / grounded-groups-8 input contract keeps the 18,000-byte user-message limit. Exact duplicate current events and provenance fields use lossless references, and relationship choices share their complete fixed explanation and alternatives. Stored packets, canonical citations, positive context and validation retain their full original records. Metadata records `wire_candidate_ids`, `wire_packet_ids`, `historical_windows_supplied`, and `input_preparation` byte counts and explicit omission reason. These describe the prepared request input; the separate transport receipt records dispatch/outcome. Byte counts include escaped Unicode in the exact serialized user message, excluding system instructions and response schema; they are not token counts. An oversized base packet fails before dispatch, while an oversized candidate is omitted without clipping facts. Legacy `supplied_packet_ids` remains the preassembly reference list used to retain evidence, and must not be interpreted as actual wire history. Job/cache identities still include the original candidates and deliberately change with the protocol versions; old assessment rows are not rewritten. Reviewed links form activity groups with stable identifiers and immutable revisions. Accepting a bridge merges groups; rejecting a link can split or archive them. Group pages retain accepted relationships and review history. Membership denotes reviewed related behavior, not confirmed shared identity. It never transfers scores or native retention.

Reporting adds paginated `GET /api/v1/behavior/groups` and `GET /api/v1/behavior/groups/<id>`. IP behavior reports include memberships. Member and relationship views are bounded; member totals and truncation are explicit.

Saved windows are accessible through authenticated observation pages and `GET /api/v1/behavior/observations/<id>`. Matches and group members link to the exact historical evidence, even after an IP’s current window changes. Prepared times are preserved with immutable packets. Parent bucket counters are not summed across duplicated samples, and repeated summaries are not supplied as additional intelligence evidence.


## AI performance

Open **System settings > AI performance** to view token usage, valid-response rate,
average response time, request outcomes and reused assessments. Select 24 hours
(hourly bins), 7 days or 30 days (daily bins). Charts use the selected display timezone.
The interval table provides the same values without relying on color or hover.
Average response measures valid assessments; the 95th percentile and latency chart
include failed and superseded requests. Superseded means evidence changed during analysis.
Tokens include both input and output, including rejected replies when the model reports usage.
Older or interrupted requests without token metadata are marked unavailable, not estimated.
Cache hits are recorded from this release onward and represent avoided model requests.

Grafana can read the same metrics with a reporting token:
`GET /api/v1/behavior/metrics?period=24h` (`7d` and `30d` are also supported).
The existing reporting-token and management-source restrictions apply.

Small-GPU analysis requests compact findings and compares the strongest historical
candidate per model call. Saved similarity results still include other candidates.
Output-limit responses and invalid evidence references are rejected. Failed calls
retain usage metadata, never the rejected raw reply. Scoring is optional and off by default. The performance view shows current applied
points and blocks requiring AI points; its impact chart averages active blocks in each interval.


## Bounded scoring pilot

Enable **AI scoring pilot** under Analysis limits and set **Maximum AI adjustment**
to a value above zero and no greater than 10. Evidence collection and AI inspection
must also be enabled. With the switch off, the maximum remains a simulation setting.
The pilot is intended for gradual homelab evaluation; model confidence is an
uncalibrated assessment, not a measured probability or validated production precision.

An adjustment requires a fresh, schema-validated malicious assessment with confidence
at least 0.90, no contradictory evidence, and at least two distinct cited observations
from the last 24 hours. Those observations must have explicit ingestion provenance
showing that they were not native scoring inputs. Missing provenance gives no credit.
If native scoring already uses that source/sensor bucket, its activity is excluded.
Duplicate copies of a request across logs do not create additional observations.
Palo drops, ownership, block history and behavioral similarity cannot satisfy this test.
Verified crawlers, whitelists and cached GreyNoise benign classifications receive no adjustment.
Already-blocked native scores receive no extra points.

The adjustment is `maximum * confidence`, capped at 10 and the combined score at 100.
It is recalculated from the native score; repeated analysis never adds cumulative points.
It expires with the assessment, after at most 24 hours, or when its supporting observations
age out. Disabling the pilot removes its contribution at the next list build.
Native retention and previous-block score floors never inherit AI-only scores.
AI-only block entries are excluded from the native repeat-offender backfill.
A native rule can independently qualify the IP later under the existing policy.

IP details show the native score, AI contribution and expiry. The AI performance page
shows current impact and historical publication samples. Missing assessment data or
an unavailable AI database falls back to native enforcement without blocking ingestion.
Publication metrics are best-effort and cannot interrupt EDL generation.


The small-GPU adapter constrains confidence to explicit numeric choices from 0.00 to
1.00. Replies outside that range are rejected rather than converted from percentages.
Prompt revisions invalidate cached inference jobs and score eligibility; evidence
packet versions remain separate. Only the strongest supplied historical candidate
contributes to an inference cache key, matching the actual model input.


## Richer cached event history

IP details link to **Browse cached history**, a paginated local view. The reporting
API adds `GET /api/v1/ips/<ip>/history?limit=100&offset=0` under the existing
reporting-token and management-source checks. Browser reads never query sources.

The separate behavioral worker queries at most two IPs per pass with its own
round-robin cursor and a 100-query UTC daily budget. Each exact-IP index query
reads at most 500 recent index records from the currently configured source/agent
scope. Successful reads reuse a five-minute cache; failures retain existing events
and back off for an hour. Disabled or unconfigured sources require no query.
The index receives source summaries, not full traffic. Even when all matching
index records fit, coverage remains partial. Repeated summary copies do not imply
new independent attacks. General Wazuh alerts are additional source observations;
EDL Manager still owns all scoring decisions.

Normalized history in `behavior.sqlite3` retains original event times, upstream
IDs where available, index record references, first local cache receipt time,
separate upstream index time where supplied, source/sensor and destinations.
Internal destinations use stable asset references. These references reduce
exposure; they are not cryptographic anonymity. Source-scope changes hide the
previous scope. A bounded worker cleanup removes derived events older than 30 days
(up to 5,000 per pass); native retention and existing immutable assessment packets
remain separate. This is not a complete audit-log archive or a new retention policy
for previously saved packets. Back up the derived database with SQLite online backup.

Small-model packets select source-balanced time endpoints and spaced intermediate
observations, sort them by original event time, and cap packet bytes. Available,
included and locally cached totals, query limits, and sequence span are explicit.
First-cache times do not reconstruct original network delivery. Late events can
appear in a later packet. Unchanged query refresh timestamps do not force a new
inference. Prompt revision `behavior-3.2` invalidates older model jobs/eligibility.
No accuracy or calibration claim follows from a successful request.

Query parameter names and syntax survive; values do not. Credential-like names
are redacted. HTTP method/status, a fixed protocol/content-type vocabulary, and
client categories are allowlisted. Authorization, cookies, arbitrary headers,
session values and bodies are omitted before derived persistence and model input.
Paths receive the existing identifier/secret redaction; free-form path text remains
potentially sensitive and operators must use appropriate source logging policy.
TLS and header-order fingerprints remain **unavailable** from these collectors.
No fields are inferred to fill those gaps. Cached/forwarded observations are
ineligible for pilot points; current native-row samples keep the existing explicit
novelty, freshness, distinct-observation and protection gates. AI outages cannot
interrupt native ingestion/publication.

Collection volume is deliberately limited for the trial. A large deployment will
have unqueried IPs and missing earlier requests. No routing changes or new sensors
are required. This release does not establish comprehensive telemetry or independently
labeled model precision.


For external normalized collectors, each `edl_activity_json.events` item may supply
`id`, timezone-qualified `seen`, `path`, `parameter_names`, `parameter_count`,
`method`, `status`, `destination`, `port`, and `http_metadata`. Query values must
be stripped upstream; parameter structures are names/counts only. `http_metadata`
accepts only fixed `protocol` and `content_type` values listed by the normalizer.
All other headers and bodies are ignored. Collector agent, index and index-record
provenance come from the actual configured index hit, not claims inside an event.
A later indexed copy can fill missing provenance without adding an observation or
changing its first local receipt. Changing the configured firewall source also
isolates the cached history scope.


History index queries accept the existing Requests `index_ca: true` system-trust
mode or a nonempty custom CA file path. Disabled/empty verification settings are
rejected. Custom CA files retain the existing index collectors' legacy certificate
extension compatibility (`VERIFY_X509_STRICT` off); trusted-chain verification
(`CERT_REQUIRED`) and hostname checks remain enabled. There is no retry that
disables verification after a certificate failure. System trust uses the standard
Requests verified transport, without treating `true` as a filesystem path.

IP details show the current applied AI contribution and effective score. The
separate, collapsed **Score simulation** uses the native score saved at analysis;
it does not determine the effective score. Cached history keeps counts, partial
coverage and collection status visible, with privacy/fingerprint details behind
keyboard-accessible help. Its event table scrolls horizontally on narrow screens.


Configurable derived retention, investigation holds, scheduling bounds and honest
benchmark definitions are documented in [AI retention and performance](AI-RETENTION-PERFORMANCE.md).


The staged additive session/source contract, capture semantics and typed rejection
diagnostics are documented in [portable source observations](SOURCE-OBSERVATIONS.md).


Scheduler index migration commits at most 200 saved packets per pass. Actual SQLite BUSY/LOCKED errors at its transaction boundary roll back all index, readiness, queue-priority and cursor changes before returning an explicit deferred status. The last committed cursor is retained; a later normal pass resumes from it. Deferred progress is zero and completeness remains unknown. Non-contention SQLite, I/O and programming errors still propagate. This does not change connection timeouts, add an inline retry loop or force a worker cycle.


Native ingestion/enrichment failures are recovered by the worker transaction
owner. Before writing failure/deferred status it rolls back the current pending
unit, invalidates timing receipts and resets pending batch bookkeeping. Earlier
commits remain durable. Only numeric SQLite BUSY/LOCKED may defer to the next
normal pass; other errors propagate, and a secondary status failure never
replaces the original error. Deferred passes do not report completed counts.
The existing commit sizes, cursor overlap and native scoring/protections stay
unchanged. Already durable ASN input replays from its snapshot before queue
publication; a failed import does not itself require another broker lookup.

A generation swapped into `current` is already published even if subsequent
SQLite bookkeeping or success-status persistence fails. Failure status records
which side of that boundary was reached; rollback does not undo published files
or earlier commits. This recovery does not establish elimination of contention.

Background history claims use an optional opaque owner and compare-release.
Old cleanup cannot clear a reclaimed lease. Native cleanup contention cannot
replace a durable derived success/failure result or trigger an immediate fetch.
Other storage failures remain visible. The existing process single-flight lock
still covers fetch/save/release, including work lasting longer than the lease;
the 90-second lease alone is not a general exactly-once request guarantee.


### SQLite writer occupancy and loaded-code rollout

An initialized native Store validates the required tables, columns, keys,
indexes and migration markers without recurring retention deletes or unchanged
audit-cursor writes. Missing indexes still require a real schema repair;
incompatible or missing initialized history fails visibly. Fresh and genuine
legacy migrations retain their backfill/replay behavior. The existing scheduled
native owner runs indexed due checks and at most 5,000 expired handoff rows,
5,000 arrivals older than 366 days and 5,000 audit records per pass. Maintenance
status includes remaining work; partial sweeps resume on the next normal pass.
Native evidence batches of 100, source pages, cursor overlap and Palo renewals
keep their existing commit boundaries and eligibility rules.

Readiness prepares the native description and intelligence context at one fixed
as-of time on a read-only native snapshot before taking the derived writer.
Inside that writer it verifies the exact ready revision, captured collection
scope, native configuration identities and caller settings. Mutable historical
receipt/ambiguity decisions, packet and feature writes, correlation/intelligence,
analysis queue and exact ready acknowledgment share that one transaction. A
changed configuration or successor revision leaves work pending for a fresh pass.

Handoff delivery keeps its public read bound of 500 while committing at most 16
selected rows per derived transaction. Each commit is followed by exact native
revision-plus-ID acknowledgments. Successful chunks continue immediately without
sleep, inference quota or cycle work cap. Earlier chunks survive a later failure;
reported counts include only committed derived work and completed acknowledgments.
Standalone history saves likewise begin IMMEDIATE before mutable receipt reads
and commit chunks of 16. Borrowed transactions use a neutral apply helper and
remain owned by their caller. A fetched history query reports success only after
all of its events have been saved. Replay remains necessary after interruption.

The staged bound of 16 favors competing-writer opportunities over fewer commits;
16/64 fixture measurements are delivery-review evidence, not a production capacity
or zero-contention guarantee. The native preparation capability is optional for
compatibility with an already loaded Brain class. Such an old class keeps the
prior in-writer context path. Foreground/fallback callers keep existing defaults.
A later authorized rollout must refresh long-lived web/worker Python processes
for all loaded functions to receive the repair, and validate fresh administrative
access before closing the original administrative session if access settings are
changed. No refresh, service change or deployment is part of implementation staging.
