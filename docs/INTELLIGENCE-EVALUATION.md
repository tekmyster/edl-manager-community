# Returning activity and independent evaluation

This implementation is staged for independent QA. Deployment, useful accuracy and
operator attribution are separate outcomes. Existing native and pilot safeguards
remain authoritative. Community collection and AI inspection remain disabled by
default. No new feed, paid service or outbound advisory fetch is enabled.

## Review activity

Behavioral intelligence links to **Returning activity** and **Independent
evaluation**. Activity alerts distinguish:

* Same-IP return: distinct later saved events separated by at least one hour from the
  latest prior saved window. This confirms observations from the same address,
  not that the address still represents the same person or machine.
* Similar activity: an existing bounded cross-IP retrieval candidate with cited
  events on both sides. This is a possible recurrence hypothesis, with common
  tools, NAT, proxies, reassignment and partial sampling as alternatives.
* Behavior change: new paths, selected behavioral actions or allowlisted claimed
  client names in an IP's saved sample. An absent feature means no longer sampled,
  not that an operator stopped using it.
* Reference pattern: a conjunction of observed fields matching an administrator's
  reviewed, versioned local tool/CVE reference. No catalog is shipped with guessed
  CVEs or named bot families. Missing or invalid catalogs produce no associations.

Fingerprints identify bounded observable path/action sets. They are stable across
IPs with those same sets and change when the sets change; neither a fingerprint
nor feature overlap is a calibrated probability. Details show current/historical
citations, first/last observations, sampled sequences and gaps, client classes and
claims, observed targets (internal targets stay pseudonyms), missing telemetry,
saved ATT&CK/D3FEND context and the next review action. A sequence is consecutive
in the saved subset, not necessarily in the original traffic.

Alerts deduplicate by kind, fingerprint and address pair (plus rule version for
reference patterns). Evidence repeats are identified by cited event IDs, so packet
rebuilds do not create new comparison observations. Rejection survives refresh.
Alert review records usefulness; it does not accept relationships, merge groups
or transfer scores. Generic assets (root, favicon, robots and sitemap) cannot satisfy the two-path
requirement in correlation version 3. Historical version-2 links remain immutable
review records; they are not retroactively rewritten as improved matches. A
comparison window can contain later events than the current packet. Details state
this explicitly and avoid assuming chronological return ordering.

The existing relationship review remains the sole group
membership path and preserves rejection/split/merge revisions.

Each pass reads at most 32 earlier same-IP windows, three existing cross-IP peers
and 32 reference rules. Oldest-first cleanup removes at most 100 unreviewed alert
observations older than 90 days per pass and releases their packet references.
Reviewed alerts retain their cited windows. Independent evaluation cases and
labels are investigation records and persist; administrators should create focused
cohorts. There is no hard disk-size cap. A maximum of 50 alerts and 100 evaluation
cases is shown; report truncation is explicit. No inference occurs in these pages.

## Queue timeliness

Scheduling combines bounded indexed pools: oldest 100 queued IPs, richest 64
queued packets, and most-recent 64 queued packets, at most 228 distinct candidate
IPs. Selection alternates age and evidence priority slots. A newer distinctive
nonempty packet beyond the oldest 100 can receive the second slot; the next age
slot remains available if the oldest job is leased or cached. Queue metadata
follows current packet changes. Deleted queue items and packets release metadata.
Legacy metadata backfills in restartable rowid pages of at most 200 per pass;
partial backfill is exposed in worker state. Selection returns at most 100
candidates, not 100 requests. The existing two-call cap, daily budget, provider
backoff, leases, cache and per-job attempt limits remain authoritative. No item
is dequeued merely because it shares a fingerprint. This does not make 96 daily
requests cover thousands of pending IPs; candidate scheduling is not a measured
live latency or coverage improvement.

The overview separates pending ages from consumed wait samples and reports
current-prompt unexpired packet coverage. That count does not certify current
configuration/source eligibility. A prompt update invalidates the old request
identity and pilot eligibility, but never resets usage or retries. Existing stored
answers are preserved as historical results. Prompt 3.6 explicitly asks for
inconclusive when legitimate versus malicious activity cannot be distinguished;
it cannot establish semantic correctness by instruction alone.

## Independent review workflow

Open a saved observation and choose **Save for independent review**. The immutable
case snapshots the exact packet, last saved assessment outcome, bounded related
comparisons and alert details. Current packets also snapshot native and effective
local policy separately at capture; older policy is unknown. This is not proof of
EDL publication or a firewall drop. Capture does not invoke a model or replay work.

Initial review hides model and policy predictions. Investigate raw events, owner
records or an already documented authorized test. Save legitimate, malicious or
borderline, an evidence basis, investigation reference, reviewer and rationale.
Reviewers explicitly attest independence from blocks, source detector labels,
model answers and copied feeds. The application records that attestation; it
cannot independently authenticate an external investigation. Earlier reviews are
append-only and the latest review is used once per case. No labels are prefilled
from production scores or synthetic fixtures.

The initial page contains the case's saved observations only. It does not render
model, policy, comparison or activity hypotheses. Quality fields are shown only
after the first label; any quality fields submitted with an initial blind label
are recorded as unknown. This prevents a quality judgment without seeing the
captured finding.

After the first label, **Frozen review context** shows the saved comparison and
activity findings, states, cited current/historical events, uncertainty and advisory
versions/source hashes. New cases also snapshot the latest ten source reviews per
finding and the local policy reasons and separate capture time. Derived findings
and reviews are read in one derived-database transaction; the local policy snapshot
is a separate native/derived read and is not claimed to be globally atomic. No live
relationship, alert or catalog lookup fills missing case context. Older cases keep
their original bytes; unavailable histories and policy fields remain unknown.

The review form prefills the prior activity label and provenance during later
quality reviews. Current IP navigation is explicitly separate from immutable case
context and cannot substitute for a missing historical finding. Unknown and Not
applicable remain available for absent or unsupported categories.

After the first label, inspect the saved model mappings and evidence and append
an optional quality review for ATT&CK, D3FEND, correlation, return activity and
tool/exploit trends: supported, unsupported, unknown or not applicable. Independent
examples should include legitimate automation, malicious activity, borderline
traffic, shared tools used by unrelated operators, NAT/proxies and reassigned
addresses. Returning-operator truth generally needs owner/investigation evidence;
matching request paths alone cannot supply it.

The latest displayed cohort reports counts and denominators, false positives,
precision, misses/recall, abstention, uncalibrated confidence bins and quality
counts. Borderline labels are excluded from binary metrics. Malicious abstentions
count as cohort misses. Unknown denominators return unknown, not zero accuracy.
Current-policy comparisons use exactly the same labeled cases for native versus
pilot, showing changed, improved and harmed decisions. A policy denial and a
maliciousness classification are different tasks; neither agreement nor a native
block is the truth label. AI-only score crossings require the captured applied
assessment identity and scores on opposite sides of 75. Whitelisted cases can
cross a numerical score without becoming enforced blocks; score and policy
metrics remain distinct. Confidence bins show review counts, not calibration.

Convenience-sampled repeated windows are not a population estimate. Preserve a
held-out IP/time cohort, inspect false links and class coverage, and obtain enough
independent labels before judging incremental value. Population recall, unseen
misses, named-operator accuracy and calibrated reliability remain unmeasured.

## Reviewed tool/CVE references

`behavior-reference-starter.json` supplies two small reviewed primary-source
associations. They are context, never scores or enforcement instructions:

* A POST to a CGI path containing parent traversal and ending at `/bin/sh`,
  `/bin/bash` or `/etc/passwd` is a traversal probe compatible with Apache
  CVE-2021-41773 / CVE-2021-42013 context. Other CGI weaknesses and broad probing
  can look alike. Decoded paths cannot distinguish those CVEs or prove an affected
  Apache version, configuration, payload execution or success.
* A POST to the recognized PHPUnit `eval-stdin.php` endpoint is targeting-only
  context for CVE-2017-9841. The maintainer's article and immutable upstream source
  revision support the endpoint context. No PHP payload or target version is
  collected. It does not identify Androxgh0st or any other operator/tool family.

The existing general identifier redactor can hide the long PHPUnit path. A fixed
`endpoint_hint` category is now derived from the original already-saved path
before redaction, without keeping raw tokens, query values, payloads or new
observation identities. This category is the same request evidence, not a third
independent corroboration. Already-redacted history cannot be reconstructed.
An indexed history allowance retrieves at most two observations per recognized
pattern (four total), within the configured IP, collection scope, enabled source
and evidence-time window. These observations are selected before ordinary source
sampling, still within the same 11,200-byte packet budget. They remain ineligible
for pilot points. This addresses retained probes falling outside the ordinary
latest-200 sample; it is not full history coverage. Legacy history indexes backfill
in restartable pages of at most 200 per pass, with partial state exposed. History
cleanup also releases index entries.

Schema 2 explicitly represents targeting-only or traversal-probe evidence and
uses two request fields, without a fabricated third signal. Schema 1 custom
catalogs remain readable for compatibility.

PaperCut CVE-2023-27350 / CVE-2023-27351 remains an unavailable association: current
samples omit distinguishing query values, application debug events and process
ancestry. A generic `/app` request cannot trigger it. Direct CISA AA24-016A and
AA23-131A requests returned 403; those full documents were not reviewed or
archived as successful primary-source fetches. No access restrictions were
bypassed. KEV membership is not treated as a request signature.

Open **Advisory context** to inspect rule strength, limitations, source versions,
retrieval times, hashes, pending source changes and recent review history. Source
snapshots are dated context, not a claim of complete coverage of new disclosures.
Only a reviewed supported matcher can be added; advisory text cannot generate or
activate a new mapping automatically.

An administrator stages a refresh with:

```sh
python behavior_references.py refresh --directory /path/to/private-data
```

This command is explicit; it installs no timer. It reads four fixed HTTPS primary
URLs, sends no local IPs/evidence/inventory/authentication, allows no redirects,
reads at most 3 MB per source with an eight-second request timeout, and permits
one refresh attempt per 24 hours including failures. The total source count and
read sizes are bounded. It checks expected advisory markers, preserves exact
bytes in a hash-named source store, records retrieval/HTTP provenance, and stages
a candidate containing changed source hashes. Existing match logic stays fixed. Retrieval timestamps alone do not change rule
versions or generate new pattern alerts; changed source bytes affect only the
corresponding rule versions.

If the Manager cannot reach these sources, fetch their exact bytes on an authorized
research workstation and prepare the reviewed public snapshot bundle. Stage it
without changing network or TLS policy:

```sh
python behavior_references.py import-bundle --directory /path/to/private-data --bundle public-primary-source-snapshots.zip
```

The importer accepts only the four fixed source filenames plus a bounded manifest,
checks URLs, timestamps and SHA-256 hashes, reads at most 3 MB per source, and never
extracts arbitrary paths, executes source text or makes network requests. It
preserves original retrieval times and records local staging separately. It does
not reset or consume the network refresh cooldown or any model budget. Import
still produces a pending candidate; it does not activate context. This also lets
reviewers inspect the starter's exact archived source bytes in the UI.

Review changed bytes and rule applicability before accepting or rejecting the
exact pending hash in the authenticated UI. Acceptance checks source byte hashes,
preserves the prior active catalog as last-good, atomically replaces the active
catalog and records reviewer/outcome/notes. Refresh failures retain active
context; invalid active data falls back to last-good or becomes unavailable.
Rejection retains active context. Catalog review grants no scoring authority.
Historical alert details retain their source versions and citations.

Current, last-good and pending source blobs stay protected; older unprotected
blobs beyond the latest sixteen expire incrementally. Review hashes persist in
the ledger. Packaged starter source bytes are preserved in the private QA bundle,
not copied as entire vendor documents into Community. A previous-byte download
can be unavailable when that snapshot was never imported or has expired; its hash
and original primary URL remain visible. The starter source manifest hashes are
shared public metadata only. The ordinary web UI downloads source bytes as
attachments with content sniffing disabled.

## Demonstrated collector gaps and scoped next collection design

The existing sensor requests event IDs, timestamps, destination/port, paths,
methods, status and selected HTTP user-agent/host fields. `web_client.http_details`
already parses known client labels; this patch preserves only fixed vocabulary
through history normalization. Raw user agents, browser versions, credentials,
request bodies and header/query values stay excluded. Labels remain spoofable.
No collector deployment or routing change is part of this patch.

Cowrie event categories survive, but its client-version/KEX payload values do not
appear in the configured sample projection. TLS and HTTP header order are explicitly
unavailable in the sensor and packet builder. A future opt-in collector should
first prove source support at the TLS terminator and Cowrie output, with source
record ID, collector version, native time and receipt time. Allowlist coarse
protocol/cipher/client categories or keyed local fingerprints, cap records/bytes,
redact before forwarding, define retention and access scope, and test privacy and
CPU/storage overhead offline. Raw JA4/header-order data can correlate legitimate
shared clients and may be identifying; it must not become operator proof or an
enforcement shortcut. No new TLS/header-order values are fabricated here.

Primary context: [Cowrie event-code reference](https://docs.cowrie.org/en/latest/OUTPUT.html)
defines the event categories; [MITRE T1110](https://attack.mitre.org/techniques/T1110/)
describes the broad brute-force family. The current hash-validated taxonomy and
telemetry eligibility rules remain unchanged. Candidate and prompt size limits
still apply. Increasing mappings cannot recover missing packet fields or make
detector descriptions independent ground truth.

## Grounded observation contract

Prompt `behavior-3.8` and generation contract `grounded-observations-2` require exact, bounded source-report statements with their bound citations. At most twelve statements are offered. The acceptance validator recomputes the contract independently: valid event IDs alone cannot support authentication failures, shared tooling, collaboration, tests or defensive-control deployment. ATT&CK and D3FEND explanations use fixed server-approved language bound to the selected technique. D3FEND remains optional defensive context. Historical similarity requires actual common request structure or a supplied client label in both cited sides, with spoofing/shared-infrastructure alternatives; generic connection overlap alone does not qualify.

No provider-authored narrative is accepted in findings, contradictions, mapping/correlation explanations, summary or limitations. The provider selects bounded observations and interpretations; it cannot invent supporting facts. This deliberately reduces narrative flexibility and may abstain or reject more often. A permitted observation is a source report, not independently established truth. The contract is not a semantic accuracy, authorization or identity oracle.

Sparse connection, negotiation/closure and authentication-failure-only reports cannot produce decisive benign or malicious classifications. Positive fresh structured cached context is required for a benign interpretation, together with a detailed observation and an explicit cited context statement. Malicious interpretation eligibility is source-neutral: it requires a complete cited pair of distinct detailed source reports with original-record provenance, aware timestamps within 15 minutes, and different supported behavior features. Reports must share an observed target or an explicitly recorded collector stream and port. Source/sensor branding grants no privilege. Fixed POST endpoint categories require structured request fields; detector labels or paths alone, generic failures, repeated labels, shared original IDs and copied request signatures do not suffice. Recognized behavior includes reported ATT&CK detector categories, machine command/transfer events and normalized public targeting patterns. A coherent HTTP/WAF/Wazuh/honeypot pair may permit a malicious interpretation; it never forces one or proves authorization, independent corroboration, compromise, attribution or successful execution. Inconclusive remains available, and the exact source-report narrative restrictions still apply. Automation/intent labels are constrained hypotheses, and unknown labels require zero confidence. This conservative coverage restriction needs independent evaluation; it must not be represented as improved population accuracy.

Maliciousness confidence is the model's uncalibrated 0–1 maliciousness estimate, not confidence in the displayed class or a calibrated probability. A historical Benign result with value 0 retains that numeric value. Older versioned outputs and reviews remain unchanged and readable, with a notice that their statements predate the grounding contract. New prompt/schema identities invalidate inference caches without rewriting history. Existing native/pilot controls, daily and per-cycle budgets, packet limits, 18,000-byte input limit, 8,192 context and 1,800 output-token limits remain authoritative. No model call or production replay is needed for the isolated legacy acceptance regression.

Sufficiency matching examines at most24supported signal events and276pairs, offers at most6support bundles, and retains only complete bundles within the existing12fact budget. Lexical bounded sampling and missing target/provenance can miss useful evidence; these are coverage limits rather than collector exclusions. The validator independently recomputes eligibility and requires both members of one offered bundle among the selected findings. No historical outputs or reviews are rewritten. All existing packet/model budgets and pilot scoring safeguards remain unchanged.
