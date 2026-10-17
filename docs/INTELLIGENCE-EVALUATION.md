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

Scheduling retains an oldest-first fairness slot and then favors distinct
fingerprints, recent events and richer evidence within the oldest 100 queued
addresses. Changed windows keep the original queue time. The existing two-call
cap, daily budget, provider backoff, leases, cache and per-job attempt limits still
apply. No item is removed merely because it shares a fingerprint. Saturated
workloads remain partially inspected; this policy cannot make 96 daily requests
cover thousands of pending IPs. It makes no fleet-wide timeliness guarantee.

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

The worker reads `behavior-references.json` beside the derived database, with a
128 KiB file cap and 32-rule cap. No public feed is sent private inventory. Schema
1 has a `rules` array. Every rule requires `id`, `version`, `label`, `kind` (`tool`
or `cve`), `reviewed_by`, `rationale`, `match` and `references`. A CVE label must be
a CVE identifier. `match` contains exact `path` and `method` plus `action` and/or
`client_type`. All fields must match one cited sampled event. Generic scans, a
model's recollection, a familiar endpoint or a claimed client alone are insufficient.

Each reference supplies an HTTPS `url`, `primary: true`, `publisher`, source
`version`, timezone-aware `retrieved_at` and the SHA-256 of the reviewed primary
source bytes. An administrator must verify the source, its applicability and the
indicator rationale before installing it. These fields are provenance assertions,
not cryptographic proof that a publisher endorses the detection. The local catalog
hash and source version should accompany independent QA. The loader does not fetch
or execute reference content. Version changes create a separately reviewable alert.

Use vendor advisories or upstream project disclosures and archived immutable
revisions. Do not install a rule if the discriminating payload, request parameter,
affected version or response evidence was stripped by privacy normalization.
Such a gap must remain unknown. A signature association does not prove that the
target runs an affected version, that a request exploited it, or that exploitation
succeeded. A conjunction can still be a false positive; review it independently.

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
