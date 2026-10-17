# Evidence-supported MITRE mappings

Behavior mappings are investigation hypotheses. They do not change native scores,
AI eligibility, retention, permanent offenses, replay rules, exceptions, crawler
protection, publication or correlation. D3FEND is relevant defensive analysis
context: it never proves that a control exists, prevention succeeded, or an event
is malicious. There is no independently labeled precision/recall evaluation.

## Reviewed sources

`mitre-sources.json` pins Enterprise ATT&CK **20.0** at upstream commit
`c2494b29dd268c46a5d0ea0990553e4327cd2253` and D3FEND **1.6.0** at its versioned
ontology URL, with exact SHA256 hashes. MITRE's version index and ontology version
page were checked on October 16, 2026. The imported snapshot contains 706 active
Enterprise techniques/subtechniques and 271 defensive technique IDs. Algorithm
IDs (including the D3-prefixed ARMA algorithm), revoked/deprecated entries and other ATT&CK object types are excluded.

Primary sources: [ATT&CK version index](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/index.json),
[ATT&CK terms](https://attack.mitre.org/resources/terms-of-use/),
[D3FEND version](https://d3fend.mitre.org/version/),
[D3FEND ontology releases](https://d3fend.mitre.org/resources/ontology/), and
[D3FEND terms](https://d3fend.mitre.org/tou/).
Derived registries retain the copyright/license notices in `MITRE-NOTICES.txt`.
Upstream datasets retain their respective terms; application licensing grants no
additional rights to them. Dataset files are acquired separately, not bundled in
either edition. No runtime download or new outbound service is introduced.

Download the two exact manifest URLs to an administrator-controlled staging
directory, then build the derived registry offline using the existing application
service account and data location:

```sh
python behavior_taxonomy.py --attack enterprise-attack-20.0.json \
  --d3fend d3fend-1.6.0.json --attack-version 20.0 --d3fend-version 1.6.0 \
  --output /private/data/behavior-taxonomy.json
```

Replace the example data location with the configured application's data directory.
Import checks both source hashes and embedded dataset versions, then atomically
replaces the derived registry. A legacy, missing or damaged registry disables
taxonomy suggestions while ordinary assessment and native processing continue.
Reimport is required to upgrade a legacy registry. Preserve the previous registry
for rollback; never edit a derived registry in place.

For an intentional dataset upgrade, review the official versions and URLs, hashes,
terms, removed/deprecated IDs, changed labels and telemetry rules. Supply a reviewed
manifest through `--manifest` or update the checked-in pins with the source change.
A version string alone cannot bypass content/version checks. Catalog fingerprints
participate in assessment cache identity, including when a dataset change leaves
the selected IDs unchanged. Existing saved assessments retain their original names,
dataset version, registry fingerprint and citations; old assessments without those
metadata display an explicit version-unavailable fallback.

## Telemetry boundaries

The application offers a bounded subset of dataset-validated IDs:

* Twenty explicit detector families support credential subtypes, external scans,
  internal service discovery, public application exploit attempts, credential
  dumping, scripting interpreters, discovery, tool transfers, web shells and
  network denial of service. Only a complete recognized action phrase qualifies;
  negated/test descriptions, paths containing technique words, ports, reputation,
  firewall drops and prior policy decisions cannot establish these behaviors.
  Many current collectors do not retain these detailed detector descriptions, so
  those mappings remain unavailable on their data. This adds eligibility for
  supplied telemetry; it does not add collectors or recover missing payloads.
* Cowrie shell-input metadata can offer the broad interpreter family. Only an
  explicit recorded network-fetch category can offer ingress transfer; a
  `file_download` event alone may represent stdin or redirected-output capture.
  Input does not establish execution or maliciousness. See
  [portable source observations](SOURCE-OBSERVATIONS.md).
* Two distinct authentication-failure observations from one collector within
  15 minutes permit only the broad brute-force candidate. They can have benign
  causes; absent account/password detail does not establish guessing, spraying or
  stuffing. Bucket totals and duplicated observations cannot substitute.
* Three distinct sensitive-path requests from one collector within 15 minutes
  permit broad active scanning. This does not establish wordlist use, vulnerability
  exploitation, access success or maliciousness. A single sensitive path does not
  qualify. Sanitized paths retain no query values or request bodies.
* Defensive context follows relevant sampled web/authentication/command/transfer
  observations and honeypot sources. It carries no deployed-control status.

Each model mapping must cite supporting observations for that particular ID.
Context-only references, unsupported IDs and unrelated events fail application
validation even if the provider returned valid JSON or the ID exists in MITRE.
Names come from the application registry, never model-supplied display fields.

## Bounds and uncertainty

Rule version `telemetry-1` offers at most **12 ATT&CK** and **6 D3FEND** candidates,
with at most two supporting observation IDs each, in deterministic ID order.
Metadata and the assessment view disclose candidate truncation. Broader eligibility
can still miss relevant activity because telemetry, redaction and selection are
partial. A detector description is not independently verified ground truth.

Prompt version `behavior-3.4` preserves the existing **18,000-byte** user-input cap,
single historical candidate, **8,192-token** context and **1,800-token** output
ceiling. Output remains at most two ATT&CK mappings and one D3FEND mapping.
Candidate and uncertainty fields count toward the byte limit. Oversized input
fails without enforcement; model settings and GPU/receptionist services do not
change. These bounds do not establish actual model memory, tokenization, latency
or classification accuracy on every packet; real GPU evaluation remains separate.

The existing evidence disclosure shows dataset/version, readable technique names,
observation links, missing mappings and uncertainty. Historical assessments remain
readable without relabeling them using a newer dataset. Server-render and isolated
synthetic visual checks cannot establish deployed appearance or production accuracy.
