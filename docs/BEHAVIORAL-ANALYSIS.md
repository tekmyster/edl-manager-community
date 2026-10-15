# Behavioral intelligence — initial shadow release

EDL Manager owns evidence comparison, AI requests, validation, assessment storage and policy decisions. Wazuh is a telemetry source and may host the application. It does not accept AI scoring decisions. The model server supplies assessments only.

This release adds bounded evidence packets, deterministic fingerprint comparison, background model assessments, validated ATT&CK/D3FEND mappings, relationship review, optional score simulations and read-only reporting. It does **not** activate AI scoring. Native scores, exceptions, expiry and EDL publication remain authoritative.

## Use

Open **System settings → Behavioral intelligence**. Enable evidence collection and, optionally, similarity matching. Configure the private HTTPS model endpoint, exact Ollama model name, dedicated key and trusted certificate file before enabling AI inspection. Keys are stored separately with mode 0600 and are never returned to the browser. Leave the key field blank to retain it.

IP details show the assessment, evidence coverage and possible similar activity. **Prepare evidence** refreshes a packet using saved source samples. The background worker performs model calls. A similar fingerprint is not proof that IPs share an operator. Accepting or rejecting a relationship records an investigation decision without changing policy.

The proposed maximum adjustment is optional and affects a simulation only. No production maximum, calibrated confidence mapping or enforcement promotion is selected by this release. A malicious assessment can have an illustrative adjustment; benign or inconclusive assessments cannot. Applied adjustments remain zero.

## Background service

Run `EDL_CONFIG=/private/config.json python behavior_worker.py` once per minute using a separate service/timer. Community Docker Compose includes the `behavior` worker; collection and model inspection start disabled. Do not run inference inside the ingestion or web request path.

Initial operational defaults: 30-day evidence window, 25 IPs per indexing pass, at most two model requests per pass, 24 requests per UTC day, 120-second request timeout and 24-hour assessment validity. These conservative test limits do not provide comprehensive coverage of a busy deployment. Raise budgets only after measuring workload and accuracy. Cache hits do not consume requests. Failures retry after one hour, with at most three attempts per UTC day. Successful assessments may refresh after expiry. Expired findings are not displayed as current.

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

Fingerprints contain normalized paths, parameter names, actions, methods, sensors and ordered path pairs. Candidate retrieval examines up to 2,000 recently indexed peers, requires at least two shared path/parameter/action features and a Jaccard similarity of 0.6, and returns up to five matches. These are initial retrieval settings, not calibrated attribution probabilities. Matching does not establish maliciousness. Pair review is available; persistent multi-member cluster merging/splitting is not implemented in this release.

## Reporting

Use an existing read-only reporting token with:

* `GET /api/v1/behavior` — indexing, assessment and request counts; explicitly reports inactive AI scoring.
* `GET /api/v1/ips/<ip>/behavior` — current assessment, coverage, sanitized evidence and related activity.

Existing management source restrictions apply. Cookie authentication cannot substitute for a reporting token. No model credentials, raw prompts or unvalidated provider responses are returned.

## Evaluation before enforcement

Review independently labeled legitimate, malicious and borderline traffic. Measure classification precision, false positives, evidence coverage, latency, queue delay, failed outputs and hypothetical threshold crossings. Do not interpret model confidence or feature similarity as calibrated probability. Shared scanners, NAT, proxies and reused public tools require explicit negative examples.

The remaining proposal phases include representative labeled evaluation, an independent-evidence overlap policy, calibrated and bounded scoring promotion, persistent cluster lifecycle, retention cleanup and aggregate evaluation reports. This initial release must not be described as completing those phases or as having activated AI enforcement.
