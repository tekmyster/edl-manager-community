# Versioned grounded choices

The offline candidate is prompt `behavior-3.28`, wire `grounded-groups-12`.
It has no new model results and is not deployed. The failed 3.27 run had
42/42 valid candidate outputs, but added generic findings in cases 3 and 19
both rounds and failed the locked case 8 round 2 reduction. Six comparisons
contain 504 attempts, 496 accepted and eight rejected; this is not accuracy.

Each optional observation ID now selects an object with `reason` followed by
`purpose`. The reason briefly explains what the complete fixed statement adds
to selected rendered accounts or the verdict. It is at most 96 characters;
non-omitted choices require nonblank text. Missing keys, an empty object, and
explicit `omit` remain legal abstention. Detail/support/counterevidence purposes
and eligibility are unchanged. Canonical `allowed_roles` metadata still describes
finding/counterevidence roles, while the wire schema names the purposes.

This changes the generated decision contract from an unexplained purpose label
to an explicit comparison. It does not score reasons for usefulness or truth.
A bad reason and a noisy legal selection still emit the entire offered statement
and ordered citations. A reason cannot add evidence, provide missing support,
change a group account, override a validator, or alter policy/scoring. It is
untrusted generation-only text, discarded before canonical validation/storage
and never displayed in the UI or copied to diagnostics. Evaluation tools may
retain the actual raw response separately. No narrative factual output is added.

All offered IDs/statements, source records, history, positive context, support
pairs, typed input/capture timing and caveats remain intact. There is no utility
filter, hidden cap, selection repair, deduplication, retry, forced support or
withheld offer. Nested/repeated JSON keys reject before overwrite; unknown IDs,
old scalar/array wires and invalid reasons reject without repair. Stored
`behavior-3` assessments remain unchanged. Prompt/wire version changes isolate
cache/job identity without replaying pending or historical jobs.

The model, temperature 0, 8192 context, 1800 output tokens and 18,000-byte user
bound are unchanged. Reasons enlarge the schema and possible output. Full
request bytes are measured separately from user bytes; neither proves token
fit or latency. Output truncation remains a rejection, with no retry. Synthetic
compatibility, passing tests and rationale fluency cannot establish selection
utility. Independent manager QA and a fresh grant are required before a real
comparison. All existing locked semantic gates and historical rejections remain.

## Prior 3.27 contract (historical)


The local offline candidate uses prompt `behavior-3.27` and generation
`grounded-groups-11`. It is untested with new model responses and is not deployed.
The failed 3.26 comparison retained five strict duplicate-ID rejections, generic
label regressions and missing explicit capture intervals; those outputs and
rejections remain historical evidence. No runtime conversion or retry is added.

`observations` maps an offered ID to a contribution purpose. The object may be
empty; missing keys and `omit` select nothing. `detail` selects a fixed statement
for concrete detail beyond selected group accounts. `support` selects that same
complete statement as cited support for the chosen verdict. Both emit a finding;
neither is verified usefulness or a stronger source claim. `counterevidence` is
available only for the same qualifying positive-context identities as before.
Original `allowed_roles` metadata describes canonical roles; the new wire uses
purposes for selection. Every offered statement, original ordered citation,
role, support pair, context and history remains available. No generic-label
postfilter, withheld offer, smaller cap, forced finding or automatic support is
introduced. A bad legal selection remains visible for semantic review.

Keys give each offered observation one exclusive contribution. Strict raw JSON
parsing rejects repeated keys, including escaped equivalents and cross-role
repeats, before decoding; it never keeps the last value. Old `finding` values,
arrays, old versions, hybrids and unknown fields reject. All selected statements
are copied exactly in emitted key order. The maximum remains twelve combined
observations, twelve ATT&CK and six D3FEND mappings. Malicious support, benign
positive context and synthesis positive-visibility validation are unchanged.

Group-first synthesis remains optional. The general linked-session account now
states capture time after both input and connection, computed from the validated
source tuples, alongside shell-input timing, syntax, original times/citations and
execution/transfer/payload/authorization caveats. This is deterministic source
presentation, not new model reasoning. No finding is forced or postfilled.
Group identities/tuples and canonical compact summaries do not change; historical
stored objects are not rewritten. Valid old groups receive the more explicit
read-only disclosure account. Invalid links do not gain an account.

The prompt asks for a comparison of the fixed statement with the selected group
account, then a contribution purpose. This differs from container-only changes,
but still relies on model judgment: a purpose enum cannot prove usefulness.
Actual noise reduction and all locked explicit-detail/control gates require a
separately reviewed and authorized comparison followed by independent semantic
QA. There is no claim of model root cause, calibrated accuracy or runtime gain.

The stable offered-ID namespace remains `grounded-groups-9`; storage remains
`behavior-3`, grounding `grounded-observations-5`, synthesis `observable-groups-2`.
Both prompt/generation versions isolate new cache/job identities. No assessment
migration, pending dispatch replay, requeue, scoring/eligibility/default/privacy
change, additional inference pass or deployment is authorized. The existing
18,000-byte user bound, qwen2.5:3b 8192 context/1800 output and temperature0 remain.
Measured request bytes are representation costs, not tokens or effective fit.

## Historical contracts

The following retained notes describe earlier versions, not the current array
wire format or authorization to deploy it.

Prompt `behavior-3.14` uses generation schema `grounded-choices-5`. Stored results
remain `behavior-3` and are independently checked by `grounded-observations-5`.
Older assessments, rejections, reviews and labels remain unchanged.

The model selects opaque IDs scoped to the packet, choice kind and complete
offered object. It cannot independently supply a summary, citations, mapping
explanation, limitations or correlation narrative. The server renders exactly
the selected offered objects and then runs the existing full canonical validator.
It does not fill missing support, add observations, reinterpret invalid legacy
payloads, accept unknown IDs or repair a bad classification. A legacy wire object
is invalid under this new protocol, including one that would otherwise be valid
as a stored result. Test-only fixture conversion is never used by runtime code.

Each of at most twelve observations has one required keyed decision slot:
`omit`, `finding`, or (for qualifying fresh positive context only)
`counterevidence`. A positive observation has one identity and one role slot,
not separate aliases for both sides. Every offered observation may occupy its
allowed role: combined findings and counterevidence cannot exceed the twelve
unique offered slots. Counterevidence still
opposes a malicious interpretation using only qualifying positive context. Additional
probes, detector labels, 301/404 responses and absent evidence have no opposing
role. Without positive context, the counterevidence list is empty. Rendering and
the canonical validator reject facts placed in that role or reused on both sides. Mappings have one required `omit`/`include` slot per offered mapping. They
retain existing eligible ATT&CK/D3FEND bounds of twelve/six. All offered entries
may be included once. Zero included mappings is valid.
One correlation may select an offered current/historical pair and confidence.
Pair construction examines at most eight current and eight historical reports
for one candidate (64 comparisons), offers at most eight supported pairs and
exposes partial coverage. Current evidence is taken from the actual packet;
historical choices require an actual shared observable feature, distinct event
IDs, the supplied candidate and both original citations. Shared behavior does
not identify a person or imply collaboration or enforcement inheritance.

Automation and intent are arrays with zero or one selected hypothesis. An empty
array explicitly means unknown with confidence zero. A nonempty array must select
an offered known label and a bounded confidence. There is no valid wire
representation of unknown with nonzero confidence: supplying one is rejected,
never silently zeroed. Maliciousness confidence remains uncalibrated and bounded
to0Ã¢â‚¬â€œ1. Inconclusive always remains available. Benign still requires cited positive
fresh context; malicious still requires a complete source-supported findings
bundle. Missing support and unsupported conclusions reject the entire assessment.

The system requests compact JSON rather than copying text. Scoped fact/mapping
IDs remove the text/citation and explanation mismatches demonstrated in the
natural `behavior-3.9` cohort. That cohort contained five completed inconclusive
outputs and seven rejections among twelve attempts; it is a small convenience
sample, not an accuracy estimate. Rejected provider text was not retained, so
precise retrospective provider wording is unknown. This change addresses the
demonstrated contract surface; actual small-model reliability and useful
interpretation under the new protocol require natural observations after QA and
deployment, not synthetic success claims or forced model calls.

The 18,000-byte input check, 8,192 context, 1,800 output-token bound, measured
streaming timing, usage accounting, Unlimited,
native/scoring and edition controls remain unchanged. Candidates are omitted
when necessary to fit the input budget, with supplied-window metadata reflecting
the actual input. No raw provider text or rejected selection values enter error
diagnostics; only fixed reason/category/field/index values are retained.

The deployed3.10 cohort independently passed121canonical/offer checks with zero
rejections but only four findings assessments; two misused probe observations as
contradictions. This version tightens evidence roles rather than asserting useful
or correct interpretation from protocol success. Earlier saved assessments are
not relabelled or rewritten. The choice-version boundary rejects the old wire;
it never converts unsupported old outputs. New natural reliability and semantic
usefulness remain unmeasured until separately reviewed after deployment.


The observed3.11 convenience window had31completed and6rejected assessments:
two repeated ATT&CK selections and four observations used on both sides. Old
arrays could repeat a single eligible ID, and separate positive-context aliases
could select the same claim in both roles. Version3removes those repeated slots.
A strict inner JSON parser also rejects duplicate object members, including
escaped equivalent keys, before Python can silently keep the last occurrence.
Unknown/missing/foreign fields, invalid roles and old
wire versions reject. No invalid stored result is converted, deduplicated,
filtered, retried or rewritten. Canonical classification, role, provenance and
support checks remain mandatory and unchanged.

All-omit observations/mappings and empty hypothesis/relation arrays are honest
empty output. Required decision slots do not require any included claim. Sparse
findings may reflect limited source detail or a model selecting no offered fact;
protocol validity does not establish which, useful interpretation or accuracy.
New natural model reliability under these slots remains unmeasured at staging.

The independently checked deployed 3.12 window contained thirteen assessments:
six completed (all inconclusive, one with generic findings) and seven rejected
for selection counts (five findings, two D3FEND). The keyed schema could express
more selections than the decoder's two-finding/one-D3FEND presentation cap. Those
caps were narrower than the canonical twelve-item arrays and the source offer
bounds. Version 4 removes that mismatch: all unique keyed assignments are count
safe, and every included offered object is rendered without clipping,
deduplication or salvage. Offer construction fails closed if its existing source
bounds regress. Maximum counts are twelve combined observations, twelve ATT&CK
and six D3FEND entries; no evidence input or taxonomy coverage was enlarged.
Every classification, source binding, role and canonical validation still runs.
An all-included response can still fail semantic checks. Count validity does not
force a finding, mapping or verdict and does not establish useful interpretation.
The unchanged output-token limit still rejects a truncated response in full.

Completed but rejected content (`invalid_assessment`, or a complete response
ending at `output_limit`) retains a failed assessment, one-hour failed cache and
three-attempt daily per-configuration retry bound. It does not create or extend
endpoint/model-wide backoff or stop unrelated eligible work. Any existing guard
remains unchanged on rejection; an active guard is checked before dispatch.
Successful inference retains the existing guard reset. Transport failures,
timeouts, non-200 provider responses (including rate limits), incomplete streams
and other errors retain the global exponential backoff (up to 900 seconds).
No automatic immediate retry or rejected-output repair is introduced.

The genuine coherent packet's original bytes and source time remain preserved.
Supervisor observed that a naturally indexed newer window superseded it; that
window had lower richness and was queued, with no new interpretation claimed.
Preserving useful session context across such windows remains an open dependency,
along with independently labelled accuracy, calibration and usefulness.

Version 5 makes already-collected honeypot metadata visible in fixed source
facts: allowlisted shell-input syntax categories and elapsed time from an
unambiguous cited connection in the same source session. It never exposes command
text, raw sessions, file names, URLs, hashes, credentials or payloads. At most five
fixed category labels are possible; missing/malformed metadata stays unavailable.
The syntax parser now also fails closed for malformed source category values;
valid existing sufficiency features and all classification guards are unchanged.
The elapsed interval is derived from original aware timestamps through the
existing unique session resolver (same stream, target/port and <=15 minutes).
Missing, reused or conflicting links do not create a time/session claim.

These are source reports of syntax and linkage, not execution, maliciousness,
authorization, successful transfer or operator identity. Fact counts/citations,
support bundles, offer bounds and model input/context/output limits are preserved.
No NetFlow/IRC adapter, invented detector action or broadened verdict eligibility
is added. The external CTU input-only pilot remains inadequate for current
positive-discrimination testing; no inference is authorized merely by this text
repair. Authentic saved honeypot before/after offers support representation QA,
not independent attack labels or useful-model conclusions. Older stored outputs
remain immutable historical results; new prompt/choice/grounding versions isolate
the new contract without revalidating or rewriting old history.
