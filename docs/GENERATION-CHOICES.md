# Versioned grounded choices

Prompt `behavior-3.11` uses generation schema `grounded-choices-2`. Stored results
remain `behavior-3` and are independently checked by `grounded-observations-4`.
Older assessments, rejections, reviews and labels remain unchanged.

The model selects opaque IDs scoped to the packet, choice kind and complete
offered object. It cannot independently supply a summary, citations, mapping
explanation, limitations or correlation narrative. The server renders exactly
the selected offered objects and then runs the existing full canonical validator.
It does not fill missing support, add observations, reinterpret invalid legacy
payloads, accept unknown IDs or repair a bad classification. A legacy wire object
is invalid under this new protocol, including one that would otherwise be valid
as a stored result. Test-only fixture conversion is never used by runtime code.

Findings select at most two of twelve offered facts. Counterevidence has a
separate packet/kind-scoped table, offering only up to two qualifying fresh
positive-context statements opposing a malicious interpretation. Additional
probes, detector labels, 301/404 responses and absent evidence have no opposing
role. Without positive context, the counterevidence list is empty. Rendering and
the canonical validator reject facts placed in that role or reused on both sides. Mapping selections
retain the existing eligible ATT&CK/D3FEND bounds, with at most two/one selected.
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
to0–1. Inconclusive always remains available. Benign still requires cited positive
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
