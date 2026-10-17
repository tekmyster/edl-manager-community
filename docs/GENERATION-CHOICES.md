# Versioned grounded choices

Prompt `behavior-3.10` uses generation schema `grounded-choices-1`. Stored results
remain `behavior-3` and are independently checked by `grounded-observations-3`.
Older assessments, rejections, reviews and labels remain unchanged.

The model selects opaque IDs scoped to the packet, choice kind and complete
offered object. It cannot independently supply a summary, citations, mapping
explanation, limitations or correlation narrative. The server renders exactly
the selected offered objects and then runs the existing full canonical validator.
It does not fill missing support, add observations, reinterpret invalid legacy
payloads, accept unknown IDs or repair a bad classification. A legacy wire object
is invalid under this new protocol, including one that would otherwise be valid
as a stored result. Test-only fixture conversion is never used by runtime code.

Findings and contradictions select at most two of twelve facts. Mapping selections
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
streaming timing, request/attempt persistence, usage accounting, Unlimited,
native/scoring and edition controls remain unchanged. Candidates are omitted
when necessary to fit the input budget, with supplied-window metadata reflecting
the actual input. No raw provider text or rejected selection values enter error
diagnostics; only fixed reason/category/field/index values are retained.
