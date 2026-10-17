# Portable source observations

`source_observations.py` defines the optional `source-observations-1` metadata
contract shared by both editions. Existing sources without it remain supported.
Metadata is additive: original sample IDs, event timestamps, destinations and
ports retain their meaning and the historical event ID formula is unchanged.
Historical assessments and rejection records are never rewritten.

Collectors may attach `source_observation` to a sampled event:

| Field | Meaning |
| --- | --- |
| `version` | Literal `source-observations-1` |
| `collector_ref` | SHA-256 of a stable local collector namespace |
| `source_ref` | SHA-256 of the canonical source IP |
| `session_ref` | SHA-256 of collector reference, source reference and local session ID, separated by `\|` |
| `semantic` | Fixed category: `connection`, `shell_input`, `interactive_input`, `file_capture`, `file_event`, `network_fetch` |
| `syntax_categories` | Optional fixed lexical categories: `permission_change`, `output_redirection`, `interpreter_input`, `relative_execution`, `network_client_input` |
| `connection_id` | Exact original connection record ID, never the most recent connection for an IP |
| `connection_count` | Integer `1`, only after an untruncated full-lookback query finds exactly one original connection for this source/session |

Use `metadata()` and `sanitize()` rather than forwarding arbitrary fields. Never
export raw session IDs, commands, credentials, file contents, artifact paths or
download URLs. Hash references are linkage pseudonyms, not proof of identity.
The original connection must be co-included with original-record provenance,
known target and port. Collector/source/session/stream, source and sensor must
match; activity must follow that connection by at most 15 minutes. Missing,
conflicting or reused-session records abstain. Derived linkage never fills in
the original activity record's destination or changes its historical ID.

Cowrie `command.input` reports input, not successful execution. A realm marks
interactive consumer input. `file_download` alone does not establish network
transfer: Cowrie also uses it for stdin and redirect captures and some input
events. An artifact digest supports the fixed capture category; a recognized
network URL plus digest supports a reported fetch category. Only that explicit
fetch category can offer T1105. Digest and URL values stay local. Lexical input
categories are bounded to 4,096 characters and never execute input; they are
partial syntax observations, not a shell emulator or proof of malicious intent.
An interpretation requires distinct supported staging input and capture reports
bound to the same original connection, with all three original events cited.
Abstention is always allowed; source reports may be wrong or incomplete.

Packet selection prefers bounded complete linkage groups and retains the existing
160-event and 11,200-byte packet bounds, 18,000-byte model input bound, 12-fact,
24-signal and six-support-bundle bounds. These bound evidence size and work;
Unlimited inference has no daily or per-cycle request-count ceiling.

`grounded-observations-3` / `behavior-3.9` adds fixed grounding rejection reasons,
schema field paths and zero-based array indexes where applicable. Diagnostics
retain no rejected text, labels, citation values or exception messages. Invalid
assessments remain failed; no partial verdict is salvaged. Old generic rejection
records cannot reveal a precise rejected field retrospectively. Diagnose future
natural failures before proposing generation changes; do not force model calls.

The Private lab adapter is intentionally excluded from Community. Integrators
must implement their own bounded, authenticated source reads and may use the
portable contract without that adapter. Changes here do not establish ground
truth, calibrate confidence or change native scoring, retention or enforcement.
