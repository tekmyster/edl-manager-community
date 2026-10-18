# Portable source observations

`source_observations.py` defines the optional `source-observations-1` metadata
contract shared by both editions. Existing sources without it remain supported.
Metadata is additive: original sample IDs, event timestamps, destinations and
ports retain their meaning and the historical event ID formula is unchanged.
Historical assessments and rejection records are never rewritten.

Cached observations and packet assembly share the same merge semantics. Missing
optional connection bindings and incomplete lookup coverage mean unknown; they
do not contradict an otherwise identical verified report. Contradictory source,
collector, session, semantics, original time/target or connection IDs still fail
closed. A complete full-window zero/multiple-connection receipt invalidates an
older unique binding, including cached siblings omitted from the latest sample
batch. Known session reuse cannot become unique through partial or older copies.
Neither successful query transport nor a sampled connection asserts uniqueness.

An optional `source-connection-proof-1` receipt records the exact original ID and
source-field hash, hashed collector/source/session scope, declared 30-day bounds,
check time, full original connection count and unique connection ID/hash where
applicable. Scope, field types, original ID/time and privacy are validated. No raw
commands, download URLs or session values enter this receipt. `lookup_status`
distinguishes complete, not-selected, partial and error. A retained older receipt
keeps its original check time; a recheck does not refresh native event time.

Existing generic conflict marks remain closed automatically. The explicit
`source_binding_recovery.recovery()` operation defaults to a dry run and reads no
model result. It requires fresh complete receipts for the original event and
connection, matching immutable packet anchor bytes, original scope/time/target,
no disputed origin copies or recorded contrary session evidence, an independent
review reference, and an exact plan hash plus reviewer identity before apply.
Only the derived metadata changes. Original packets, assessments, labels,
feedback, source counters and native scores/retention are never rewritten.

Latest complete receipts and conflict/recovery audits live in derived history.
Audit updates are rejected, and deletion is rejected while corresponding history
or receipt is retained. Existing 30-day history expiry removes orphan receipts
and audits in batches of at most 5,000; this creates no indefinite identity ledger.
Hard disputes and indexed exact-original lookups remain scoped by source, sensor,
address and configured collection. No broad cache reset or automatic legacy
recovery is performed by deployment. A recovery plan is not an authorization to
apply it; operators review the original-source proof first.

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
| `connection_count` | `1` only for a complete unique original connection; a complete zero/multiple result explicitly disqualifies the binding |
| `lookup_status` | `complete`, `not_selected`, `partial` or `error`; unknown detail cannot erase compatible verified evidence |
| `binding_proof` | Validated original-record/full-window receipt described above; optional for legacy producers |

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

`grounded-observations-3` / `behavior-3.9` added fixed grounding rejection reasons,
schema field paths and zero-based array indexes where applicable. Diagnostics
retain no rejected text, labels, citation values or exception messages. Invalid
assessments remain failed; no partial verdict is salvaged. Old generic rejection
records cannot reveal a precise rejected field retrospectively. Diagnose future
natural failures before proposing generation changes; do not force model calls.

The Private lab adapter is intentionally excluded from Community. Integrators
must implement their own bounded, authenticated source reads and may use the
portable contract without that adapter. Changes here do not establish ground
truth, calibrate confidence or change native scoring, retention or enforcement.

The staged `behavior-3.10` generation protocol selects scoped offered objects
without copying text/citations; see [generation choices](GENERATION-CHOICES.md).

Native sample delivery uses a local transactional handoff. Each distinct
normalized sample revision is retained in `source_sample_handoff` in the same
native SQLite transaction as `source_activity`, before later bounded bucket
snapshots can replace that row. The handoff stores the existing redacted event
allowlist and configured collection-scope hash; no raw commands, sessions,
credentials, query values or new source queries are introduced. Original event
time and the first actual local receipt are separate. Counters, native scores,
retention and source attribution remain on their existing paths.

The handoff commits at most 500 revisions per transaction. It commits
history, source receipts, an idempotency ledger and packet-readiness revisions
together, then acknowledges only those exact native revisions. A busy or
unavailable derived store cannot block native ingestion. A crash before native
acknowledgement safely replays already committed revisions. Complete nonunique
receipts still invalidate cached siblings even when later native subsets omit
the file; no legacy conflict is automatically recovered.

Readiness uses a separate real content revision, not a rewritten event timestamp.
Eligible changed addresses use the existing half-batch priority allocation;
normal round-robin slots, packet bounds, inference guards and Unlimited settings
are unchanged. Readiness is cleared only for the revision successfully indexed,
so a concurrent newer delivery remains pending. Handoff and delivery bookkeeping
expire on original event time after 30 days, with at most 5,000 deletions per
cleanup. This retains ingested sampled reports; it does not turn upstream
summaries into a complete raw event archive or recover reports never ingested.

Delivery runs independently of serial model work in a thread inside the existing
behavior process. Each transaction still reads at most 500 rows, but a successful
nonempty transaction immediately proceeds to the next; there is no per-cycle
delivery quota. Only empty/unavailable storage waits. Cancellation rolls back an
unfinished transaction; an already committed batch can replay safely before its
native acknowledgement. One-shot behavior invocations finish their pending
delivery before exiting, unless cancelled or storage is busy. Behavior Off stays
Off, and model enablement, budgets, inference guards and ordinary packet-indexing
fairness are unchanged. No extra service, timer or collector query is introduced.

For an identical coherent unique full proof, `complete` versus `not_selected`
describes the current selection, not new source evidence. The handoff recognizes
these aliases while retaining the first actual body/receipt. A derived semantic
ledger also prevents redundant merges/readiness when older queued aliases are
delivered. Existing native rows remain intact and receive exact individual
acknowledgements. Genuine proof checked times/windows, hashes, original IDs,
scope, targets, counts and other fields remain part of the revision identity.
Partial/error reports and nonunique/missing-connection proofs are never coalesced
by this rule. All ledgers expire on original event age using bounded cleanup.
