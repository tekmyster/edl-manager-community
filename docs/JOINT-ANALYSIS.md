# Joint behavioral assessment contract

Prompt 3.30 uses **one model request per new assessment**. It selects optional source accounts, fixed observation purposes, verdict, mappings and relationship hypotheses together. A legal omission or a structurally valid result does not establish useful analysis. This implementation has no model acceptance or release approval.

The generation contract is `joint-keyed-purpose-1`. The canonical stored result remains `behavior-3`, preserving complete fixed statements, citations, source tuples, roles, support policy and uncertainty. Prompt, schema, source, configuration and exact input identities distinguish these results from old assessments. A historical result is never silently reinterpreted under the new contract.

## Input and selections

Each observation key has one optional value: `omit`, `detail`, `support`, or qualifying `counterevidence` where originally allowed. Missing keys omit. Detail and support copy the same complete original finding and citations; support does not strengthen the reported fact. Counterevidence must be the offered fresh positive opposing context. Duplicate JSON keys, conflicting roles, unknown references, old nested rationale objects and extra fields reject the response. No rationale placeholder, output repair, deduplication, usefulness filter or forced support is used.

Source groups remain optional model selections. All groups may be omitted, and all generic fixed statements remain legal. Selecting a group never supplies scoring support. Malicious eligibility still needs the original complete support pair in findings; it never forces a verdict. Benign requires cited fresh positive context. Unknown intent or automation remains unknown with confidence zero. Input does not establish execution, file capture does not establish network transfer, and firewall drops do not independently establish attacks. EDL Manager retains scoring and enforcement ownership.

Whole repeated string values may be represented by explicit dictionary references. Literal objects shaped like reference markers are escaped. Recursive expansion recovers every original value and type; keys and all complete packet, event, context, history, candidate, offer, role and uncertainty data are retained. No candidate-dropping fallback is used to make an input fit. The complete original synthesis policy is retained. Reference factoring and instruction factoring can still affect model behavior; lossless representation is not evidence of equal interpretation or improved quality.

An immutable plan binds one exact request and the source/configuration/tokenizer identity. Verified token accounting reserves 1,800 output tokens plus one EOS spare under an 8,192-token context. Missing metadata, mismatched identities or oversized complete inputs stop before quota or dispatch. No output allowance is reduced, and a length-terminated response cannot be salvaged or retried. Configure the existing operator-pinned tokenizer metadata file and hash; runtime never queries metadata or downloads assets automatically.

## Deadline, ownership and quota

The existing configurable assessment timeout, at most 180 seconds, covers preparation, admission, connection, streaming, parsing, validation, capture and accepted-result finalization. It is not reset for another request. At the existing 180-second setting, the admission allowance remains 15 seconds within that same deadline. Cancellation closes watched I/O and fences late completions.

One short FULL-sync SQLite transaction reserves one request unit. Exactly one child can be claimed and entered. Claims commit before transport; no writer remains held across generation. Enabled state, configuration, source files, packet, registry, tokenizer, request bytes, lease, day and budget are rechecked at the existing claim/entry/dispatch/finalization boundaries. A claimed unit is retained even when receipt or dispatch is uncertain. Missing token counters or a lost connection do not prove a free request.

The state path is ready, claimed, entered, durable final pending, then completed. Failed, uncertain and review outcomes do not authorize another inference for that spent assessment. A durable completed result may be saved after a transient persistence failure without calling the model again. The normal finite two-request-per-pass limit now permits two single-request assessments when quota allows; daily limits, Unlimited configuration, cancellation and provider backoff retain their existing meaning.

## Versioned recovery

Ledger schema version 2 records an explicit topology. Existing schema-version-1 plans retain `account-then-selection-1`, both original child rows, receipts, charged usage and durable outcome bytes. Migration atomically fences interrupted old generation as uncertain and releases only unconsumed reservations. Unresolved old plans prevent new generation pending review. An old durable final-pending result can still be persisted in its original format. Old stage 2 is never resumed or converted into a new one-request assessment. Unknown schema versions require review rather than reinitialization.

The historical [two-stage contract](TWO-STAGE-ANALYSIS.md) documents those old records; it is not a fallback execution path.

## Private request evidence and accounting

Each new plan retains bounded raw response evidence and immutable request/receipt snapshots in the private sibling `.request-evidence` directory beside its derived behavior database. The existing response-size limit remains in force; an unread or oversized tail stays explicitly unknown. File writes use exclusive creation, restrictive permissions and durable flush. Credentials, authorization headers and private provider configuration are never captured.

A successful raw close/snapshot is required before accepted-result publication. A `validated` sidecar is a validation receipt, not proof of a committed assessment; acceptance is determined separately by the durable plan and assessment transaction. Snapshot, close, stream or deadline failures cannot publish a completed assessment. Partial or rejected raw output remains private evidence, never repaired into findings. On timeout or cancellation, the controller takes an immutable in-memory failure snapshot and attempts private publication asynchronously. Until that write completes, metadata explicitly reports publication as incomplete; no file hash or accepted result is claimed. A stalled journal save returns deferred only for an already durable outcome. Recovery persists those original bytes without another inference; permanent persistence errors still require review.

Reported counters are validated as integers with provenance, conflict and missingness retained in private as-of reports. Known metadata or captured terminal counters do not become unknown merely because an artifact publication is late. Preparation estimates are never billing reports. Conflicting counts remain unknown; dollar charges remain unknown. Public assessment metadata contains bounded counter summaries and opaque evidence references, not rejected raw content or invalid counter strings.

An explicit operator reconciliation through `behavior_accounting.reconcile` appends a supplemental accounting file. It binds the original outcome hash and adds zero attempts, zero accepted outputs and no deadline extension. It does not rewrite the original outcome, assessment, claims or quota. Late callbacks may append metadata only; they cannot change accepted state.

Evidence follows the existing assessment-retention decision. Completed/failed evidence is eligible for bounded filesystem cleanup only after its expired assessment has been removed and the plan compacted to a permanent consumed tombstone. Holds and retained assessments keep their evidence. Pending, review and uncertain evidence remain for investigation. File cleanup occurs outside the database writer transaction and checks the private resolved root before removal.

## Verification limits

Both editions require offline contract, accounting, migration/recovery, concurrency, cancellation, deadline and ordinary regression tests. Frozen source-first controls, full input reconstruction, exact request hashes and token reservations must be independently checked. The full protected 21-case/42-pair model gates remain unchanged: all original useful accounts, neutral and HTTP controls, eight typed timing/syntax findings, and strict reduction in each locked noise cell with no fresh generic regression.

The unchanged 3.28 legacy baseline cannot reserve the full output allowance in 14 of 21 cases per edition. It remains a limited historical comparison arm. Any context-corrected baseline requires separate review and identity. Input fit, fewer requests and synthetic reachability are not semantic gains. Native compiled grammar behavior, full output completion and actual model usefulness require separately authorized evaluation; this document authorizes no inference, deployment or enforcement.
