# Derived AI retention and performance

This implementation is available for review before deployment. It does not change
native scoring, evidence retention, publication, qualified permanent-offense IDs,
replay protection, pilot eligibility, whitelist/crawler protections or daily quotas.
Wazuh remains an input; EDL Manager owns scoring. Community AI remains disabled by
default. The separate AI Receptionist is outside this implementation.

## Retention policy

Analysis limits on Behavioral intelligence configure saved observations, expired
assessments and operational metrics independently: 90 days by default, 30–3,650
days supported. Cleanup scans 100 candidates per table per enabled worker pass
(configurable 1–500). It never opens the native database. The existing redacted
event-history cache keeps its separate 30-day policy and 5,000-row cleanup limit.

Current packets, unexpired assessments, retained assessment input/output packet
references, pending queued packets and live job leases prevent packet removal.
Reviewed accepted **and rejected** relationships, reviews, current group members,
all historical group revisions and their immutable packet citations are preserved.
Groups/revisions have no automatic expiration because they represent saved review
history. A packet's feature indexes and correlation diagnostics are removed only
with that packet; proposed links and their stored evidence expire together.

Use **Keep for investigation** on a saved observation before expiration to preserve
it and its assessments. The hold is permanent and requires a reason; no public
unpin endpoint is provided. Administrators can also use
`behavior_retention.hold(brain, kind, id, reason)` for packet, assessment or link
holds. Ordinary browser bookmarks are not visible to the server and do not pin
data. Reviewed/grouped references are automatic; unheld expired observations may
return 404. An assessment hold keeps all its indexed packet references; a link
hold keeps its endpoints and immutable relationship evidence.

Reference indexes are populated by insert/delete triggers for new immutable rows.
Legacy assessments and revisions are backfilled in restartable bounded chunks;
no retention deletion starts before both backfills finish. Malformed legacy JSON
fails closed. Date/ID sweep cursors advance past protected pages rather than
repeatedly scanning the oldest pinned rows. Deletions, dependent indexes and cursor
updates commit together; interruptions roll back and the next pass resumes.
The current UTC usage day is never pruned. Retention settings do not invalidate
the model cache. Changing a retention period cannot restore deleted information.

This is an age policy with reference exemptions, not an absolute disk-size cap.
Current addresses and retained investigations can grow without expiration. Cleanup
frees SQLite pages for reuse; it does not shrink the filesystem file. No automatic
VACUUM, forced WAL truncation, production fixtures or timer pauses are introduced.
Back up both databases consistently before deployment; retain the original source
archive and database backup for rollback. Schema additions are additive and older
code ignores them. Restoring older code alone does not restore expired data.

## Scheduling and resource bounds

Half an indexing batch prioritizes new addresses or native event times newer than
the current packet; the remaining slots keep the existing round-robin sweep.
Same-timestamp counter/context changes are eventually revisited by that sweep.
The inference queue is separate: oldest first, at most one latest pending packet
per address, up to 10,000 addresses, at most 100 entries examined and two actual
model attempts per pass. Replacing queued evidence retains its original queue age.
When full, new entries wait for a later indexing pass; native ingestion continues.
Current packet pointers refresh pending content before dispatch. Empty packets
are not queued. Queued windows without any in-window event expire without a
model request. Index-only mode may prepare a queue but never dispatches it.

Quota exhaustion stops model dispatch for that pass; it does not clear pending
work or reset the UTC budget. Cached/leased entries do not consume request slots.
Provider failures use persisted endpoint/model-specific exponential backoff from
60 seconds to 15 minutes, while existing per-packet cache/retry checks remain.
Completed inference clears that provider's backoff. The worker remains separate
and single-flight, with its existing timeout, CPU, memory and process restrictions.
No inference is added to native ingestion or atomic publication. The overview
shows pending count and oldest enqueue time; quota is a real throughput limit,
and a growing backlog must not be presented as prompt inspection.

## Measurement

Run `python benchmarks/retention_performance.py` on Linux with application
dependencies. It creates temporary databases and does not contact sensors, the
model, origin or firewall. It measures 10,000 packet/index/link inserts, 100 indexed
retrievals, bounded cleanup/reusable pages, the actual durable scheduler using an
explicit 10 ms terminal-failure stub, and real native event-to-atomic-local-list
publication across 30 offline events. Membership checks understand CIDR coverage.
The service stub creates no assessment/verdict; its queue times exclude the real
timer interval and are not small-GPU performance.

Production observations must remain separate. Retained legacy request wall times
and output tokens per wall second do not establish current-prompt sustained GPU
throughput, GPU generation speed, memory use, accuracy or reliability. Packet
preparation-to-request-start estimates have timestamp precision and reuse bias.
Native event-time-to-recorded-list-transition intervals include upstream clock,
retention and backfill ambiguity; they are not detector-arrival-to-firewall latency.
Origin sync/firewall fetch/drop latency requires separate authentic evidence.

At the initial read-only observation, the daily quota remained exhausted and no behavior-3.4
inference had occurred. Observe a natural quota reset when available; never reset
or override it or manufacture telemetry, verdicts, threshold crossings or labels.
Current-prompt sustained GPU/tokenization/memory/reliability measurement remains
an explicit dependency. Browser visual/focus/narrow-screen redesign debt remains
separate; server-rendered controls alone do not establish visual acceptance.
