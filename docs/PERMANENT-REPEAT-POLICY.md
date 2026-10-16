# Permanent repeat-offender policy

A confirmed native block establishes an exact-IP baseline. The policy records
the publication generation, combined-feed SHA-256, native score and normalized
native evidence identifiers. It never starts from AI-only eligibility, a manual
block alone, subnet/ASN/cluster membership alone, or overlapping report windows.
Existing historical reports lack the full baseline provenance this policy needs;
there is no retrospective migration. The next qualifying native publication
starts tracking. Publication and firewall enforcement are separate facts.

Monthly periods are fixed, non-overlapping intervals from that baseline, using
UTC native event time, not ingestion time:

| Period | Native time relative to baseline |
| --- | --- |
| 0 | Before day 30; does not qualify |
| 1 | Day 30 inclusive to day 60 exclusive |
| 2 | Day 60 inclusive to day 90 exclusive |
| 3 | Day 90 inclusive to day 120 exclusive |

Three consecutive qualifying periods earn a permanent block, at the earliest
native event in the third period. Multiple events in one period count once.
For example, days 42, 73 and 108 qualify; days 42, 95 and 125 do not. A missing
period resets the run: after that gap, three new consecutive periods can qualify.
The baseline stays fixed; missing periods are never silently bridged.

Permanent milestones require positively qualified **offenses**, not ordinary
visits or the existing broad native return floor. Source activity alone never
qualifies, even if marked `deterministic_qualifying=True`. The ledger re-reads the
persisted evidence row and requires positive strength, explicit source
qualification, a native record ID, pipeline identity and supported detector
semantics. Missing/ambiguous metadata, explicit nonqualification and arbitrary
source labels abstain. These fields are copied from the worker's existing native
source records; no source routing or source detector behavior is changed.

Supported offense evidence is deliberately conservative:

- Sensor-qualified NGINX sensitive-path probes, WAF interruptions and nonmanual
  CrowdSec ban alerts, with the sensor pipeline and explicit qualifying flag.
- T-Pot Cowrie command/file-transfer behavior or the sensor's failed-login
  detector. Generic Cowrie aggregates qualify only through identified native
  session-connect, authentication-attempt, command or file-transfer samples at
  their own native times. Session bookkeeping, rolling counters and aggregate
  last-seen refreshes do not qualify. Other honeypot formats without supported
  positive attempt semantics abstain; ordinary native scoring remains intact.
- Selected native Wazuh attack/IDS/authentication alerts, retaining their actual
  alert ID, rule ID/level/groups and the existing worker's selection criteria.

Baseline creation requires an actual native publication with qualified offense
evidence too. A previous-block return floor alone, generic evidence or manual
membership cannot establish a permanent-policy baseline. The earliest qualifying
native event per period is retained with its normalized evidence ID, native
record/attempt identity, detector, source, sensor and qualification provenance.
Reused native attempt IDs cannot be moved into later periods by a timestamp or
counter refresh. Earlier representative replacements and earned-date corrections
are audited. No new scoring points or maliciousness inference are introduced.
The original broad native return, score and retention calculations are unchanged.

Out-of-order and late events use their original times and can fill a previously
missing period. Native ingestion still rejects data outside its existing 30-day
horizon; the new policy does not bypass that guard or invent missing history.
Future events cannot earn a milestone. Disabled configured sources cannot qualify.

Palo events are excluded. Existing Palo return/renewal behavior is unchanged, but
its saved return records do not positively attribute a distinct new attempt to a
specific EDL block. Generic drops, repeated polling, AI analysis, confidence
changes and intelligence refreshes never earn monthly milestones. AI storage is
never read by this policy.

Earned IPs enter the actual combined feed even after ordinary evidence, native
retention and one-year reporting history expire. Scores are not inflated to
achieve this. Permanent-only entries remain exact IPs, including adjacent IPs;
the policy never promotes a subnet or ASN. Whitelists and verified crawlers
suppress publication; the existing explicitly requested emergency override
behavior is unchanged. Policy status, baseline, earned date and milestones are
shown in IP details. General rolling-window reports remain separate.

An authenticated administrator can reverse the permanent policy with a required
reason through the existing CSRF-protected session. The reversal is durable and
audited. It prevents automatic re-promotion from replayed **and future** events.
Other native retention or manual blocks may still publish the IP. A whitelist is
the existing way to allow an IP across those independent decisions. No implicit
restart or silent clearing of the administrator's reversal is provided.

`permanent_cases`, `permanent_milestones`, `permanent_event_ids` and `permanent_audit` live in the native
SQLite database and survive routine cleanup. Include that database in normal
backups. Monthly representatives are stored per IP and period; native offense identities
are retained separately to prevent replay from becoming a later milestone.
This durable identity ledger grows with identified qualifying offenses; it is
not a raw packet or credential store and is not deleted by one-year report cleanup. Native ingestion writes milestones in its existing
transaction; a failed transaction rolls back both. The existing publication
request/completion IDs, owner-only maintenance and pending retry are unchanged.
As with other policy changes, the next normal publication updates the served
feed; this does not claim immediate firewall enforcement or Palo acceptance.

Tests simulate native time in disposable databases and Linux publication trees.
No synthetic evidence is inserted into production. Deployment and public release
require independent supervisor QA and explicit authorization.
