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

Qualifying inputs are native evidence and native source activity from T-Pot,
OWAPot, NGINX, WAF, CrowdSec and Wazuh for the same previously blocked exact IP.
As in the existing native return policy, a new native visit can be a repeat even
when it is ordinary NGINX activity. This is an administrator policy about repeated
native observations after a block, not a new maliciousness or actor attribution
claim. Existing native scoring and retention calculations are unchanged.

The ledger retains one earliest representative event per period, its normalized
identifier, source, sensor, event time and record type. It audits replacement by
earlier evidence and earned-date corrections. Source activity IDs deterministically
identify IP/source/sensor/native time; collection refresh metadata is excluded.
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

`permanent_cases`, `permanent_milestones` and `permanent_audit` live in the native
SQLite database and survive routine cleanup. Include that database in normal
backups. Monthly representatives bound storage by IP and elapsed monthly period,
rather than by packet count. Native ingestion writes milestones in its existing
transaction; a failed transaction rolls back both. The existing publication
request/completion IDs, owner-only maintenance and pending retry are unchanged.
As with other policy changes, the next normal publication updates the served
feed; this does not claim immediate firewall enforcement or Palo acceptance.

Tests simulate native time in disposable databases and Linux publication trees.
No synthetic evidence is inserted into production. Deployment and public release
require independent supervisor QA and explicit authorization.
