# Local managed IP context

`misp_feed_sync.py` is an opt-in operator utility. It does not run by default,
change firewall configuration, or export indicators to a firewall list.
Manager enriches IPs already observed locally; moving a direct firewall feed to
this workflow changes enforcement semantics. Every imported indicator has
`to_ids=false` and contributes zero intelligence points. Existing native scoring,
whitelists, crawler protections and other actionable MISP feeds retain their policy.

Use an operator-owned JSON configuration outside the repository:

```json
{
  "sources": [{
    "id": "example",
    "name": "Example IP context",
    "provider": "Example provider",
    "url": "https://example.org/ips.txt",
    "ttl_hours": 48,
    "allow_empty": false,
    "optional": false
  }]
}
```

Stage and inspect with `python3 misp_feed_sync.py --config CONFIG --output STATE`.
Only adding `--import --container MISP_CONTAINER` invokes the native Cake shell.
The sibling `MispManagedFeedShell.php` must accompany the utility. Docker access
and an existing local MISP administrator are required; no users, keys, sync servers
or global settings are created. MISP must already have the intended native
warninglists enabled. Imports use organisation-only distribution and remain
unpublished. Native MISP may represent attribute distribution as inherited from
the organisation-only event.

For a read-only model preflight, stage files under MISP's
`app/tmp/managed-ip-context`, make them readable to the MISP application user and
invoke `cake MispManagedFeed PATH_TO_STATUS dry-run`. This checks native models,
ownership, duplicates, source states, sharing policy and projected volume without
saving feeds or events. `import_ready=false` reports missing warninglists.
Do not interpret a dry run as proof that native event imports succeeded.

Source files are bounded to 8 MB and 50,000 unique entries each. Strict IP/CIDR
validation rejects nonpublic space, HTML and malformed lines. Ranges become an
equivalent set of CIDRs without expanding individual hosts. Comment-only feeds
are accepted as `healthy_empty` only with `allow_empty=true`; unavailable feeds
never become successful empty feeds. Optional unavailable sources remain visible
and disabled in MISP. Their retirement requires a separately documented decision.
Source IDs and URLs must stay paired; rename/removal requires explicit retirement
of the old managed event, otherwise its attributes would remain active.

Per-source health records preserve URL, collection time, transport metadata and
raw/canonical hashes. Collection time is explicitly distinguished from an unknown
native observation time. Stable source/indicator UUIDs avoid duplicate imports.
Only attributes missing from that source's event are revoked. Existing unrelated
events and indicators are outside this utility's reconciliation scope.

Schedule one serialized hourly invocation (for example with a systemd timer and
`flock`), retaining STATE between invocations. On a fetch failure, the last good
snapshot retains its original timestamps and provenance until its configured TTL;
at expiry the importer revokes that source's attributes. Required fetch failures
return a nonzero exit even while last-good data is held. Always run the explicit
import phase on failed fetches too, so expiry revocations reach MISP. Monitor both
the process result and each source state. A stopped scheduler cannot revoke data:
alert on missed runs and disable/retire stale managed events before trusting them.
Managed attributes also carry an explicit expiry marker. Manager filters expired
managed context and caps snapshot freshness at its earliest managed expiry, so
stopping the importer cannot keep that context fresh for the 30-day query window.
Do not remove a source from configuration as an expiry mechanism.

Manager reads a complete snapshot of fewer than 100,000 recent IP attributes,
with deleted attributes excluded and MISP warninglists enforced. A partial fetch,
unexpected response or volume overflow retains the prior snapshot and reports a
failed sync. Per-IP results cannot outlive snapshot freshness. Snapshot refresh is
up to six hours, so allow that propagation delay after a source changes or is
revoked. Verify the fresh Manager generation before removing direct protections.

The optional operator setting `redis_no_password=true` applies only to this Cake
process for an existing passwordless Redis deployment. It does not change Redis
credentials or MISP's saved configuration; leave it absent for other deployments.

Before first import, back up the MISP database, feed definitions, configuration,
timer/service definitions and staging state. Before firewall changes, export
running and candidate configurations and affected object/reference data; preserve
unrelated candidate edits. Imports are scoped but not one database transaction;
inspect partial failures and restore from backups if necessary. Validate every
replacement through native MISP and Manager before retiring a direct feed.
