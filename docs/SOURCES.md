# Source integration contract

The current automatic collector queries a Wazuh/OpenSearch-compatible index at `wazuh-alerts-*`. NGINX, WAF, CrowdSec, T-Pot and OWAPot must be forwarded and normalized there; connecting a raw NGINX file is not implemented by this edition.

Configure source agent names in System settings, using `*` only to include all agents for that source. Blank entries disable collection. Optional fields control presentation and correlation without changing API storage keys.

Native observation rules use IDs `119900` and `119902`. Required fields:

| Field | Meaning |
|---|---|
| `data.srcip` | Public unicast source address |
| `data.edl_source` | `tpot`, `owapot`, `nginx`, `waf`, `crowdsec` or `wazuh` |
| `data.edl_detector` | Honeypot/service identifier and detector |
| `data.edl_seen_utc` | Original event time, ISO 8601 with timezone |
| `timestamp` | Index delivery time |
| `agent.name` | Configured source agent |

Additional supported fields include cumulative `edl_native_attempt_count` and `edl_native_event_count`, comma-separated `edl_dst_ports`, `edl_qualifying`, `edl_path_hashes`, and JSON-encoded `edl_activity_json`. Counters must represent distinct attempts; forwarding duplicates and session housekeeping must not increment them.

Palo activity uses a configured `location` and decoded native fields such as `data.source_address`, `destination_address`, `destination_port`, `action`, and `high_resolution_timestamp`. Block-hit context renews existing blocks and adds no score. The investigation query is read-only.

MISP uses your own read-only API key, current indicators and warning-list enforcement. Context-only indicators do not add points. GreyNoise checks share a per-IP cache, weekly budget and rate-limit backoff. Provider permissions and quotas remain those of your account.

No automatic firewall rule installation or external source decoder provisioning is included. Configure those deliberately, then verify native timestamps, distinct-attempt counts, public-IP filtering and end-to-end enforcement with your own test traffic.
