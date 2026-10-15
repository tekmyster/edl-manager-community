# EDL Manager Community Edition

Detect malicious activity, correlate evidence, publish block lists and investigate why an address was blocked.

This edition retains the Private Edition's scoring, whitelist and crawler protections, repeat-offender history, IP investigation, audit notes, cached enrichment, charts, table controls and read-only reporting API. It has no bundled credentials, collected traffic, private certificates or lab-specific deployment configuration.

## License

Public source is available under the [EDL Manager Community License](LICENSE), a custom **source-available** license. Personal home labs and legally established nonprofits may use it free within the allowance. Enterprise and commercial use require a separate written license.

- Count distinct public IPs observed each UTC day, once across all sources.
- Rolling 30-day average: at most **500/day**.
- At most **one day per UTC calendar month** above 500, up to **1,000**.
- A separate license is needed for enterprise use or usage above any limit.

System settings reports local usage. Detection and blocking continue when a license is required; the application never silently disables protection. Multiple installations' combined usage is the operator's responsibility. There is no publisher usage telemetry or implemented license-key purchasing service. Contact [the publisher](https://github.com/tekmyster) for licensing.

## Start here

See [Installation](docs/INSTALL.md), [Source integration](docs/SOURCES.md), and [Architecture](docs/ARCHITECTURE.md). Supported runtime: Linux with Python 3.13. Docker Compose uses Linux host networking. The native application can run in a virtual environment without Docker.

A fresh installation starts empty. Configure sources in System settings. Optional enrichment providers require your own API keys and account allowances. No MISP instance or honeypot sensor is deployed by the application.

## Tests

```sh
python -m pip install -r requirements-dev.txt -c requirements-lock.txt
python -m pytest -q
```

Test databases and example addresses are synthetic fixtures. Native detection requires appropriately normalized source logs; see the source contract before expecting ingestion.

## Enforcement

Use `/feeds/combined-block.txt` from explicitly allowed firewall source addresses. Configure the firewall's EDL refresh and rule placement separately. Authenticated administrators download lists from the web UI. Feeds revalidate with ETag against the latest complete generation. Firewall download, acceptance and enforcement are separate outcomes.

## Behavioral intelligence

Optional background AI inspection and behavioral similarity are available in shadow mode. They never change enforcement in this release. See [configuration, evidence handling and limitations](docs/BEHAVIORAL-ANALYSIS.md).
