# Installation

## Native Linux setup

Install Python 3.13 with its venv/ensurepip support, system CA certificates and OpenSSL first (Debian/Ubuntu: the matching python3.13-venv package). Run as a dedicated unprivileged account with write access only to its data directory.

```sh
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt -c requirements-lock.txt
.venv/bin/python setup.py --data ./data --hosts localhost,127.0.0.1
export EDL_CONFIG="$(pwd)/data/config.json"
```

Setup prompts for a new administrator password, hashes it and creates a random session secret. It never imports Private Edition data or resets an existing installation. The default listener and management source restrictions allow loopback only; no firewall consumer can download feeds until configured.

For a remotely accessible installation, provide your own hostname and authorized management CIDRs at first setup using `--hosts` and `--management`. Set `--feed-sources` to exact firewall source CIDRs where possible. Set `EDL_BIND` to the intended interface. Incoming forwarding headers are not trusted; configure source paths deliberately when using a proxy.

Provide an HTTPS certificate and private key accessible to the service account:

```sh
export EDL_TLS_CERT=/path/to/server.crt
export EDL_TLS_KEY=/path/to/server.key
.venv/bin/python run_service.py web
```

Run ingestion and enrichment as separate supervised processes:

```sh
.venv/bin/python run_service.py ingest
.venv/bin/python run_service.py enrich
```

Ingestion runs 30 seconds after each completion; enrichment runs five minutes after completion. Existing locks prevent overlapping runs of each worker. Source arrival, run duration and firewall polling determine total blocking latency.

## Docker Compose on Linux

```sh
docker compose build
docker compose run --rm setup
```

Copy a certificate and key into the named data volume at `/data/tls/server.crt` and `/data/tls/server.key`; ensure UID 10001 can read them. A mounted data volume survives container replacement. Then run:

```sh
docker compose up -d web ingest enrich
```

Host networking preserves incoming source addresses. The default bind is `127.0.0.1:9445`. Configure remote hosts and CIDRs with setup command arguments before exposing the listener. Docker Desktop's host-networking behavior is not a supported deployment target for this initial edition.

## Optional integrations

Index username/password can be supplied to setup using `EDL_INDEX_USER` and `EDL_INDEX_PASSWORD`; they are stored in the private configuration file. `EDL_INDEX_CA` and `EDL_MISP_CA` select trusted CA files, otherwise system trust is used. Configure URLs and source agents through System settings. API keys are entered in the provider settings and never displayed after saving.

To change connection credentials later, edit the protected configuration file and restart the workers and web service. Keep an original administrative session open during access or credential changes until a separate authorized new session authenticates with required privileges. Do not close the original session after a failed check.

Use your own current licensed ASN MMDB file via `EDL_ASN_DATABASE` at setup or the private config afterward. ASN is optional; missing data does not prevent crawler verification or other enrichment. Community Edition performs GreyNoise calls directly from its enrichment worker; it does not need the Private Edition's Ops host.

## Backups and upgrades

Back up configuration, provider keys and the data volume privately. Use SQLite's online backup API for a live database rather than copying only its main file during WAL writes. Never commit these files to Git. Stage and test upgrades before changing a live deployment; retain source and database rollback copies.
