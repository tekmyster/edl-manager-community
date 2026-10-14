# Community Edition 0.1.0

Initial source-available Community Edition derived from the preserved Private Edition.

Includes the existing detection and scoring engine, safe policy exceptions, atomic EDL publication, repeat-offender history, cached intelligence, IP investigation, administrative audit, reporting API, charts and table controls. Adds a clean first-install setup, Linux/container packaging, optional ASN configuration, direct GreyNoise transport, explicit firewall-source allowlists and local licensing usage reporting.

Validation: 183 Linux tests passed, followed by a fresh virtual-environment installation and complete suite with newly resolved dependencies. HTTPS sign-in, an authenticated administrative settings write and allowed-source feed download were verified against an empty temporary installation. Production Private Edition remained unchanged.

Known limits: GitHub CI verified the Docker image build, Compose configuration and initial setup as an unprivileged user with a read-only root filesystem. Full Compose stack launch was not executed. The new Community license settings panel could not be visually inspected because browser policy blocked the local preview. Paid-license purchasing/activation and organization-wide multi-installation usage aggregation are not implemented. Source normalization/forwarding and firewall rule placement remain operator-managed; see docs/SOURCES.md.

The custom license reflects the requested use and traffic restrictions; legal enforceability has not been independently reviewed.
