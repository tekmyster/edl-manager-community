# Architecture and edition boundaries

The Community Edition shares the preserved Private Edition's core policy and investigation modules. Changes for portability are confined to setup, optional-source defaults, optional ASN behavior, direct enrichment transport, authenticated UI branding, source-restricted live feeds, documentation and compliance reporting.

Evidence is normalized and ingested locally; SQLite stores observations, policy, cached intelligence, reviews and usage. Native ingestion and enrichment run separately. Builds publish immutable complete generations, with an atomic `current` switch. The UI uses cached summaries and bounded table pages; filtering preserves loading feedback, selection and safe text highlighting.

Manual whitelist/crawler protection, exact-IP emergency override, native scoring, shared intelligence bonus, retention and repeat-blocked-offender semantics are retained. A license-required state does not alter those decisions. Source allowlists for administrative access and firewall downloads are separate, and both default closed beyond loopback management.

The reporting API remains read-only and token-authenticated. Community usage is local only. There is no license-server call, telemetry, MSP tenant isolation, billing integration, or paid-key verification in this initial release.

Private Edition production deployment, credentials, provider keys, operational data and access controls are maintained separately and are not migrated or changed by Community Edition.
