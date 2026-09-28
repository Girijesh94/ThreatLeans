# Shared SOC operations

This release supports a single SOC with three roles. It is not multi-tenant SaaS. The portable SQLite profile and the shared PostgreSQL profile use the same data model and API.

## Roles

| Action | Analyst | Reviewer | Administrator |
|---|---|---|---|
| Research public sources | Yes | Yes | Yes |
| Read and export own history | Yes | Yes | Yes |
| Request review of own case | Yes | Yes | Yes |
| Inspect team review queue | No | Yes | Yes |
| Approve/reject a case | No | Yes | Yes |
| Refresh feeds | No | No | Yes |
| Create/disable accounts | No | No | Yes |
| Inspect audit and metrics | No | No | Yes |

Approval is a human review disposition. It does not change the original source verification status or rewrite evidence. A reviewer may export a reviewed case; analyst history remains owner-scoped. Disabled users lose access even while holding a previously valid session.

## Deployment checklist

1. Configure a random database password and an initial admin password. Keep `.env` in restricted server storage.
2. Run the Compose stack inside the SOC network. PostgreSQL and Qdrant stay internal.
3. Terminate HTTPS with a trusted certificate. Set `THREATLEANS_COOKIE_SECURE=true` when the public origin is HTTPS. Do not enable that option on an HTTP-only localhost demo, because browsers will refuse its secure cookie.
4. Create distinct analyst and reviewer accounts. Do not share the bootstrap administrator account for everyday investigations.
5. Confirm successful source ingestion, counts, observation dates and retrieval mode in the UI. A successful health check does not establish source freshness.
6. Set any cloud provider's account spending limits and approve its handling of analyst queries before enabling it. No browser-side provider key exists.
7. Take a database and raw-evidence-volume backup, restore it into an isolated environment, and run the fixed evaluation workload.

## Updates and generations

The worker refreshes KEV, ATT&CK and the pinned OWASP edition daily. A failed/empty feed retains the prior published evidence. Revoked or removed ATT&CK records are removed after a complete successful snapshot. Raw feeds remain content-addressed. NVD and CNA records are fetched for specifically requested CVEs, not claimed as a complete global CVE mirror.

Search vectors are derived data. Qdrant collection names include the corpus fingerprint; old collections can be retired after confirming no running API process uses them. An API refresh can take minutes on CPU. Schedule large refreshes outside peak analyst periods. The first semantic startup also downloads the model. A lexical fallback is visible and remains useful for exact IDs.

## Retention and recovery

Default investigation retention is 30 days, enforced by the worker. Pending reviews are excluded from ordinary pruning. Audit retention is not automatically pruned in this release; configure a deployment policy and an export/archive routine appropriate to your SOC. No query text is included in general audit metadata, but complete investigations intentionally retain the submitted question and response.

For SQLite, `threatleans backup backups/snapshot.sqlite` creates a consistent snapshot. Restore with the API stopped: preserve the current database as a recoverable copy, place the tested snapshot at the configured database path, then restart. For PostgreSQL use `pg_dump`/`pg_restore` into a fresh database and change the service configuration after the isolated restore passes. Keep backup credentials separate from ordinary analyst accounts.

## Operational limits

- One API process; in-memory rate limiting and circuit breakers are not shared across replicas.
- Public-source ingestion only. No arbitrary URL fetching, file uploads, network scanning or exploit execution.
- The audit table is application-owned, not a tamper-proof external audit service.
- Cloud adapters are transport-tested with deterministic mocks until real provider credentials are configured. No claim of live paid-provider failover is made.
- No enterprise SSO/MFA integration in this release. Use a trusted access proxy if organizational policy requires those controls.
- PostgreSQL/Docker deployment must be verified on its deployment host. The development workstation has no Docker runtime installed.

## Troubleshooting

**Login fails:** check that the API started with the intended `.env`, the bootstrap account exists, and the secure cookie option matches HTTPS use. After ten failed logins from one address, wait five minutes.

**No sources:** wait for the worker's first run or refresh feeds as admin. Inspect source logs; a network failure does not fabricate a corpus.

**Unknown CVE:** use the live check or `threatleans nvd CVE-YYYY-NNNN`. Absence from the local KEV corpus does not mean a vulnerability is safe or does not exist.

**Dense retrieval unavailable:** inspect `threatleans doctor` and model cache permissions. Leave dense mode disabled for lexical operation while repairing the server runtime.

**AI unavailable:** inspect the provider configuration, model identifier, spending limit, rate limit and attempt trace. Evidence mode continues. A local-only request never silently sends data to a cloud provider.
