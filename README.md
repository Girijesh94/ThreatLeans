# ThreatLeans

ThreatLeans is a self-hosted threat intelligence workspace for a shared SOC. Analysts ask questions, inspect source-bound claims and evidence, save investigations, and send uncertain results to reviewers. It never treats a missing CVE as proof of safety and never derives CVE-to-ATT&CK mappings from similarity.

**No ChatGPT subscription, Claude subscription, API key, or local chatbot is required.** Evidence mode formats authoritative records directly. Optional team AI providers add a separately labeled interpretation. API credentials are configured on the server by an administrator, never delivered to the browser.

## Architecture

- React 19 and TypeScript browser workspace, Vite build, Lucide icons.
- Animated public introduction using React Three Fiber, ShaderGradient, Paper LiquidMetal, and an adapted liquid-glass-js surface. See [graphics integration and notices](docs/GRAPHICS.md).
- Python 3.12, FastAPI, SQLAlchemy, PostgreSQL for a shared deployment; SQLite for portable use.
- Bounded LangGraph planner → retriever → fact builder → verifier → decision/synthesis workflow.
- Exact identifier filtering, BM25, optional BGE small v1.5 CPU ONNX embeddings, reciprocal rank fusion, optional Qdrant.
- CISA KEV, MITRE enterprise ATT&CK including explicit STIX relationships, versioned OWASP 2021 guidance, per-CVE NVD and CVE Program records.
- Argon2 passwords, opaque eight-hour server sessions, HttpOnly/SameSite cookies, CSRF checks, analyst/reviewer/admin roles, owner-scoped history, audit events, query admission limits.
- Optional OpenAI Responses, Anthropic Messages, and Ollama adapters; bounded timeouts, circuit cooldown, permitted provider failover, final evidence fallback.

## Portable development setup

Use Python 3.12 and Node 22 or newer. From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e "./backend[dense,postgres,test]"
.\.venv\Scripts\python.exe scripts/initialize_local.py
Set-Location frontend
npm ci
npm run build
Set-Location ..
.\.venv\Scripts\python.exe -m threatleans.cli ingest
.\.venv\Scripts\python.exe -m threatleans.cli nvd CVE-2021-44228
.\.venv\Scripts\python.exe -m threatleans.cli serve
```

Open `http://127.0.0.1:8000`. Development UI hot reload: run `npm run dev` inside `frontend`; it proxies `/api` to port 8000. The compiled frontend is served by FastAPI on the same origin in a normal build.

The initialization script creates an authenticated localhost configuration and writes generated initial credentials to the ignored private file `data/runtime/initial-admin.txt`. Existing `.env` files are preserved. The raw `.env.example` disables sign-in for isolated development; use the shared profile below for a team and never expose an unauthenticated profile to a network.

## Shared SOC deployment

Docker Engine with Compose is required on the deployment server. Create `.env` from `.env.example` and set:

```dotenv
POSTGRES_PASSWORD=replace-with-a-long-random-database-password
THREATLEANS_ADMIN_USERNAME=admin
THREATLEANS_ADMIN_PASSWORD=replace-with-a-long-random-admin-password
THREATLEANS_AUTH_REQUIRED=true
THREATLEANS_PUBLIC_URL=http://localhost:8080
THREATLEANS_BIND_ADDRESS=127.0.0.1
```

Use URI-safe characters for the database password or URL-encode it. Admin passwords must have at least 12 characters. The application refuses to bootstrap a shared deployment without a suitable password. Do not commit `.env`.

```sh
docker compose up --build -d
docker compose exec api threatleans nvd CVE-2021-44228
docker compose logs -f worker
```

Open `http://localhost:8080`, sign in as the configured admin, and create analyst and reviewer accounts in Team settings. The worker imports official sources on startup and daily thereafter. An admin can also refresh a source in the UI. Records become visible to the API after its index generation check, at most ten seconds plus index build time. Unresolved review cases are retained when the worker prunes ordinary expired investigations.

For a real shared network, put a trusted HTTPS reverse proxy in front of the localhost binding, use your actual public origin in `THREATLEANS_PUBLIC_URL`, and set the secure-cookie option documented in the environment file. Restrict the service to your SOC network. PostgreSQL and Qdrant are internal Compose services with no public host ports. Scale this release as one API process and one ingestion worker; its in-memory admission controls and circuit breakers are not distributed.

## Semantic search without a chatbot

Set `THREATLEANS_DENSE_ENABLED=true` and restart. The server downloads a roughly 34 MB quantized ONNX export of BGE small v1.5, then computes 384-dimensional search vectors. CPU inference uses two threads. Initial indexing takes time; later starts load cached vectors. The model is a retrieval encoder, not an LLM. It runs on the server, so analyst computers need only a browser.

The model exporter is `Xenova/bge-small-en-v1.5`, pinned to revision `ea104da`. The cache stores a revision and SHA-256 manifest. If model initialization fails, lexical search remains available and the interface explicitly reports the degradation. Set `THREATLEANS_QDRANT_URL` to use an internal Qdrant server; leave it empty to search the cached local vectors. Each Qdrant collection belongs to a corpus fingerprint.

## Optional AI providers

Configure any combination on the server:

```dotenv
THREATLEANS_OPENAI_API_KEY=your-provider-api-key
THREATLEANS_OPENAI_MODEL=your-supported-model-id
THREATLEANS_ANTHROPIC_API_KEY=your-provider-api-key
THREATLEANS_ANTHROPIC_MODEL=your-supported-model-id
THREATLEANS_OLLAMA_URL=http://ollama:11434
THREATLEANS_OLLAMA_MODEL=your-installed-model-name
```

Restart the API after changing configuration. ChatGPT/Claude consumer subscriptions do not configure these server APIs. A team account pays for permitted cloud calls. Analysts see only configuration status and model names. No key is returned by any endpoint.

Cloud summaries require a per-request external-sharing confirmation. The question and retrieved public-source excerpts are sent to configured external providers; do not include sensitive SOC material unless your organization has approved that processing. A cloud request may fail over to another configured cloud provider or the team Ollama server. A request selecting Ollama never silently falls back to a cloud provider. Evidence-only requests make no LLM calls. Provider timeouts are eight seconds per attempt, with at most three permitted providers and a 60-second cooldown after failure. The result retains attempt status and latency. No token-price estimate is represented as an actual invoice; configure spending caps at your provider account.

To use Ollama through Compose, enable `--profile local-ai`, choose a model that fits the server, and pull that model using the Ollama service. The optional service does not download a large model automatically.

## What verification means

Each displayed claim has a source field, value, evidence reference and provenance hash. The verifier checks whether that field/value is present in the recorded source. Direct excerpts are labeled as quotations. Matching CVSS version, numeric value **and vector** in a second source produces a separate corroboration reference. NVD and a CNA record may share upstream information: two records are corroboration, not proof of independent discovery.

An optional live check for a named CVE fetches NVD and CVE Program records. It preserves failures and cached evidence. CVSS 2.0 and 3.1 differences are not automatically called conflicts; differing scores within the same version are surfaced for review. KEV establishes catalog membership; it does not establish your organization's exposure or compromise. CISA action deadlines are US federal civilian agency obligations, not universal patch deadlines.

Conceptual searches return related evidence and require analyst judgment. Product applicability requires exact version, edition, configuration, and vendor applicability rules. No CVE-to-technique relationship is inferred. MITRE relationships retain their STIX relationship identifiers.

## Administration

```sh
threatleans doctor
threatleans ingest --source kev
threatleans ingest --source attack
threatleans ingest --source owasp
threatleans nvd CVE-2021-44228
threatleans evaluate --output reports/evaluation.json
threatleans backup backups/threatleans.sqlite
```

`backup` uses SQLite's consistent backup API. For PostgreSQL use `pg_dump` and restore into a fresh database, then rebuild retrieval projections from canonical documents. Also preserve the raw evidence volume and `.env` securely. Test restores on an isolated server before relying on a backup.

API reference: `/docs`. Health: `/api/health`. Authenticated admin metrics: `/api/metrics`. Investigations export as JSON with claims, evidence, hashes, workflow trace, provider attempts, warnings and review decisions.

## Verification and evaluation

```sh
python -m pytest backend/tests -q
python -m ruff check backend/src backend/tests
cd frontend
npm run build
npm test
npm audit
```

Tests cover source normalization, exact missing-ID behavior, versioned scores, claim verification, same-version conflicts, authentication, CSRF, permissions, cloud consent, adapter schemas, circuit breaking, failover, and final evidence behavior. Failure fixtures are synthetic and labeled; they never enter the public evidence store. `reports/evaluation.json` contains measured results over an enumerated small retrieval workload. Its pass rate is not a general intelligence accuracy claim. Actual cloud calls require credentials and are not implied by mock transport tests.

## Data licenses and scope

Source URLs and provenance are retained per record. CISA KEV and NVD are public US government data; CVE Program and MITRE material remain subject to their published terms and attribution requirements. OWASP guidance is explicitly labeled by edition and retains its source link; this build does not claim the 2021 edition is the newest edition. See `docs/SOURCES.md` for upstream references.

The application does not scan networks, run exploits, patch assets, ingest private logs, or train a new model. Enterprise SSO, multi-organization tenancy, distributed query workers, bulk asset/SBOM matching, cross-encoder reranking, and independent vendor-advisory verification are future extensions rather than silently simulated features.
