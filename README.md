# ThreatPulse

![Python](https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

**Threat intelligence aggregation and FedRAMP 20x continuous monitoring, locally hosted.**

ThreatPulse pulls CVEs, CISA KEV alerts, vendor advisories, malware feeds, threat actor intelligence, and dark web exposure into a single searchable feed. It includes a full FedRAMP 20x compliance suite — KSI validation, OSCAL document generation, scanner/SIEM integrations, and an automated audit log — plus a local AI analyst powered by Ollama. No SaaS subscriptions, no telemetry, no data sent externally.

---

## Contents

- [Prerequisites](#prerequisites)
- [Quickstart — Local Dev](#quickstart--local-dev)
- [Production Deployment](#production-deployment)
- [Authentication](#authentication)
- [Feeds Ingested](#feeds-ingested)
- [Pages](#pages)
- [REST API Reference](#rest-api-reference)
- [Environment Variables](#environment-variables)
- [Architecture](#architecture)
- [Adding a New Feed](#adding-a-new-feed)
- [License](#license)

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.13+ | Check "Add Python to PATH" on Windows |
| Git | any | [git-scm.com](https://git-scm.com/downloads) |
| Ollama | latest | [ollama.com](https://ollama.com/download) — optional, enables AI analyst |

---

## Quickstart — Local Dev

```bash
# 1. Clone
git clone https://github.com/zacharyloganhill/PhantomFeed.git threatpulse
cd threatpulse

# 2. Virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY and ADMIN_PASSWORD

# 5. (Optional) Pull an Ollama model for the AI analyst
ollama pull llama3.2

# 6. Start
python main.py
```

Open **http://localhost:8000** in your browser. Login with the credentials you set in `.env` (default username: `admin`).

On first run, all feeds are polled immediately. The dashboard statusbar shows **● CONNECTED** when the API is live and **● AI: llama3.2** when Ollama is detected.

### Generate strong secrets

```bash
python scripts/generate-secrets.py
```

Prints a ready-to-paste `.env` block with a cryptographically strong `SECRET_KEY`, `ADMIN_PASSWORD`, and `PHANTOMFEED_ENCRYPTION_KEY`.

---

## Production Deployment

### Docker Compose

```bash
# Generate secrets first
python scripts/generate-secrets.py >> .env

# Edit nginx/certs/ — add your TLS cert and key (or use self-signed for testing)
# See nginx/nginx.conf for the expected filenames

docker compose up -d
```

The compose stack runs:
- **app** — FastAPI on `127.0.0.1:8000` (not exposed directly)
- **nginx** — HTTPS on port 443, HTTP→HTTPS redirect on 80, rate limiting at 60 req/min per IP

The SQLite database and upload temp files are stored in named Docker volumes (`db_data`, `uploads`).

> **SQLite constraint:** The app runs with `--workers 1`. SQLite's write locking is not safe under concurrent multi-process access. If you need horizontal scaling, migrate to PostgreSQL.

### systemd (bare metal)

```bash
# Copy service file
sudo cp deploy/threatpulse.service /etc/systemd/system/
# Edit WorkingDirectory and EnvironmentFile paths in the unit file
sudo systemctl daemon-reload
sudo systemctl enable --now threatpulse
```

The unit runs as a non-root user with kernel-level hardening (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, empty `CapabilityBoundingSet`).

### Health check

```
GET /health
```

Unauthenticated liveness + readiness probe. Returns `200 {"status":"ok","db":"ok"}` or `503 {"status":"degraded","db":"error"}`. Used by the Docker `HEALTHCHECK` and nginx upstream health checks.

---

## Authentication

Every API endpoint (except `GET /health`) requires a JWT bearer token.

### Login

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' | jq .
```

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "role": "admin"
}
```

Include the token in every request:
```bash
curl http://localhost:8000/api/v1/stats \
  -H "Authorization: Bearer eyJ..."
```

### Auth endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Issue JWT — returns `access_token`, `role` |
| POST | `/auth/logout` | Revoke current token immediately |
| GET | `/auth/me` | Current user info (`username`, `role`, `client_id`) |

### Roles

| Role | Access |
|------|--------|
| `admin` | Full access — all clients, all admin operations, refresh, purge |
| `analyst` | Read access to threat feed, stats, notifications. Write access to their own read-state. No admin operations |
| `client` | Scoped to their assigned `client_id` — sees only their own KSI, findings, remediation |

### Session limits

Each user account supports a maximum of **5 concurrent sessions**. A sixth login returns `429 Too Many Requests`. Logging out frees a slot immediately. Tokens are revoked server-side on logout and remain invalid even if the JWT has not expired.

---

## Feeds Ingested

### Vulnerability Intelligence

| Feed | Source | Interval |
|------|--------|----------|
| NVD CVE API v2 | nvd.nist.gov | 15 min |
| CISA KEV | cisa.gov | 15 min |
| CISA IT Advisories | github.com/cisagov | 60 min |
| CISA ICS/OT Advisories | github.com/cisagov | 60 min |

### Vendor Security Advisories

| Vendor | Source |
|--------|--------|
| Microsoft MSRC | msrc.microsoft.com |
| Cisco | sec.cloudapps.cisco.com |
| Fortinet PSIRT | fortiguard.com |
| Palo Alto Networks | security.paloaltonetworks.com |
| Red Hat | access.redhat.com |
| Ubuntu / Canonical | ubuntu.com |

### Threat Intelligence & Malware

| Feed | Source |
|------|--------|
| abuse.ch URLhaus | urlhaus-api.abuse.ch |
| abuse.ch Feodo Tracker | feodotracker.abuse.ch |
| AlienVault OTX | otx.alienvault.com |

### Supply Chain

| Feed | Source |
|------|--------|
| GitHub Advisory (npm) | github.com/advisories |
| GitHub Advisory (PyPI) | github.com/advisories |

---

## Pages

| URL | Description |
|-----|-------------|
| `/` | Mission Control — stats, platform status, recent alerts |
| `/dashboard.html` | Threat feed — real-time, filterable, AI analyst, IOC enrichment |
| `/analytics.html` | Charts: 90-day trend, severity distribution, vendor risk, MTTR |
| `/actors.html` | Threat actor dossier browser (55+ APTs with ATT&CK heatmap) |
| `/cmmc.html` | CMMC 2.0 gap assessment — 110 practices, 14 domains |
| `/supplychain.html` | Supply chain risk graph (D3.js force-directed) |
| `/darkweb.html` | Dark web exposure monitoring and alert acknowledgement |
| `/upload.html` | Scan upload center, IOC import, bulk operations, exports |
| `/integrations.html` | Scanner and SIEM wizard — setup, field mapping, pull history |
| `/fedramp.html` | FedRAMP 20x dashboard — KSI, OSCAL, scanners, SIEMs, audit log |
| `/admin.html` | Client management, user accounts, assets, webhooks *(admin only)* |
| `/login.html` | Login |

---

## REST API Reference

Base URL: `http://localhost:8000/api/v1`  
Interactive docs (requires auth): `http://localhost:8000/docs`

All requests require `Authorization: Bearer <token>` unless noted.

### Threat Feed

```
GET    /items                      List items — filterable, searchable, paginated
GET    /items/{id}                 Single item by ID
POST   /items/{id}/read            Mark item read (per-user — does not affect other users)
POST   /items/read-all             Mark all items read for current user
GET    /stats                      Counts by severity, feed, new/total
GET    /feeds                      List all registered feed IDs
POST   /refresh                    Trigger immediate poll of all feeds (admin)
POST   /refresh/{feed_id}          Trigger poll of one feed (admin)
DELETE /items/purge                Delete items older than retention period (admin)
```

#### `GET /items` query parameters

| Param | Example | Description |
|-------|---------|-------------|
| `severity` | `CRITICAL,HIGH` | Comma-separated severity filter |
| `category` | `cve` | `cve` · `kev` · `advisory` · `vendor` · `ics` · `threat` · `malware` · `supply` |
| `feed_id` | `nvd` | Filter to a single source |
| `is_new` | `true` | Unread items only (per calling user) |
| `search` | `ivanti` | Full-text search: title, description, vendor, tags (max 200 chars) |
| `limit` | `50` | Page size (max 500) |
| `offset` | `0` | Pagination offset |
| `client_id` | `abc123` | Filter to assets matching a client's stack |
| `exposed_only` | `true` | Only items matching client asset CPEs |

### IOC Enrichment

```
GET  /ioc/lookup?value=8.8.8.8    Enrich IP, hash, domain, or URL (24-hour cache)
GET  /ioc/cache?limit=20          Recent enrichment cache entries
```

### Analytics

```
GET  /analytics/trend?days=90             Severity volumes by day
GET  /analytics/vendor-risk               Top vendors by threat count
GET  /analytics/category-breakdown        Items by category × severity
GET  /analytics/remediation-mttr          Mean time to remediate trend
GET  /clients/{id}/posture                Risk posture score + industry percentile
GET  /clients/{id}/posture/history        Historical score snapshots
GET  /benchmarks/{industry}               Industry baseline statistics
GET  /benchmarks                          All clients ranked
```

### Remediation

```
GET    /clients/{id}/remediation                     List items + SLA status
POST   /clients/{id}/remediation                     Create item
PATCH  /clients/{id}/remediation/{rid}               Update status
GET    /clients/{id}/metrics                         MTTR, SLA compliance, overdue counts
```

Statuses: `open` · `in_progress` · `patched` · `accepted_risk` · `false_positive` · `wont_fix`

### Dark Web Monitoring

```
GET  /clients/{id}/darkweb-alerts                       List alerts
POST /clients/{id}/darkweb-alerts/{alert_id}/acknowledge
POST /clients/{id}/darkweb-scan                         Trigger immediate scan
GET  /notifications                                     Aggregated notification center
```

### TAXII 2.1

```
GET  /taxii/sources              List configured TAXII servers + status
POST /taxii/test/{feed_id}       Test connection
```

### Threat Actors

```
GET  /actors                      List all actors (filter: origin, motivation)
GET  /actors/{id}                 Full dossier
GET  /actors/{id}/items           Threat items linked to this actor
GET  /clients/{id}/actor-alerts   Actors targeting client's industry
```

### FedRAMP — Scanners

Scanner credentials are Fernet-encrypted at rest. All endpoints scoped to `/clients/{id}/`.

```
GET    /clients/{id}/scanners
POST   /clients/{id}/scanners
PATCH  /clients/{id}/scanners/{scanner_id}
DELETE /clients/{id}/scanners/{scanner_id}
POST   /clients/{id}/scanners/{scanner_id}/poll
GET    /clients/{id}/scan-findings
GET    /clients/{id}/scan-findings/summary
```

Supported scanners: **Tenable.io**, **Tenable.sc**, **Rapid7 InsightVM**, **Qualys VMDR**, **CrowdStrike Spotlight**

### FedRAMP — SIEMs

Same endpoint pattern as scanners at `/clients/{id}/siems/...`

Supported SIEMs: **Splunk**, **Microsoft Sentinel**, **IBM QRadar**, **Elastic Security**

### FedRAMP — KSI Validation

Seven Key Security Indicators validated automatically every 6 hours.

```
GET   /clients/{id}/ksi              Current results + pass/fail per KSI
POST  /clients/{id}/ksi/validate     Trigger immediate validation
GET   /ksi/summary                   All-client KSI summary (admin)
```

| KSI | Category | Pass Condition |
|-----|----------|----------------|
| KSI-1 | Vulnerability Management | No CRITICAL open > 15 days, HIGH > 30 days |
| KSI-2 | Patch Currency | ≥ 90% patch rate |
| KSI-3 | Continuous Monitoring | All scanners polled within interval + 2 h |
| KSI-4 | Incident Detection | ≥ 1 active SIEM with recent data |
| KSI-5 | POA&M Timeliness | 0 overdue CRITICAL remediations |
| KSI-6 | Supply Chain | ≥ 80% vendors assessed within 30 days |
| KSI-7 | Dark Web Exposure | No unacknowledged alerts > 48 hours |

### FedRAMP — OSCAL Output

```
GET  /clients/{id}/oscal/poam.xml
GET  /clients/{id}/oscal/sar.xml
GET  /clients/{id}/oscal/vdr.json
GET  /clients/{id}/oscal/oar.json
GET  /clients/{id}/oscal/ssp.xml
GET  /clients/{id}/oscal/bundle.zip     All five documents
```

### FedRAMP — Audit Log

Every API call is logged: event type, user, client, method, path, status code, IP, duration ms, `X-Request-ID`.

```
GET  /audit                          Global audit log (admin)
GET  /clients/{id}/audit             Per-client log
GET  /clients/{id}/audit.csv         CSV export
```

### CMMC 2.0

```
GET    /clients/{id}/cmmc/assessment
PATCH  /clients/{id}/cmmc/practices/{practice_id}
POST   /clients/{id}/cmmc/bulk-update
GET    /cmmc/practices?domain=Access+Control
```

### Upload & Export

```
POST /upload/scan                     Auto-detect and preview scan file
POST /upload/scan/{id}/confirm        Confirm import
POST /upload/assets                   Preview asset CSV/XLSX
POST /upload/assets/{id}/confirm      Confirm
POST /upload/iocs                     Import IOC list (enrichment in background)
POST /upload/stix                     Import STIX 2.1 bundle
POST /upload/clients                  Bulk client preview
POST /upload/clients/{id}/confirm     Confirm
GET  /upload/history                  Upload log
GET  /upload/templates/{type}         Download CSV template (assets | clients | iocs)

GET  /export/items.csv
GET  /export/items.json
GET  /export/iocs.txt?days=7
GET  /export/iocs.csv?days=7
GET  /export/iocs.stix?days=7
GET  /clients/{id}/export/remediation.csv
GET  /clients/{id}/export/remediation.xlsx
GET  /clients/{id}/export/detection-rules.zip   SPL + KQL + Sigma
POST /clients/{id}/export/push-rules-github
GET  /clients/{id}/report.html?days=30
GET  /clients/{id}/report/pdf
```

**Supported upload formats:** Nessus (`.nessus`), Qualys XML/CSV, OpenVAS XML, Rapid7/InsightVM CSV, generic CSV/XLSX (fuzzy mapping), IOC plain-text/JSON, STIX 2.1 bundle, bulk clients CSV.

### Executive Briefing Deck

```
GET  /clients/{id}/deck.pptx?days=30
GET  /clients/{id}/deck-preview
```

12-slide PowerPoint with AI-written summaries, matplotlib charts, and remediation donut. Requires `python-pptx matplotlib Pillow` (included in `requirements.txt`).

### Tabletop Exercise Generator

```
GET   /clients/{id}/tabletops
POST  /clients/{id}/tabletops/generate    {scenario_type, custom_prompt}
GET   /clients/{id}/tabletops/{id}/export.pdf
GET   /clients/{id}/tabletops/{id}/export.pptx
GET   /tabletop/scenario-types
```

Scenarios: `ransomware` · `supply_chain` · `data_breach` · `insider_threat` · `ddos` · `phishing` · `zero_day` · `cloud_breach`

### Ollama Proxy

```
GET|POST  /api/ollama/{path}    Proxies to http://localhost:11434/{path}
```

Streams responses token-by-token. Rate-limited to 30 req/min per user. Eliminates browser CORS issues between the dashboard and Ollama.

### Admin

```
GET    /api/v1/admin/users
POST   /api/v1/admin/users
DELETE /api/v1/admin/users/{id}
POST   /api/v1/admin/users/{id}/force-logout

GET    /api/v1/admin/clients
POST   /api/v1/admin/clients
PATCH  /api/v1/admin/clients/{id}
DELETE /api/v1/admin/clients/{id}
GET    /api/v1/admin/clients/{id}/assets
POST   /api/v1/admin/clients/{id}/assets/import
DELETE /api/v1/admin/clients/{id}/assets/{asset_id}
```

---

## Environment Variables

Copy `.env.example` to `.env`. Generate strong values with `python scripts/generate-secrets.py`.

### Required for production

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing secret — minimum 32 random bytes |
| `ADMIN_PASSWORD` | Admin account password — must satisfy complexity rules |
| `PHANTOMFEED_ENCRYPTION_KEY` | Fernet key for scanner/SIEM credential encryption. **Required when `HOST` is not localhost.** Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8000` | Port |
| `DB_PATH` | `./threatpulse.db` | SQLite file path |
| `RETENTION_DAYS` | `90` | Days of history before purge |
| `CORS_ORIGINS` | `http://localhost:8000` | Comma-separated allowed origins |

### Feed API keys (all optional — improve rate limits or unlock feeds)

| Variable | Source | Effect |
|----------|--------|--------|
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | Raises NVD rate limit from 5 to 50 req/30s |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) | Required for OTX threat pulses |
| `URLHAUS_API_KEY` | [auth.abuse.ch](https://auth.abuse.ch/) | Increased URLhaus access |
| `POLL_INTERVAL_FAST` | `15` | High-priority feed interval (minutes) |
| `POLL_INTERVAL_SLOW` | `60` | Vendor/intel feed interval (minutes) |
| `NVD_PAGE_SIZE` | `200` | CVEs per NVD API page (max 2000) |

### IOC enrichment keys (all optional)

| Variable | Source | Enriches |
|----------|--------|---------|
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | IP reputation + country |
| `GREYNOISE_API_KEY` | [greynoise.io](https://www.greynoise.io) | IP classification |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com) | Hash/domain/URL detection ratio |

### MISP

```env
MISP_URL=https://your-misp-instance
MISP_API_KEY=your_api_key
MISP_VERIFY_SSL=true
```

### TAXII

```env
TAXII_USERNAME=
TAXII_PASSWORD=
TAXII_CERT_PATH=       # PEM path for CISA AIS mutual TLS
```

---

## Architecture

```
threatpulse/
├── main.py                 # FastAPI app, lifespan, middleware, Ollama proxy
├── config.py               # Feed URLs, API keys, settings
├── .env                    # Secrets — never commit
├── .env.example            # Template
├── requirements.txt
│
├── db/
│   ├── database.py         # Async SQLite: connect, CRUD, sessions, token denylist
│   └── audit_log.py        # Audit log table, CSV export, request correlation
│
├── auth/
│   └── auth.py             # JWT issue/verify, token_version, admin seed
│
├── ingest/
│   ├── base.py             # BaseFetcher: HTTP helpers, retries, normalization
│   ├── nvd.py              # NVD CVE API v2
│   ├── cisa.py             # CISA KEV + CSAF advisories
│   ├── rss_feeds.py        # Vendor RSS ingestion
│   ├── threat_intel.py     # abuse.ch, OTX, supply chain
│   └── scheduler.py        # APScheduler: per-feed intervals
│
├── api/
│   ├── routes.py           # Core feed endpoints
│   ├── auth_routes.py      # /auth/login, /auth/logout, /auth/me
│   ├── admin_routes.py     # Users, clients, assets, webhooks
│   ├── audit_middleware.py # AuditMiddleware: logs every request, injects X-Request-ID
│   ├── rate_limit.py       # In-memory sliding window rate limiter
│   ├── analytics_routes.py
│   ├── ioc_routes.py
│   ├── upload_routes.py
│   ├── export_routes.py
│   ├── scanner_routes.py
│   ├── siem_routes.py
│   ├── ksi_routes.py
│   ├── oscal_routes.py
│   ├── audit_routes.py
│   └── ...                 # actor, darkweb, misp, deck, cmmc, tabletop, supply chain
│
├── threat_actors/
│   └── seed_data.py        # 55+ actor dossiers, seeded at startup
│
├── scripts/
│   └── generate-secrets.py # Generate SECRET_KEY, ADMIN_PASSWORD, ENCRYPTION_KEY
│
├── deploy/
│   └── threatpulse.service # systemd unit with kernel hardening
│
├── nginx/
│   ├── nginx.conf          # HTTPS, HSTS, rate limiting, /health exempt
│   └── certs/              # TLS cert + key (not committed)
│
├── Dockerfile
├── docker-compose.yml
│
└── tests/
    ├── test_api_integration.py   # HTTP integration tests via TestClient
    └── test_fedramp.py           # Unit tests: security invariants, audit, sessions
```

### Security model

- **JWT** with `jti` denylist (server-side revocation) and per-user `token_version` (force-logout all sessions)
- **Session cap** — max 5 concurrent sessions per user; enforced at login
- **Fernet encryption** for scanner/SIEM credentials at rest
- **SSRF protection** — webhook delivery blocks RFC-1918/loopback; scanner endpoints explicitly allow internal ranges for legitimate enterprise networks
- **Content-Security-Policy**, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, HSTS (HTTPS only)
- **Rate limiting** — 60 req/min per IP on all routes; 30 req/min per user on Ollama proxy
- **JSON body size limit** — 1 MB cap on `application/json` requests
- **Request correlation** — every response carries `X-Request-ID` (generated or echoed from client), stored in audit log

### Running tests

```bash
python -m pytest tests/ -v
```

Uses an in-memory SQLite database. Scheduler, initial poll, and threat-actor seeding are patched out. All 75 tests should pass.

---

## Adding a New Feed

1. Create a class in `ingest/` inheriting `BaseFetcher`
2. Set `feed_id`, `feed_label`, `category`, and `poll_interval`
3. Implement `async def fetch(self) -> list[dict]`
4. Register it in `ingest/scheduler.py` → `_build_fetchers()`

For simple RSS sources, add an entry to `VENDOR_RSS_FEEDS` in `config.py` — no code needed.

---

## License

MIT — do whatever you want with it.
