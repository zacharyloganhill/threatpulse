# PhantomFeed

![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Open Source](https://img.shields.io/badge/open%20source-%E2%99%A5-red)

**Real-time threat intelligence aggregation, locally hosted.**

PhantomFeed pulls CVEs, vendor advisories, CISA alerts, malware feeds, and threat intel into a single searchable feed — with a dark-mode dashboard and a local AI analyst powered by Ollama. No SaaS subscriptions, no telemetry, no API bills. Runs entirely on your machine.

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.12+ | [python.org](https://www.python.org/downloads/) |
| Git | any | [git-scm.com](https://git-scm.com/downloads) |
| Ollama | latest | [ollama.com](https://ollama.com/download) |

> **Windows users:** During Python install, check **"Add Python to PATH"**.

---

## Quickstart

```bat
:: 1. Clone
git clone https://github.com/zacharyloganhill/threatpulse.git phantomfeed
cd phantomfeed

:: 2. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

:: 3. Install dependencies
pip install -r requirements.txt

:: 4. Configure
copy .env.example .env

:: 5. Pull an Ollama model (runs locally, one-time download ~2 GB)
ollama pull llama3.2

:: 6. Start PhantomFeed
python main.py
```

Then open **http://localhost:8000/dashboard.html** in your browser.

On first run, all feeds are polled immediately. The statusbar shows **● CONNECTED** when the API is live and **● AI: llama3.2** when Ollama is detected.

> **Optional:** Add API keys to `.env` for higher rate limits (see [Environment Variables](#environment-variables)).

---

## Feeds Ingested

### Vulnerability Intelligence

| Feed | Source | Interval | Notes |
|------|--------|----------|-------|
| NVD CVE API v2 | nvd.nist.gov | 15 min | Full CVSS, CPE, CWE metadata |
| CISA KEV | cisa.gov | 15 min | Actively exploited CVEs only |
| CISA Cyber Advisories | github.com/cisagov | 60 min | CSAF/IT — joint advisories, BODs |
| CISA ICS Advisories | github.com/cisagov | 60 min | CSAF/OT — SCADA, ICS, OT systems |

### Vendor Security Advisories

| Feed | Vendor | Source |
|------|--------|--------|
| Microsoft MSRC | Microsoft | msrc.microsoft.com |
| Cisco Security | Cisco | sec.cloudapps.cisco.com |
| Fortinet PSIRT | Fortinet | fortiguard.com |
| Palo Alto Networks | Palo Alto | security.paloaltonetworks.com |
| Red Hat Security | Red Hat | access.redhat.com |
| Ubuntu Security | Canonical | ubuntu.com |

### Threat Intelligence & Malware

| Feed | Source | Notes |
|------|--------|-------|
| abuse.ch URLhaus | urlhaus-api.abuse.ch | Live malware URLs and C2 infrastructure |
| abuse.ch Feodo Tracker | feodotracker.abuse.ch | Botnet C2 IP blocklist |
| AlienVault OTX | otx.alienvault.com | Threat pulses (free API key required) |

### Supply Chain

| Feed | Source | Notes |
|------|--------|-------|
| GitHub Advisory (npm) | github.com/advisories | Node.js package vulnerabilities |
| GitHub Advisory (PyPI) | github.com/advisories | Python package vulnerabilities |

---

## REST API

Base URL: `http://localhost:8000/api/v1`
Interactive docs: `http://localhost:8000/docs`

### Endpoints

```
GET    /items                  List items — filterable, searchable, paginated
GET    /items/{id}             Get a single item by ID
POST   /items/{id}/read        Mark item as read
POST   /items/read-all         Mark all items as read
GET    /stats                  Counts by severity, feed, and new/total
GET    /feeds                  List all registered feed IDs
POST   /refresh                Trigger immediate poll of all feeds
POST   /refresh/{feed_id}      Trigger poll of one specific feed
DELETE /items/purge            Delete items older than retention period
```

### Ollama Proxy

```
GET|POST  /api/ollama/{path}   Proxies to http://localhost:11434/{path}
```

Eliminates CORS issues between the dashboard and Ollama. The proxy streams responses so chat completions render token-by-token.

### Query Parameters for `GET /items`

| Param | Example | Description |
|-------|---------|-------------|
| `severity` | `CRITICAL,HIGH` | Comma-separated severity filter |
| `category` | `cve` | `cve` · `kev` · `advisory` · `vendor` · `ics` · `threat` · `malware` · `supply` |
| `feed_id` | `nvd` | Filter to a single source |
| `is_new` | `true` | Unread items only |
| `search` | `ivanti` | Full-text search: title, description, vendor, tags |
| `limit` | `50` | Page size (max 500) |
| `offset` | `0` | Pagination offset |

### Example curl Commands

```bash
# New critical and high items
curl "http://localhost:8000/api/v1/items?severity=CRITICAL,HIGH&is_new=true"

# Search for Ivanti
curl "http://localhost:8000/api/v1/items?search=ivanti"

# All ICS/OT advisories
curl "http://localhost:8000/api/v1/items?category=ics"

# CISA KEV only
curl "http://localhost:8000/api/v1/items?feed_id=cisa_kev"

# Force an immediate refresh of all feeds
curl -X POST "http://localhost:8000/api/v1/refresh"

# Stats
curl "http://localhost:8000/api/v1/stats"

# Check available Ollama models via proxy
curl "http://localhost:8000/api/ollama/api/tags"
```

---

## Phase 2 Features

### Asset Inventory & Exposure Matching

Upload a CSV of client assets — PhantomFeed automatically matches incoming threat items to affected software using CPE strings, vendor/product tokens, and keyword matching:

```
POST /api/v1/admin/clients/{id}/assets/import    CSV upload
GET  /api/v1/admin/clients/{id}/assets           List all assets
GET  /api/v1/items?client_id={id}&exposed_only=true  Only matched items
```

**CSV format** (columns: `hostname`, `ip_address`, `os`, `os_version`, `software`, `version`, `cpe_string`, `asset_type`):
```csv
hostname,ip_address,os,os_version,software,version
srv01,10.0.0.1,Windows,2019,Microsoft Windows Server,2019
web01,10.0.0.2,Linux,Ubuntu 22.04,Apache HTTP Server,2.4.58
```

Confidence tiers: **1.0** exact CPE · **0.85** CPE prefix · **0.8** vendor+product · **0.7** vendor keyword · **0.5** vendor-only.

### TAXII 2.1 / STIX Ingestion

Polls TAXII 2.1 servers for STIX bundles. Incremental polling via stored `added_after` timestamps.

Pre-configured sources:
- **CISA AIS** — `https://ais2.cisa.dhs.gov/taxii2/` (requires cert — [register at cisa.gov/ais](https://www.cisa.gov/ais))
- **CIRCL MISP** — public OSINT feed
- **AlienVault OTX TAXII** — uses `OTX_API_KEY` as credential

Add `TAXII_USERNAME`, `TAXII_PASSWORD`, `TAXII_CERT_PATH` to `.env`. Fetchers skip gracefully when credentials missing.

```
GET  /api/v1/taxii/sources          List configured servers and connection status
POST /api/v1/taxii/test/{feed_id}   Test connection to a TAXII feed
```

### Remediation SLA Tracking

Track vulnerability remediation with per-client SLA deadlines:

| Severity | Default SLA |
|----------|-------------|
| CRITICAL | 15 days     |
| HIGH     | 30 days     |
| MEDIUM   | 90 days     |
| LOW      | 180 days    |

Override per client in `stack_profile`:
```json
{"sla": {"CRITICAL": 7, "HIGH": 14}}
```

```
GET    /api/v1/clients/{id}/remediation        List remediation items + days remaining
POST   /api/v1/clients/{id}/remediation        Create remediation item
PATCH  /api/v1/clients/{id}/remediation/{rid}  Update status (open/in_progress/patched/accepted_risk/false_positive/wont_fix)
GET    /api/v1/clients/{id}/metrics            MTTR, SLA compliance rate, open/overdue counts
```

SLA overdue check runs daily at 07:00 UTC.

### Analytics Dashboard

Visit **http://localhost:8000/analytics.html** for the executive analytics view:

- **Threat volume trend** — 90-day line chart by severity (CRITICAL/HIGH/MEDIUM)
- **Severity distribution** — doughnut chart
- **Top vendors** — horizontal bar chart by risk volume
- **Category breakdown** — stacked bar by category + severity
- **Remediation MTTR trend** — avg days to patch over time
- **Top risk items** — ranked by composite risk score

Client selector dropdown switches all charts to a specific client's view. Date range: 30 / 60 / 90 days.

### IOC Enrichment Engine

Automatically enriches IPs, domains, URLs, and file hashes from malware/threat feeds. Cached for 24 hours.

```
GET /api/v1/ioc/lookup?value=8.8.8.8      Live enrichment (IP/hash/domain/URL)
GET /api/v1/ioc/cache                      Recent cache entries
```

IOC Lookup widget is also built into the dashboard detail pane — type any value in the Quick Actions section.

| API Key | Source | Enriches |
|---------|--------|---------|
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | IP reputation score + country |
| `GREYNOISE_API_KEY` | [greynoise.io](https://www.greynoise.io) | IP classification (benign/malicious/unknown) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com) | Hash/domain/URL detection ratio |

### SIEM Webhook Push

Configure webhooks per client to push new threat items to your SIEM or alerting platform:

```
POST   /api/v1/admin/clients/{id}/webhooks           Create webhook
GET    /api/v1/admin/clients/{id}/webhooks            List webhooks  
PUT    /api/v1/admin/clients/{id}/webhooks/{wid}      Update
DELETE /api/v1/admin/clients/{id}/webhooks/{wid}      Delete
POST   /api/v1/admin/clients/{id}/webhooks/{wid}/test Send test payload
```

**Supported types:**

| Type | Format | Auth |
|------|--------|------|
| `generic` | Plain JSON body | — |
| `slack` | Block Kit attachment with severity color | Webhook URL |
| `splunk_hec` | `{time, sourcetype:"phantomfeed:threat", event:{...}}` | `Authorization: Splunk {token}` |
| `sentinel` | Azure Monitor Log Analytics, HMAC-SHA256 signed | `{workspace_id}:{workspace_key}` in secret |

**Example — Slack webhook:**
```bash
curl -X POST http://localhost:8000/api/v1/admin/clients/{id}/webhooks \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"webhook_type":"slack","url":"https://hooks.slack.com/T.../...","min_severity":"HIGH"}'
```

**Example — Splunk HEC:**
```bash
curl -X POST http://localhost:8000/api/v1/admin/clients/{id}/webhooks \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"webhook_type":"splunk_hec","url":"https://splunk:8088/services/collector","secret":"your-hec-token","min_severity":"CRITICAL"}'
```

---

## Upload & Export Center

Visit **http://localhost:8000/upload.html** for the full Upload & Export center.

### Supported Upload Formats

| Format | Extension | Parser |
|--------|-----------|--------|
| Nessus scan | `.nessus` | Auto-detected; extracts assets + findings per host |
| Qualys XML | `.xml` | `<HOST>` and `<VULN>` elements |
| Qualys CSV | `.csv` | QID, Title, Severity, CVE ID columns |
| OpenVAS XML | `.xml` | `<report>` root, `<result>` with `<nvt>` children |
| Rapid7/InsightVM CSV | `.csv` | Asset IP Address, Vulnerability Title, Severity columns |
| Generic CSV/XLSX | `.csv`, `.xlsx` | Fuzzy column mapping (auto-detects hostname/IP/severity/CVE columns) |
| IOC list (plain text) | `.txt` | One IOC per line; auto-detects IPs, hashes, domains, URLs |
| IOC list (JSON) | `.json` | Array of `{type, value}` or STIX 2.1 Indicator patterns |
| STIX 2.1 bundle | `.json` | Full bundle; imports Indicator, Malware, Threat-Actor, Vulnerability objects |
| Bulk clients | `.csv` | Columns: name, industry, contact_email, min_severity, vendors, products |

Download templates: `GET /api/v1/upload/templates/{assets|clients|iocs}`

### Upload API

```
POST /api/v1/upload/scan                  Auto-detect and preview scan file
POST /api/v1/upload/scan/{id}/confirm     Confirm and import (with optional field mapping)
POST /api/v1/upload/assets                Preview asset CSV/XLSX
POST /api/v1/upload/assets/{id}/confirm   Confirm asset import
POST /api/v1/upload/iocs                  Import IOC list (enrichment triggered in background)
POST /api/v1/upload/stix                  Import STIX 2.1 bundle directly
POST /api/v1/upload/clients               Bulk client preview
POST /api/v1/upload/clients/{id}/confirm  Confirm bulk client import
GET  /api/v1/upload/history               Upload log (filter by client_id)
GET  /api/v1/upload/templates/{type}      Download CSV template
```

### Export API

```
GET /api/v1/export/items.csv             Threat items as CSV (severity, category, search, days filters)
GET /api/v1/export/items.json            Threat items as JSON
GET /api/v1/export/iocs.txt?days=7       IOC plain text list
GET /api/v1/export/iocs.csv?days=7       IOC list as CSV with enrichment data
GET /api/v1/export/iocs.stix?days=7      IOC list as STIX 2.1 Bundle JSON
GET /api/v1/clients/{id}/export/remediation.csv   Remediation tracker CSV
GET /api/v1/clients/{id}/export/remediation.xlsx  Remediation tracker XLSX (color-coded)
GET /api/v1/clients/{id}/export/detection-rules.zip  SPL + KQL + Sigma ZIP
POST /api/v1/clients/{id}/export/push-rules-github   Push rules to GitHub repo
GET /api/v1/clients/{id}/report.html?days=30  HTML report preview with Download PDF button
```

**Detection Rules ZIP** contains:
- `splunk/` — Splunk SPL searches per CRITICAL/HIGH item
- `sentinel/` — Microsoft Sentinel KQL queries
- `sigma/` — Sigma YAML rules (convert with sigmac or pySigma)

---

## Quick Actions (AI Analyst)

Each item in the dashboard has four **Quick Actions** that send a pre-built prompt to your local Ollama model:

| Action | What it produces |
|--------|-----------------|
| **Draft Client Advisory** | Non-technical advisory email ready to send to affected clients |
| **Generate Detection Rules** | Splunk SPL, Microsoft Sentinel KQL, and a Sigma rule |
| **Get IOCs & Hunting Queries** | File hashes, IPs, domains, registry keys, YARA snippets |
| **Analyze Client Impact** | Exposure assessment questions and at-risk asset types |

Responses stream in real-time in the AI panel. Everything runs locally via Ollama — **zero cost, zero data sent externally.**

---

## Architecture

```
phantomfeed/
├── main.py                  # FastAPI app, lifespan, CORS, Ollama proxy, static files
├── config.py                # Feed URLs, API keys, severity mappings, settings
├── dashboard.html           # Dark-mode web dashboard (served at /dashboard.html)
├── .env                     # Your local secrets — never commit this
├── .env.example             # Template — copy to .env to get started
├── requirements.txt
│
├── db/
│   └── database.py          # Async SQLite: connect, CRUD, deduplication
│
├── ingest/
│   ├── base.py              # BaseFetcher: HTTP helpers, retries, normalization
│   ├── nvd.py               # NVD CVE API v2
│   ├── cisa.py              # CISA KEV + CSAF advisories (IT + OT)
│   ├── rss_feeds.py         # Generic vendor RSS ingestion
│   ├── threat_intel.py      # abuse.ch, OTX, supply chain
│   └── scheduler.py         # APScheduler: per-feed poll intervals
│
└── api/
    └── routes.py            # All REST endpoints
```

### Adding a New Feed

1. Create a class in `ingest/` that inherits `BaseFetcher`
2. Set `feed_id`, `feed_label`, `category`, and `poll_interval`
3. Implement `async def fetch(self) -> list[dict]`
4. Register it in `ingest/scheduler.py` → `_build_fetchers()`

For simple RSS sources, just add an entry to `VENDOR_RSS_FEEDS` in `config.py` — no code required.

---

## Environment Variables

Copy `.env.example` to `.env` and set values as needed. All variables are optional except the server defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(empty)* | NVD API key — [get one free](https://nvd.nist.gov/developers/request-an-api-key). Raises rate limit from 5 to 50 req/30s |
| `OTX_API_KEY` | *(empty)* | AlienVault OTX key — [get one free](https://otx.alienvault.com). Required for OTX pulses |
| `URLHAUS_API_KEY` | *(empty)* | abuse.ch key — [get one free](https://auth.abuse.ch/). Increases URLhaus access |
| `POLL_INTERVAL_FAST` | `15` | Polling interval for high-priority feeds (minutes) |
| `POLL_INTERVAL_SLOW` | `60` | Polling interval for vendor/intel feeds (minutes) |
| `HOST` | `127.0.0.1` | API bind address |
| `PORT` | `8000` | API port |
| `DB_PATH` | `./phantomfeed.db` | SQLite database file path |
| `RETENTION_DAYS` | `90` | Days of history to retain before purge |
| `NVD_PAGE_SIZE` | `200` | CVEs fetched per NVD API page (max 2000) |

---

## Phase 3 — Market Differentiators

### Dark Web & Paste Site Monitoring

Monitors dark web data breach sources for client name mentions:

| Monitor | Source | Notes |
|---------|--------|-------|
| RansomWatch | github.com/joshhighet/ransomwatch | Ransomware group victim posts — fuzzy name matching |
| Pastebin Scraper | scrape.pastebin.com | Requires Pastebin Pro account |
| GitHub Gists | api.github.com/gists/public | Public gist leak detection |
| HIBP Domain Breach | haveibeenpwned.com | Domain breach lookup (API key required) |

```
GET  /api/v1/clients/{id}/darkweb-alerts                    List alerts (unacknowledged_only filter)
POST /api/v1/clients/{id}/darkweb-alerts/{alert_id}/acknowledge
POST /api/v1/clients/{id}/darkweb-scan                      Trigger immediate scan
GET  /api/v1/notifications                                  Aggregated notification center
```

Dark web alerts appear in the client dashboard notification center and Dark Web tab.

### Threat Actor Dossier Database

55 tracked threat actors with MITRE ATT&CK alignment:

- APT1, APT10, APT28, APT29, APT32, APT34, APT38, APT40, APT41
- Lazarus Group, Sandworm, Volt Typhoon, Scattered Spider, BlackCat, LockBit, Cl0p, and more

Each actor dossier includes: origin, sponsor, motivation, TTPs (MITRE IDs), known malware, target industries, recent activity.

Open **http://localhost:8000/actors.html** to browse the full dossier browser.

```
GET /api/v1/actors                              List all actors (filterable by origin/motivation)
GET /api/v1/actors/{id}                         Full dossier
GET /api/v1/actors/{id}/items                   Threat items linked to this actor
GET /api/v1/clients/{id}/actor-alerts           Actors targeting client's industry
```

### MISP Integration

Pull and push threat events from/to a MISP instance:

```env
MISP_URL=https://your-misp-instance
MISP_API_KEY=your_api_key
MISP_VERIFY_SSL=true
```

```
GET  /api/v1/misp/status          Connection status
POST /api/v1/misp/sync            Trigger MISP event pull (background)
GET  /api/v1/misp/events          Recently pulled MISP events
POST /api/v1/misp/push/{item_id}  Push a PhantomFeed item to MISP
```

### Automated Executive Briefing Deck

Generate a 12-slide PowerPoint briefing deck with AI-written summaries and matplotlib charts.

```
GET /api/v1/clients/{id}/deck.pptx?days=30     Download PPTX (supports ?token= for window.open)
GET /api/v1/clients/{id}/deck-preview           JSON slide outline for preview
```

Slides: Title → Executive Summary (Ollama AI) → Threat Landscape → Top 5 Threats → CISA KEV → Threat Actors → Vendor Risk Bar Chart → Compliance Impact → Asset Exposure → Remediation Donut Chart → Recommended Actions (AI) → Contact

Requires: `pip install python-pptx matplotlib Pillow` (included in requirements.txt)

### Peer Benchmarking Engine

Calculate a 0–100 posture score and industry percentile ranking:

| Component | Weight | Metric |
|-----------|--------|--------|
| SLA Compliance | 30 pts | % remediations closed before SLA deadline |
| MTTR | 30 pts | Mean time to remediate vs industry median |
| Open Criticals | 20 pts | Inverted count of open CRITICAL items |
| Patch Velocity | 20 pts | Items patched in last 30 days / total open |

Industry baselines for 9 sectors: Technology, Finance, Healthcare, Government, Retail, Energy, Education, Manufacturing, Legal.

```
GET /api/v1/clients/{id}/posture            Current score, grade, percentile, component breakdown
GET /api/v1/clients/{id}/posture/history    Historical score snapshots
GET /api/v1/benchmarks/{industry}           Industry baseline statistics
GET /api/v1/benchmarks                      All clients ranked by score
```

### CMMC 2.0 Dynamic Gap Assessment

All 110 NIST SP 800-171 Rev 2 / CMMC Level 2 practices across 14 domains.

Open **http://localhost:8000/cmmc.html** for the full interactive gap assessment UI.

- Auto-derived status from active threat intelligence (compliance_tags mapping)
- Manual override per practice with notes
- Bulk update and CSV export
- Domain-level scoring and overall compliance percentage

```
GET    /api/v1/clients/{id}/cmmc/assessment
PATCH  /api/v1/clients/{id}/cmmc/practices/{practice_id}
POST   /api/v1/clients/{id}/cmmc/bulk-update
GET    /api/v1/cmmc/practices?domain=Access+Control
```

### Tabletop Exercise Generator

AI-powered tabletop exercises with 8 scenario types:

`ransomware` · `supply_chain` · `data_breach` · `insider_threat` · `ddos` · `phishing` · `zero_day` · `cloud_breach`

Each exercise includes: scenario overview, 5 exercise objectives, per-phase situation+inject+discussion questions+expected actions, debrief questions. Exports to PDF (reportlab) and PPTX (python-pptx).

```
GET  /api/v1/clients/{id}/tabletops
POST /api/v1/clients/{id}/tabletops/generate    {scenario_type, custom_prompt}
GET  /api/v1/clients/{id}/tabletops/{id}/export.pdf
GET  /api/v1/clients/{id}/tabletops/{id}/export.pptx
GET  /api/v1/tabletop/scenario-types
```

### Supply Chain Risk Graph

Track vendor software exposure with a D3.js force-directed risk graph.

Open **http://localhost:8000/supplychain.html** for the interactive graph view.

```
GET    /api/v1/clients/{id}/vendors                List vendors with risk levels
POST   /api/v1/clients/{id}/vendors                Add vendor {vendor_name, products, criticality}
DELETE /api/v1/clients/{id}/vendors/{vendor_id}    Remove vendor
POST   /api/v1/clients/{id}/vendors/scan           Trigger background risk scoring
GET    /api/v1/clients/{id}/supply-chain-graph     D3.js {nodes, links} graph data
```

Vendors are risk-scored by scanning the threat feed for name/product matches. Red = high risk, amber = medium, green = low.

### Breach Cost & ROI Calculator

Expected financial loss per threat item using IBM Cost of a Data Breach Report 2024 models:

| Industry | Average Breach Cost |
|----------|---------------------|
| Healthcare | $9.77M |
| Finance | $6.08M |
| Technology | $5.10M |
| Energy | $4.72M |
| Manufacturing | $4.20M |

```
GET /api/v1/clients/{id}/risk-portfolio     Full portfolio: total exposure, patched vs unpatched, ROI ratios, top 20 items
GET /api/v1/breach-cost/industries          IBM 2024 baseline by industry
```

Risk Portfolio is displayed in the client dashboard's Risk Portfolio tab with `$` exposure amounts and patch ROI ratios.

---

## Pages

| URL | Description |
|-----|-------------|
| `/dashboard.html` | Main threat feed — real-time, filterable, AI analyst |
| `/analytics.html` | Charts: trend, vendor, category, MTTR, heatmap |
| `/actors.html` | Threat actor dossier browser with ATT&CK heatmap |
| `/cmmc.html` | CMMC 2.0 gap assessment — 110 practices, 14 domains |
| `/supplychain.html` | Supply chain risk graph (D3.js force-directed) |
| `/upload.html` | Scan upload center and export tools |
| `/admin.html` | Client management, assets, users, exports |
| `/client_dashboard.html?client_id={id}` | Per-client portal with all Phase 3 features |
| `/fedramp.html` | FedRAMP 20x compliance dashboard (KSI, OSCAL, scanners, SIEMs) |

---

## FedRAMP 20x Compliance Features

PhantomFeed includes a full FedRAMP 20x continuous monitoring capability suite.

### Section 1 — Automated Scanner Pulls

| Scanner | Auth Method | Notes |
|---------|-------------|-------|
| Tenable.io | `X-ApiKeys` header (accessKey + secretKey) | Export API + workbench fallback |
| Tenable.sc | Session token (`/rest/token`) | On-prem; set `extra_config.mode=sc` |
| Rapid7 InsightVM | HTTP Basic auth | Paginated asset + vuln endpoints |
| Qualys VMDR | Basic auth + `X-Requested-With` | XML detection API |
| CrowdStrike Spotlight | OAuth2 client_credentials | Two-phase query + detail fetch |

All credentials are **Fernet-encrypted** at rest. Set `PHANTOMFEED_ENCRYPTION_KEY` in `.env`:

```
PHANTOMFEED_ENCRYPTION_KEY=<base64-url-safe-32-byte-key>
# Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Scanner API endpoints (prefix: `/api/v1/clients/{id}/`):

| Method | Path | Description |
|--------|------|-------------|
| GET | `scanners` | List scanner configs (credentials masked) |
| POST | `scanners` | Add scanner config |
| PATCH | `scanners/{scanner_id}` | Update config |
| DELETE | `scanners/{scanner_id}` | Delete scanner + findings |
| POST | `scanners/{scanner_id}/poll` | Trigger immediate poll |
| GET | `scan-findings` | List findings (filterable by severity, scanner) |
| GET | `scan-findings/summary` | Severity counts + scanner status |

### Section 2 — SIEM Integrations

| SIEM | Auth Method | Notes |
|------|-------------|-------|
| Splunk | Session key (`/services/auth/login`) | Saved-search job polling |
| Microsoft Sentinel | Azure AD client_credentials OAuth2 | Log Analytics KQL query |
| IBM QRadar | `SEC` token header | Offenses API with pagination |
| Elastic Security | `ApiKey` header | Detection signals + fallback alerts API |

SIEM endpoints: same pattern as scanners at `/api/v1/clients/{id}/siems/...`

### Section 3 — OSCAL Output Engine

| Document | Format | Description |
|----------|--------|-------------|
| POA&M | XML | Open remediation items as OSCAL plan-of-action-and-milestones |
| SAR | XML | Scan findings as OSCAL assessment-results |
| VDR | JSON | CVE-tagged vulnerabilities with asset mapping |
| OAR | JSON | Posture score, authorization decision, CM activity log |
| SSP (partial) | XML | System characteristics + 8 control implementation stubs |
| Bundle | ZIP | All 5 documents in one download |

OSCAL endpoints: `GET /api/v1/clients/{id}/oscal/{type}.{ext}` and `/oscal/bundle.zip`

### Section 4 — KSI Validation Engine

Seven Key Security Indicators validated automatically every 6 hours:

| KSI | Category | Pass Threshold |
|-----|----------|----------------|
| KSI-1 | Vulnerability Management | No CRITICAL/HIGH CVEs open > 15/30 days |
| KSI-2 | Patch Currency | ≥90% patch rate |
| KSI-3 | Continuous Monitoring | All scanners polled within interval + 2h |
| KSI-4 | Incident Detection | ≥1 active SIEM with recent data |
| KSI-5 | POA&M Timeliness | 0 overdue CRITICAL remediations |
| KSI-6 | Supply Chain | ≥80% vendors assessed within 30 days |
| KSI-7 | Dark Web Exposure | No unacknowledged alerts > 48 hours |

KSI API: `GET /api/v1/clients/{id}/ksi`, `POST /api/v1/clients/{id}/ksi/validate`

### Section 6 — Audit Log

Every API call is logged to the `audit_log` table (event type, user, client, method, path, status, IP, duration). Export as CSV:

- `GET /api/v1/audit` — global audit log (admin)
- `GET /api/v1/clients/{id}/audit` — per-client audit log
- `GET /api/v1/clients/{id}/audit.csv` — CSV export

---

## Contributing

PRs and issues are welcome. If you add a new feed source, fix a parser, or improve the dashboard — open a pull request. If a feed is broken or returning bad data, open an issue with the feed ID and a sample of what you're seeing.

---

## License

MIT — do whatever you want with it.
