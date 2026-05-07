"""
ThreatPulse — Database Layer
Async SQLite via aiosqlite. Single table with full-text search support.
"""

import json
import hashlib
import uuid
import aiosqlite
from datetime import datetime, timedelta
from typing import Optional

import config

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS threat_items (
    id              TEXT PRIMARY KEY,
    feed_id         TEXT NOT NULL,
    feed_label      TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'INFO',
    cvss            REAL,
    title           TEXT NOT NULL,
    vendor          TEXT,
    product         TEXT,
    description     TEXT,
    url             TEXT,
    published_at    TEXT,
    fetched_at      TEXT NOT NULL,
    tags            TEXT DEFAULT '[]',
    cve_ids         TEXT DEFAULT '[]',
    is_new          INTEGER DEFAULT 1,
    is_read         INTEGER DEFAULT 0,
    raw             TEXT,
    risk_score      REAL,
    compliance_tags TEXT DEFAULT '[]'
);
"""

MIGRATIONS = [
    "ALTER TABLE threat_items ADD COLUMN risk_score REAL;",
    "ALTER TABLE threat_items ADD COLUMN compliance_tags TEXT DEFAULT '[]';",
]

CREATE_CLIENTS_TABLE = """
CREATE TABLE IF NOT EXISTS clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    contact_email TEXT,
    stack_profile TEXT DEFAULT '{}',
    created_at    TEXT NOT NULL
);
"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    client_id     TEXT,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_TAXII_STATE = """
CREATE TABLE IF NOT EXISTS taxii_state (
    feed_id TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""

CREATE_CLIENT_ASSETS = """
CREATE TABLE IF NOT EXISTS client_assets (
    id          TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    hostname    TEXT,
    ip_address  TEXT,
    os          TEXT,
    os_version  TEXT,
    software    TEXT NOT NULL,
    version     TEXT,
    cpe_string  TEXT,
    asset_type  TEXT DEFAULT 'workstation',
    created_at  TEXT,
    updated_at  TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_ASSET_EXPOSURES = """
CREATE TABLE IF NOT EXISTS asset_exposures (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    asset_id     TEXT NOT NULL,
    match_type   TEXT,
    confidence   REAL,
    confirmed_at TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (item_id)   REFERENCES threat_items(id),
    FOREIGN KEY (asset_id)  REFERENCES client_assets(id)
);
"""

CREATE_REMEDIATION = """
CREATE TABLE IF NOT EXISTS remediation_items (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    status       TEXT DEFAULT 'open',
    priority     INTEGER DEFAULT 0,
    assigned_to  TEXT,
    due_date     TEXT,
    patched_date TEXT,
    notes        TEXT,
    created_at   TEXT,
    updated_at   TEXT,
    sla_days     INTEGER,
    is_overdue   INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (item_id)   REFERENCES threat_items(id)
);
"""

CREATE_IOC_CACHE = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc_value                TEXT PRIMARY KEY,
    ioc_type                 TEXT NOT NULL,
    abuseipdb_score          INTEGER,
    abuseipdb_country        TEXT,
    vt_malicious             INTEGER,
    vt_total                 INTEGER,
    vt_name                  TEXT,
    greynoise_classification TEXT,
    greynoise_name           TEXT,
    enriched_at              TEXT,
    expires_at               TEXT
);
"""

CREATE_WEBHOOK_CONFIGS = """
CREATE TABLE IF NOT EXISTS webhook_configs (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    webhook_type TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret       TEXT,
    min_severity TEXT DEFAULT 'HIGH',
    categories   TEXT DEFAULT '[]',
    is_active    INTEGER DEFAULT 1,
    last_fired   TEXT,
    created_at   TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_WEBHOOK_ERRORS = """
CREATE TABLE IF NOT EXISTS webhook_errors (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT NOT NULL,
    error        TEXT,
    created_at   TEXT
);
"""

CREATE_UPLOAD_LOG = """
CREATE TABLE IF NOT EXISTS upload_log (
  id               TEXT PRIMARY KEY,
  filename         TEXT NOT NULL,
  file_type        TEXT NOT NULL,
  client_id        TEXT,
  status           TEXT DEFAULT 'pending',
  records_total    INTEGER DEFAULT 0,
  records_imported INTEGER DEFAULT 0,
  records_skipped  INTEGER DEFAULT 0,
  error_message    TEXT,
  uploaded_at      TEXT,
  completed_at     TEXT
);
"""

CREATE_DARKWEB_ALERTS = """
CREATE TABLE IF NOT EXISTS darkweb_alerts (
    id               TEXT PRIMARY KEY,
    client_id        TEXT NOT NULL,
    alert_type       TEXT NOT NULL,
    source           TEXT NOT NULL,
    matched_term     TEXT,
    content_preview  TEXT,
    url              TEXT,
    detected_at      TEXT,
    is_acknowledged  INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_DARKWEB_SEEN = """
CREATE TABLE IF NOT EXISTS darkweb_seen (
    id        TEXT PRIMARY KEY,
    source    TEXT NOT NULL,
    seen_at   TEXT NOT NULL
);
"""

CREATE_THREAT_ACTORS = """
CREATE TABLE IF NOT EXISTS threat_actors (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    aliases           TEXT DEFAULT '[]',
    origin            TEXT,
    sponsor           TEXT,
    motivation        TEXT,
    active_since      TEXT,
    target_industries TEXT DEFAULT '[]',
    ttps              TEXT DEFAULT '[]',
    known_malware     TEXT DEFAULT '[]',
    description       TEXT,
    recent_activity   TEXT DEFAULT 'Unknown',
    last_seen         TEXT,
    ioc_count         INTEGER DEFAULT 0,
    item_count        INTEGER DEFAULT 0
);
"""

CREATE_ACTOR_ITEM_LINKS = """
CREATE TABLE IF NOT EXISTS actor_item_links (
    id        TEXT PRIMARY KEY,
    actor_id  TEXT NOT NULL,
    item_id   TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    FOREIGN KEY (actor_id) REFERENCES threat_actors(id),
    FOREIGN KEY (item_id)  REFERENCES threat_items(id),
    UNIQUE(actor_id, item_id)
);
"""

CREATE_CLIENT_VENDORS = """
CREATE TABLE IF NOT EXISTS client_vendors (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    vendor_name  TEXT NOT NULL,
    vendor_type  TEXT,
    criticality  TEXT DEFAULT 'medium',
    data_types   TEXT DEFAULT '[]',
    contact_email TEXT,
    created_at   TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_VENDOR_EXPOSURES = """
CREATE TABLE IF NOT EXISTS vendor_exposures (
    id          TEXT PRIMARY KEY,
    vendor_id   TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    detected_at TEXT,
    FOREIGN KEY (vendor_id) REFERENCES client_vendors(id),
    FOREIGN KEY (item_id)   REFERENCES threat_items(id)
);
"""

CREATE_POSTURE_SCORES = """
CREATE TABLE IF NOT EXISTS posture_scores (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL,
    score               REAL NOT NULL,
    grade               TEXT NOT NULL,
    percentile          REAL,
    sla_component       REAL,
    mttr_component      REAL,
    open_crit_component REAL,
    velocity_component  REAL,
    calculated_at       TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_CMMC_ASSESSMENTS = """
CREATE TABLE IF NOT EXISTS cmmc_assessments (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    level1_score  REAL,
    level2_score  REAL,
    practices_json TEXT DEFAULT '[]',
    assessed_at   TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_TABLETOP_EXERCISES = """
CREATE TABLE IF NOT EXISTS tabletop_exercises (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    title         TEXT,
    scenario_type TEXT,
    generated_at  TEXT,
    conducted_at  TEXT,
    participants  INTEGER,
    scenario_json TEXT,
    debrief_notes TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_KSI_RESULTS = """
CREATE TABLE IF NOT EXISTS ksi_results (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    ksi_id        TEXT NOT NULL,
    ksi_name      TEXT NOT NULL,
    status        TEXT NOT NULL,
    score         REAL NOT NULL,
    details       TEXT DEFAULT '{}',
    validated_at  TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_SIEM_CONFIGS = """
CREATE TABLE IF NOT EXISTS siem_configs (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL,
    siem_type           TEXT NOT NULL,
    label               TEXT NOT NULL,
    host_url            TEXT,
    api_key_enc         TEXT,
    secret_key_enc      TEXT,
    username_enc        TEXT,
    password_enc        TEXT,
    extra_config        TEXT DEFAULT '{}',
    poll_interval_hours INTEGER DEFAULT 6,
    is_active           INTEGER DEFAULT 1,
    last_polled         TEXT,
    last_status         TEXT DEFAULT 'never',
    created_at          TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_SCANNER_CONFIGS = """
CREATE TABLE IF NOT EXISTS scanner_configs (
    id                  TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL,
    scanner_type        TEXT NOT NULL,
    label               TEXT NOT NULL,
    host_url            TEXT,
    api_key_enc         TEXT,
    secret_key_enc      TEXT,
    username_enc        TEXT,
    password_enc        TEXT,
    extra_config        TEXT DEFAULT '{}',
    poll_interval_hours INTEGER DEFAULT 6,
    is_active           INTEGER DEFAULT 1,
    last_polled         TEXT,
    last_status         TEXT DEFAULT 'never',
    created_at          TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_SCAN_FINDINGS = """
CREATE TABLE IF NOT EXISTS scan_findings (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    scanner_id      TEXT NOT NULL,
    scanner_type    TEXT NOT NULL,
    asset_id        TEXT,
    hostname        TEXT,
    ip_address      TEXT,
    cve_id          TEXT,
    plugin_id       TEXT,
    severity        TEXT NOT NULL DEFAULT 'INFO',
    cvss            REAL,
    title           TEXT NOT NULL,
    description     TEXT,
    solution        TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    threat_item_id  TEXT,
    raw             TEXT,
    FOREIGN KEY (client_id)     REFERENCES clients(id),
    FOREIGN KEY (scanner_id)    REFERENCES scanner_configs(id),
    FOREIGN KEY (threat_item_id) REFERENCES threat_items(id)
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_severity   ON threat_items(severity);",
    "CREATE INDEX IF NOT EXISTS idx_category   ON threat_items(category);",
    "CREATE INDEX IF NOT EXISTS idx_feed_id    ON threat_items(feed_id);",
    "CREATE INDEX IF NOT EXISTS idx_published  ON threat_items(published_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_fetched    ON threat_items(fetched_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_is_new     ON threat_items(is_new);",
]

PHASE3_MIGRATIONS = [
    "ALTER TABLE clients ADD COLUMN industry TEXT;",
    "ALTER TABLE clients ADD COLUMN logo_path TEXT;",
    "ALTER TABLE clients ADD COLUMN brand_color TEXT;",
    "ALTER TABLE clients ADD COLUMN cmmc_assessment_date TEXT;",
    "ALTER TABLE threat_items ADD COLUMN expected_loss REAL;",
    "ALTER TABLE threat_items ADD COLUMN remediation_cost REAL;",
    "ALTER TABLE threat_items ADD COLUMN epss_score REAL;",
    "ALTER TABLE client_vendors ADD COLUMN products TEXT DEFAULT '[]';",
    "ALTER TABLE client_vendors ADD COLUMN category TEXT DEFAULT '';",
    "ALTER TABLE client_vendors ADD COLUMN threat_level TEXT DEFAULT 'unknown';",
    "ALTER TABLE client_vendors ADD COLUMN risk_data TEXT DEFAULT '{}';",
]

_db: Optional[aiosqlite.Connection] = None


async def connect() -> aiosqlite.Connection:
    global _db
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL;")
    await _db.execute("PRAGMA foreign_keys=ON;")
    await _db.execute(CREATE_TABLE)
    await _db.execute(CREATE_CLIENTS_TABLE)
    await _db.execute(CREATE_USERS_TABLE)
    await _db.execute(CREATE_TAXII_STATE)
    await _db.execute(CREATE_CLIENT_ASSETS)
    await _db.execute(CREATE_ASSET_EXPOSURES)
    await _db.execute(CREATE_REMEDIATION)
    await _db.execute(CREATE_IOC_CACHE)
    await _db.execute(CREATE_WEBHOOK_CONFIGS)
    await _db.execute(CREATE_WEBHOOK_ERRORS)
    await _db.execute(CREATE_UPLOAD_LOG)
    await _db.execute(CREATE_DARKWEB_ALERTS)
    await _db.execute(CREATE_DARKWEB_SEEN)
    await _db.execute(CREATE_THREAT_ACTORS)
    await _db.execute(CREATE_ACTOR_ITEM_LINKS)
    await _db.execute(CREATE_CLIENT_VENDORS)
    await _db.execute(CREATE_VENDOR_EXPOSURES)
    await _db.execute(CREATE_POSTURE_SCORES)
    await _db.execute(CREATE_CMMC_ASSESSMENTS)
    await _db.execute(CREATE_TABLETOP_EXERCISES)
    await _db.execute(CREATE_KSI_RESULTS)
    await _db.execute(CREATE_SIEM_CONFIGS)
    await _db.execute(CREATE_SCANNER_CONFIGS)
    await _db.execute(CREATE_SCAN_FINDINGS)
    for idx in CREATE_INDEXES:
        await _db.execute(idx)
    for migration in MIGRATIONS + PHASE3_MIGRATIONS:
        try:
            await _db.execute(migration)
        except Exception:
            pass
    await _db.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_score ON threat_items(risk_score DESC);"
    )
    await _db.commit()
    return _db


async def close():
    global _db
    if _db:
        await _db.close()
        _db = None


def get_db() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Database not connected. Call connect() first.")
    return _db


def make_id(feed_id: str, title: str, published: str) -> str:
    """Deterministic ID for deduplication — same item always gets same ID."""
    raw = f"{feed_id}:{title.lower().strip()}:{published}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


async def upsert_item(item: dict) -> bool:
    """
    Insert or ignore a threat item. Returns True if it was a new insertion.
    We never update existing items — the original fetch is canonical.
    """
    db = get_db()
    item_id = item.get("id") or make_id(
        item["feed_id"], item["title"], item.get("published_at", "")
    )
    now = datetime.utcnow().isoformat()

    sql = """
    INSERT OR IGNORE INTO threat_items
        (id, feed_id, feed_label, category, severity, cvss, title,
         vendor, product, description, url, published_at, fetched_at,
         tags, cve_ids, is_new, is_read, raw, risk_score, compliance_tags)
    VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?,?,?)
    """
    params = (
        item_id,
        item.get("feed_id", ""),
        item.get("feed_label", ""),
        item.get("category", "advisory"),
        item.get("severity", "INFO"),
        item.get("cvss"),
        item.get("title", "(no title)"),
        item.get("vendor"),
        item.get("product"),
        item.get("description"),
        item.get("url"),
        item.get("published_at"),
        now,
        json.dumps(item.get("tags", [])),
        json.dumps(item.get("cve_ids", [])),
        json.dumps(item.get("raw")),
        item.get("risk_score"),
        json.dumps(item.get("compliance_tags", [])),
    )
    cursor = await db.execute(sql, params)
    await db.commit()
    return cursor.rowcount > 0


async def update_risk_score(item_id: str, risk_score: float):
    """Update risk_score for an existing item (rescore endpoint)."""
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET risk_score = ? WHERE id = ?",
        (risk_score, item_id),
    )
    await db.commit()


async def update_compliance_tags(item_id: str, tags: list[str]):
    """Update compliance_tags for an existing item."""
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET compliance_tags = ? WHERE id = ?",
        (json.dumps(tags), item_id),
    )
    await db.commit()


async def get_items(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    feed_id: Optional[str] = None,
    is_new: Optional[bool] = None,
    search: Optional[str] = None,
    compliance: Optional[str] = None,
    client_id: Optional[str] = None,
    sort: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    stack_vendors: Optional[list] = None,
    stack_products: Optional[list] = None,
) -> list[dict]:
    db = get_db()
    conditions = []
    params = []

    if severity:
        sevs = [s.strip().upper() for s in severity.split(",")]
        placeholders = ",".join("?" * len(sevs))
        conditions.append(f"severity IN ({placeholders})")
        params.extend(sevs)
    if category:
        conditions.append("category = ?")
        params.append(category)
    if feed_id:
        conditions.append("feed_id = ?")
        params.append(feed_id)
    if is_new is not None:
        conditions.append("is_new = ?")
        params.append(1 if is_new else 0)
    if search:
        conditions.append(
            "(title LIKE ? OR description LIKE ? OR vendor LIKE ? OR tags LIKE ? OR cve_ids LIKE ?)"
        )
        q = f"%{search}%"
        params.extend([q, q, q, q, q])
    if compliance:
        # compliance_tags is a JSON array; filter items that contain the tag
        tag = compliance.lower().strip()
        conditions.append("LOWER(compliance_tags) LIKE ?")
        params.append(f"%{tag}%")
    if client_id:
        pass  # client_id filtering handled via stack_vendors/stack_products
    if stack_vendors or stack_products:
        parts = []
        for v in (stack_vendors or []):
            pct = f"%{v}%"
            parts.append("(LOWER(vendor) LIKE ? OR LOWER(title) LIKE ? OR LOWER(COALESCE(tags,'')) LIKE ?)")
            params.extend([pct, pct, pct])
        for p in (stack_products or []):
            pct = f"%{p}%"
            parts.append("(LOWER(product) LIKE ? OR LOWER(title) LIKE ? OR LOWER(COALESCE(tags,'')) LIKE ?)")
            params.extend([pct, pct, pct])
        conditions.append("(" + " OR ".join(parts) + ")")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    if sort == "risk":
        order = "ORDER BY COALESCE(risk_score, 0) DESC, published_at DESC"
    else:
        order = """ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            published_at DESC"""

    sql = f"SELECT * FROM threat_items {where} {order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    async with db.execute(sql, params) as cursor:
        rows = await cursor.fetchall()
    return [_row_to_dict(r) for r in rows]


async def get_item(item_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM threat_items WHERE id = ?", (item_id,)) as cur:
        row = await cur.fetchone()
    return _row_to_dict(row) if row else None


async def mark_read(item_id: str):
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET is_read = 1, is_new = 0 WHERE id = ?", (item_id,)
    )
    await db.commit()


async def mark_all_read(feed_id: Optional[str] = None):
    db = get_db()
    if feed_id:
        await db.execute(
            "UPDATE threat_items SET is_read = 1, is_new = 0 WHERE feed_id = ?",
            (feed_id,),
        )
    else:
        await db.execute("UPDATE threat_items SET is_read = 1, is_new = 0")
    await db.commit()


async def get_stats() -> dict:
    db = get_db()
    stats = {}

    # Counts by severity
    async with db.execute(
        "SELECT severity, COUNT(*) as cnt FROM threat_items GROUP BY severity"
    ) as cur:
        stats["by_severity"] = {r["severity"]: r["cnt"] for r in await cur.fetchall()}

    # Counts by category
    async with db.execute(
        "SELECT category, COUNT(*) as cnt FROM threat_items GROUP BY category"
    ) as cur:
        stats["by_category"] = {r["category"]: r["cnt"] for r in await cur.fetchall()}

    # Counts by feed
    async with db.execute(
        "SELECT feed_id, feed_label, COUNT(*) as cnt FROM threat_items GROUP BY feed_id"
    ) as cur:
        stats["by_feed"] = [
            {"feed_id": r["feed_id"], "label": r["feed_label"], "count": r["cnt"]}
            for r in await cur.fetchall()
        ]

    # New / unread
    async with db.execute("SELECT COUNT(*) as cnt FROM threat_items WHERE is_new = 1") as cur:
        stats["new_count"] = (await cur.fetchone())["cnt"]

    async with db.execute("SELECT COUNT(*) as cnt FROM threat_items") as cur:
        stats["total"] = (await cur.fetchone())["cnt"]

    # Last ingested
    async with db.execute("SELECT MAX(fetched_at) as last FROM threat_items") as cur:
        stats["last_ingested"] = (await cur.fetchone())["last"]

    # Client count
    async with db.execute("SELECT COUNT(*) as cnt FROM clients") as cur:
        stats["client_count"] = (await cur.fetchone())["cnt"]

    # Scanner count
    async with db.execute("SELECT COUNT(*) as cnt FROM scanner_configs WHERE is_active=1") as cur:
        stats["scanner_count"] = (await cur.fetchone())["cnt"]

    # Dark web alert count (unacknowledged)
    try:
        async with db.execute(
            "SELECT COUNT(*) as cnt FROM darkweb_alerts WHERE acknowledged=0"
        ) as cur:
            stats["darkweb_alert_count"] = (await cur.fetchone())["cnt"]
    except Exception:
        stats["darkweb_alert_count"] = 0

    # KSI pass rate (average across all latest results)
    try:
        async with db.execute(
            "SELECT AVG(score) as avg FROM ksi_results WHERE id IN ("
            "  SELECT MAX(id) FROM ksi_results GROUP BY client_id, ksi_id"
            ")"
        ) as cur:
            row = await cur.fetchone()
            stats["ksi_pass_rate"] = round(row["avg"], 3) if row["avg"] is not None else None
    except Exception:
        stats["ksi_pass_rate"] = None

    return stats


async def purge_old_items():
    """Remove items older than RETENTION_DAYS."""
    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(days=config.RETENTION_DAYS)).isoformat()
    cursor = await db.execute(
        "DELETE FROM threat_items WHERE published_at < ? AND is_new = 0", (cutoff,)
    )
    await db.commit()
    return cursor.rowcount


# ── Client CRUD ───────────────────────────────────────────────────────────────

async def create_client(name: str, contact_email: str = "", stack_profile: dict = None) -> dict:
    import uuid
    db = get_db()
    client_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO clients (id, name, contact_email, stack_profile, created_at) VALUES (?,?,?,?,?)",
        (client_id, name, contact_email, json.dumps(stack_profile or {}), now),
    )
    await db.commit()
    return {"id": client_id, "name": name, "contact_email": contact_email,
            "stack_profile": stack_profile or {}, "created_at": now}


async def get_clients() -> list[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM clients ORDER BY created_at DESC") as cur:
        rows = await cur.fetchall()
    return [_client_row(r) for r in rows]


async def get_client(client_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)) as cur:
        row = await cur.fetchone()
    return _client_row(row) if row else None


async def update_client(client_id: str, name: str = None, contact_email: str = None,
                        stack_profile: dict = None) -> Optional[dict]:
    db = get_db()
    sets, params = [], []
    if name is not None:
        sets.append("name = ?"); params.append(name)
    if contact_email is not None:
        sets.append("contact_email = ?"); params.append(contact_email)
    if stack_profile is not None:
        sets.append("stack_profile = ?"); params.append(json.dumps(stack_profile))
    if not sets:
        return await get_client(client_id)
    params.append(client_id)
    await db.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_client(client_id)


async def delete_client(client_id: str):
    db = get_db()
    # Delete dependents first (FK constraints)
    await db.execute("DELETE FROM asset_exposures WHERE client_id = ?", (client_id,))
    await db.execute("DELETE FROM client_assets WHERE client_id = ?", (client_id,))
    await db.execute("DELETE FROM remediation_items WHERE client_id = ?", (client_id,))
    await db.execute("DELETE FROM webhook_configs WHERE client_id = ?", (client_id,))
    await db.execute("DELETE FROM users WHERE client_id = ?", (client_id,))
    await db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    await db.commit()


def _client_row(row) -> dict:
    d = dict(row)
    if d.get("stack_profile"):
        try:
            d["stack_profile"] = json.loads(d["stack_profile"])
        except Exception:
            d["stack_profile"] = {}
    return d


# ── User CRUD ─────────────────────────────────────────────────────────────────

async def create_user(username: str, password_hash: str, role: str = "analyst",
                      client_id: str = None) -> dict:
    import uuid
    db = get_db()
    user_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO users (id, username, password_hash, role, client_id, created_at) VALUES (?,?,?,?,?,?)",
        (user_id, username, password_hash, role, client_id, now),
    )
    await db.commit()
    return {"id": user_id, "username": username, "role": role,
            "client_id": client_id, "created_at": now}


async def get_user_by_username(username: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


# ── Asset CRUD ────────────────────────────────────────────────────────────────

async def upsert_asset(client_id: str, software: str, version: str = "",
                       hostname: str = "", ip_address: str = "",
                       os: str = "", os_version: str = "",
                       cpe_string: str = "", asset_type: str = "workstation") -> str:
    import uuid
    db = get_db()
    asset_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO client_assets
           (id, client_id, hostname, ip_address, os, os_version, software, version, cpe_string, asset_type, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (asset_id, client_id, hostname, ip_address, os, os_version, software, version, cpe_string, asset_type, now, now),
    )
    await db.commit()
    return asset_id


async def get_assets(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM client_assets WHERE client_id = ? ORDER BY software", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_asset(asset_id: str):
    db = get_db()
    await db.execute("DELETE FROM client_assets WHERE id = ?", (asset_id,))
    await db.execute("DELETE FROM asset_exposures WHERE asset_id = ?", (asset_id,))
    await db.commit()


async def get_all_assets_for_matching() -> list[dict]:
    """Return all assets grouped by client for CPE matching."""
    db = get_db()
    async with db.execute("SELECT * FROM client_assets") as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def upsert_exposure(client_id: str, item_id: str, asset_id: str,
                           match_type: str, confidence: float) -> str:
    import uuid
    db = get_db()
    # deduplicate on (item_id, asset_id)
    async with db.execute(
        "SELECT id FROM asset_exposures WHERE item_id = ? AND asset_id = ?",
        (item_id, asset_id),
    ) as cur:
        existing = await cur.fetchone()
    if existing:
        return existing[0]
    exp_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO asset_exposures (id, client_id, item_id, asset_id, match_type, confidence, confirmed_at)
           VALUES (?,?,?,?,?,?,?)""",
        (exp_id, client_id, item_id, asset_id, match_type, confidence, now),
    )
    await db.commit()
    return exp_id


async def get_exposures_for_item(item_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        """SELECT ae.*, ca.hostname, ca.software, ca.version, ca.ip_address
           FROM asset_exposures ae
           JOIN client_assets ca ON ae.asset_id = ca.id
           WHERE ae.item_id = ?""",
        (item_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_exposed_item_ids(client_id: str) -> set[str]:
    db = get_db()
    async with db.execute(
        "SELECT DISTINCT item_id FROM asset_exposures WHERE client_id = ?", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return {r[0] for r in rows}


# ── Remediation CRUD ───────────────────────────────────────────────────────────

async def create_remediation(client_id: str, item_id: str, sla_days: int,
                              due_date: str, priority: int = 0) -> dict:
    import uuid
    db = get_db()
    # prevent duplicates
    async with db.execute(
        "SELECT id FROM remediation_items WHERE client_id = ? AND item_id = ?",
        (client_id, item_id),
    ) as cur:
        existing = await cur.fetchone()
    if existing:
        return {"id": existing[0], "exists": True}
    rem_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO remediation_items
           (id, client_id, item_id, status, priority, due_date, sla_days, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (rem_id, client_id, item_id, "open", priority, due_date, sla_days, now, now),
    )
    await db.commit()
    return {"id": rem_id, "exists": False, "due_date": due_date}


async def get_remediations(client_id: str, status: Optional[str] = None) -> list[dict]:
    db = get_db()
    if status:
        q = "SELECT * FROM remediation_items WHERE client_id = ? AND status = ? ORDER BY due_date"
        args = (client_id, status)
    else:
        q = "SELECT * FROM remediation_items WHERE client_id = ? ORDER BY due_date"
        args = (client_id,)
    async with db.execute(q, args) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def update_remediation(rem_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"status", "assigned_to", "notes", "patched_date", "priority", "is_overdue"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return None
    sets.append("updated_at = ?")
    params.append(datetime.utcnow().isoformat())
    params.append(rem_id)
    await db.execute(f"UPDATE remediation_items SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    async with db.execute("SELECT * FROM remediation_items WHERE id = ?", (rem_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_overdue_remediations() -> list[dict]:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    db = get_db()
    async with db.execute(
        "SELECT * FROM remediation_items WHERE status = 'open' AND due_date < ?", (today,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ── IOC Cache CRUD ────────────────────────────────────────────────────────────

async def get_ioc_cache(ioc_value: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM ioc_cache WHERE ioc_value = ?", (ioc_value,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    # Check expiry
    if d.get("expires_at") and d["expires_at"] < datetime.utcnow().isoformat():
        return None
    return d


async def upsert_ioc_cache(data: dict):
    db = get_db()
    await db.execute(
        """INSERT OR REPLACE INTO ioc_cache
           (ioc_value, ioc_type, abuseipdb_score, abuseipdb_country,
            vt_malicious, vt_total, vt_name,
            greynoise_classification, greynoise_name,
            enriched_at, expires_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data.get("ioc_value"), data.get("ioc_type"),
            data.get("abuseipdb_score"), data.get("abuseipdb_country"),
            data.get("vt_malicious"), data.get("vt_total"), data.get("vt_name"),
            data.get("greynoise_classification"), data.get("greynoise_name"),
            data.get("enriched_at"), data.get("expires_at"),
        ),
    )
    await db.commit()


async def list_ioc_cache(limit: int = 100) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM ioc_cache ORDER BY enriched_at DESC LIMIT ?", (limit,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ── Webhook CRUD ───────────────────────────────────────────────────────────────

async def create_webhook(client_id: str, webhook_type: str, url: str,
                          secret: str = "", min_severity: str = "HIGH",
                          categories: list = None) -> dict:
    import uuid
    db = get_db()
    wh_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO webhook_configs
           (id, client_id, webhook_type, url, secret, min_severity, categories, is_active, created_at)
           VALUES (?,?,?,?,?,?,?,1,?)""",
        (wh_id, client_id, webhook_type, url, secret, min_severity,
         json.dumps(categories or []), now),
    )
    await db.commit()
    return await get_webhook(wh_id)


async def get_webhooks(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM webhook_configs WHERE client_id = ? ORDER BY created_at", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [_wh_row(r) for r in rows]


async def get_webhook(wh_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM webhook_configs WHERE id = ?", (wh_id,)) as cur:
        row = await cur.fetchone()
    return _wh_row(row) if row else None


async def update_webhook(wh_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"webhook_type", "url", "secret", "min_severity", "categories", "is_active", "last_fired"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if k == "categories" else v)
    if not sets:
        return await get_webhook(wh_id)
    params.append(wh_id)
    await db.execute(f"UPDATE webhook_configs SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_webhook(wh_id)


async def delete_webhook(wh_id: str):
    db = get_db()
    await db.execute("DELETE FROM webhook_configs WHERE id = ?", (wh_id,))
    await db.commit()


async def get_active_webhooks_for_severity(severity: str, category: str) -> list[dict]:
    """Return all active webhooks that match this item's severity and category."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    item_sev = sev_order.get(severity, 4)
    db = get_db()
    async with db.execute("SELECT * FROM webhook_configs WHERE is_active = 1") as cur:
        rows = await cur.fetchall()
    result = []
    for row in rows:
        wh = _wh_row(row)
        min_sev = sev_order.get(wh.get("min_severity", "HIGH"), 1)
        if item_sev > min_sev:
            continue
        cats = wh.get("categories") or []
        if cats and category not in cats:
            continue
        result.append(wh)
    return result


def _wh_row(row) -> dict:
    d = dict(row)
    if d.get("categories"):
        try:
            d["categories"] = json.loads(d["categories"])
        except Exception:
            d["categories"] = []
    return d


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("tags", "cve_ids", "raw", "compliance_tags"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
        elif field == "compliance_tags":
            d[field] = []
    d["is_new"] = bool(d.get("is_new"))
    d["is_read"] = bool(d.get("is_read"))
    return d


# ── Dark Web Alerts CRUD ───────────────────────────────────────────────────────

async def create_darkweb_alert(client_id: str, alert_type: str, source: str,
                                matched_term: str = "", content_preview: str = "",
                                url: str = "") -> dict:
    db = get_db()
    alert_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO darkweb_alerts
           (id, client_id, alert_type, source, matched_term, content_preview, url, detected_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (alert_id, client_id, alert_type, source, matched_term, content_preview[:500], url, now),
    )
    await db.commit()
    return {"id": alert_id, "client_id": client_id, "alert_type": alert_type,
            "source": source, "matched_term": matched_term,
            "content_preview": content_preview[:500], "url": url,
            "detected_at": now, "is_acknowledged": 0}


async def get_darkweb_alerts(client_id: str, limit: int = 100,
                              unacknowledged_only: bool = False) -> list[dict]:
    db = get_db()
    if unacknowledged_only:
        q = "SELECT * FROM darkweb_alerts WHERE client_id = ? AND is_acknowledged = 0 ORDER BY detected_at DESC LIMIT ?"
    else:
        q = "SELECT * FROM darkweb_alerts WHERE client_id = ? ORDER BY detected_at DESC LIMIT ?"
    async with db.execute(q, (client_id, limit)) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def acknowledge_darkweb_alert(alert_id: str) -> bool:
    db = get_db()
    await db.execute("UPDATE darkweb_alerts SET is_acknowledged = 1 WHERE id = ?", (alert_id,))
    await db.commit()
    return True


async def count_unacknowledged_alerts(client_id: str) -> int:
    db = get_db()
    async with db.execute(
        "SELECT COUNT(*) FROM darkweb_alerts WHERE client_id = ? AND is_acknowledged = 0",
        (client_id,),
    ) as cur:
        row = await cur.fetchone()
    return row[0] if row else 0


async def is_darkweb_seen(source: str, item_id: str) -> bool:
    db = get_db()
    key = f"{source}:{item_id}"
    async with db.execute("SELECT id FROM darkweb_seen WHERE id = ?", (key,)) as cur:
        return bool(await cur.fetchone())


async def mark_darkweb_seen(source: str, item_id: str):
    db = get_db()
    key = f"{source}:{item_id}"
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO darkweb_seen (id, source, seen_at) VALUES (?,?,?)",
        (key, source, now),
    )
    await db.commit()


# ── Threat Actor CRUD ─────────────────────────────────────────────────────────

def _actor_row(row) -> dict:
    d = dict(row)
    for f in ("aliases", "target_industries", "ttps", "known_malware"):
        if d.get(f):
            try:
                d[f] = json.loads(d[f])
            except Exception:
                d[f] = []
        else:
            d[f] = []
    return d


async def upsert_threat_actor(actor: dict) -> bool:
    db = get_db()
    async with db.execute("SELECT id FROM threat_actors WHERE id = ?", (actor["id"],)) as cur:
        existing = await cur.fetchone()
    now = datetime.utcnow().isoformat()
    params = (
        actor["id"], actor.get("name", ""), json.dumps(actor.get("aliases", [])),
        actor.get("origin", ""), actor.get("sponsor", ""), actor.get("motivation", ""),
        actor.get("active_since", ""),
        json.dumps(actor.get("target_industries", [])),
        json.dumps(actor.get("ttps", [])),
        json.dumps(actor.get("known_malware", [])),
        actor.get("description", ""), actor.get("recent_activity", "Unknown"),
        now,
    )
    if existing:
        await db.execute(
            """UPDATE threat_actors SET name=?,aliases=?,origin=?,sponsor=?,motivation=?,
               active_since=?,target_industries=?,ttps=?,known_malware=?,description=?,
               recent_activity=?,last_seen=? WHERE id=?""",
            params[1:] + (actor["id"],),
        )
    else:
        await db.execute(
            """INSERT INTO threat_actors
               (id,name,aliases,origin,sponsor,motivation,active_since,
                target_industries,ttps,known_malware,description,recent_activity,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            params,
        )
    await db.commit()
    return not bool(existing)


async def get_threat_actors(origin: str = None, motivation: str = None,
                             active_only: bool = False) -> list[dict]:
    db = get_db()
    conditions, params = [], []
    if origin:
        conditions.append("origin = ?"); params.append(origin)
    if motivation:
        conditions.append("motivation = ?"); params.append(motivation)
    if active_only:
        conditions.append("recent_activity = 'Active'")
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with db.execute(
        f"SELECT * FROM threat_actors {where} ORDER BY name", params
    ) as cur:
        rows = await cur.fetchall()
    return [_actor_row(r) for r in rows]


async def get_threat_actor(actor_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM threat_actors WHERE id = ?", (actor_id,)) as cur:
        row = await cur.fetchone()
    return _actor_row(row) if row else None


async def link_actor_to_item(actor_id: str, item_id: str):
    db = get_db()
    link_id = hashlib.md5(f"{actor_id}:{item_id}".encode()).hexdigest()[:16]
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO actor_item_links (id, actor_id, item_id, linked_at) VALUES (?,?,?,?)",
        (link_id, actor_id, item_id, now),
    )
    await db.execute(
        "UPDATE threat_actors SET item_count = item_count + 1 WHERE id = ? AND NOT EXISTS "
        "(SELECT 1 FROM actor_item_links WHERE actor_id=? AND item_id=?)",
        (actor_id, actor_id, item_id),
    )
    await db.commit()


async def get_actor_items(actor_id: str, limit: int = 50) -> list[dict]:
    db = get_db()
    async with db.execute(
        """SELECT ti.* FROM threat_items ti
           JOIN actor_item_links al ON ti.id = al.item_id
           WHERE al.actor_id = ?
           ORDER BY al.linked_at DESC LIMIT ?""",
        (actor_id, limit),
    ) as cur:
        rows = await cur.fetchall()
    return [_row_to_dict(r) for r in rows]


# ── Client Vendor CRUD ────────────────────────────────────────────────────────

async def create_vendor(client_id: str, vendor_name: str, vendor_type: str = "",
                         criticality: str = "medium", data_types: list = None,
                         contact_email: str = "") -> dict:
    db = get_db()
    vid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO client_vendors
           (id, client_id, vendor_name, vendor_type, criticality, data_types, contact_email, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (vid, client_id, vendor_name, vendor_type, criticality,
         json.dumps(data_types or []), contact_email, now),
    )
    await db.commit()
    return {"id": vid, "client_id": client_id, "vendor_name": vendor_name,
            "vendor_type": vendor_type, "criticality": criticality,
            "data_types": data_types or [], "contact_email": contact_email, "created_at": now}


async def get_vendors(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM client_vendors WHERE client_id = ? ORDER BY vendor_name", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["data_types"] = json.loads(d.get("data_types") or "[]")
        except Exception:
            d["data_types"] = []
        try:
            d["products"] = json.loads(d.get("products") or "[]")
        except Exception:
            d["products"] = []
        try:
            d["risk_data"] = json.loads(d.get("risk_data") or "{}")
        except Exception:
            d["risk_data"] = {}
        result.append(d)
    return result


async def delete_vendor(vendor_id: str):
    db = get_db()
    await db.execute("DELETE FROM vendor_exposures WHERE vendor_id = ?", (vendor_id,))
    await db.execute("DELETE FROM client_vendors WHERE id = ?", (vendor_id,))
    await db.commit()


# Aliases used by supply_chain_monitor
async def get_client_vendors(client_id: str) -> list[dict]:
    return await get_vendors(client_id)


async def update_vendor_risk(client_id: str, vendor_id: str, threat_level: str, risk_data: dict):
    db = get_db()
    await db.execute(
        "UPDATE client_vendors SET threat_level = ?, risk_data = ? WHERE id = ? AND client_id = ?",
        (threat_level, json.dumps(risk_data), vendor_id, client_id),
    )
    await db.commit()


async def create_vendor_full(client_id: str, vendor_name: str, vendor_type: str = "",
                              criticality: str = "medium", products: list = None,
                              category: str = "", contact_email: str = "") -> dict:
    db = get_db()
    vid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO client_vendors
           (id, client_id, vendor_name, vendor_type, criticality, products, category,
            data_types, contact_email, threat_level, risk_data, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (vid, client_id, vendor_name, vendor_type, criticality,
         json.dumps(products or []), category, "[]", contact_email, "unknown", "{}", now),
    )
    await db.commit()
    return {"id": vid, "client_id": client_id, "vendor_name": vendor_name,
            "vendor_type": vendor_type, "criticality": criticality,
            "products": products or [], "category": category,
            "threat_level": "unknown", "created_at": now}


async def get_vendor_exposure_count(vendor_id: str) -> int:
    db = get_db()
    async with db.execute(
        "SELECT COUNT(*) FROM vendor_exposures WHERE vendor_id = ?", (vendor_id,)
    ) as cur:
        row = await cur.fetchone()
    return row[0] if row else 0


async def add_vendor_exposure(vendor_id: str, item_id: str):
    db = get_db()
    eid = hashlib.md5(f"{vendor_id}:{item_id}".encode()).hexdigest()[:16]
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT OR IGNORE INTO vendor_exposures (id, vendor_id, item_id, detected_at) VALUES (?,?,?,?)",
        (eid, vendor_id, item_id, now),
    )
    await db.commit()


# ── Posture Score CRUD ────────────────────────────────────────────────────────

async def save_posture_score(client_id: str, score: float, grade: str,
                              percentile: float = None, sla_component: float = 0,
                              mttr_component: float = 0, open_crit_component: float = 0,
                              velocity_component: float = 0) -> dict:
    db = get_db()
    sid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO posture_scores
           (id, client_id, score, grade, percentile, sla_component, mttr_component,
            open_crit_component, velocity_component, calculated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (sid, client_id, score, grade, percentile, sla_component,
         mttr_component, open_crit_component, velocity_component, now),
    )
    await db.commit()
    return {"id": sid, "client_id": client_id, "score": score, "grade": grade,
            "percentile": percentile, "calculated_at": now}


async def get_latest_posture_score(client_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM posture_scores WHERE client_id = ? ORDER BY calculated_at DESC LIMIT 1",
        (client_id,),
    ) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_posture_history(client_id: str, limit: int = 30) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM posture_scores WHERE client_id = ? ORDER BY calculated_at DESC LIMIT ?",
        (client_id, limit),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ── Tabletop Exercise CRUD ────────────────────────────────────────────────────

async def create_tabletop(client_id: str, title: str, scenario_type: str,
                           scenario_json: dict) -> dict:
    db = get_db()
    ex_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO tabletop_exercises
           (id, client_id, title, scenario_type, generated_at, scenario_json)
           VALUES (?,?,?,?,?,?)""",
        (ex_id, client_id, title, scenario_type, now, json.dumps(scenario_json)),
    )
    await db.commit()
    return {"id": ex_id, "client_id": client_id, "title": title,
            "scenario_type": scenario_type, "generated_at": now}


async def get_tabletops(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT id,client_id,title,scenario_type,generated_at,conducted_at,participants "
        "FROM tabletop_exercises WHERE client_id = ? ORDER BY generated_at DESC",
        (client_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_tabletop(ex_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM tabletop_exercises WHERE id = ?", (ex_id,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("scenario_json"):
        try:
            d["scenario_json"] = json.loads(d["scenario_json"])
        except Exception:
            pass
    return d


async def update_tabletop(ex_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"conducted_at", "participants", "debrief_notes"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?"); params.append(v)
    if not sets:
        return await get_tabletop(ex_id)
    params.append(ex_id)
    await db.execute(f"UPDATE tabletop_exercises SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_tabletop(ex_id)


# ── Update client with extended fields ───────────────────────────────────────

async def update_client_extended(client_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"name", "contact_email", "stack_profile", "industry",
               "logo_path", "brand_color", "cmmc_assessment_date"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if k == "stack_profile" else v)
    if not sets:
        return await get_client(client_id)
    params.append(client_id)
    await db.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_client(client_id)


# ── Notifications aggregator ──────────────────────────────────────────────────

async def get_notifications(client_id: str = None, limit: int = 10) -> list[dict]:
    """Aggregate recent alerts across dark web, SLA, and critical items."""
    db = get_db()
    notifications = []
    now = datetime.utcnow().isoformat()
    cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()

    # Dark web alerts (unacknowledged)
    if client_id:
        q = ("SELECT id, client_id, alert_type, source, matched_term, detected_at "
             "FROM darkweb_alerts WHERE client_id = ? AND is_acknowledged = 0 "
             "ORDER BY detected_at DESC LIMIT ?")
        args = (client_id, limit)
    else:
        q = ("SELECT id, client_id, alert_type, source, matched_term, detected_at "
             "FROM darkweb_alerts WHERE is_acknowledged = 0 "
             "ORDER BY detected_at DESC LIMIT ?")
        args = (limit,)
    async with db.execute(q, args) as cur:
        rows = await cur.fetchall()
    for r in rows:
        d = dict(r)
        notifications.append({
            "type": "darkweb",
            "severity": "HIGH",
            "title": f"Dark web alert: {d['alert_type']} on {d['source']}",
            "detail": d.get("matched_term", ""),
            "timestamp": d["detected_at"],
            "client_id": d["client_id"],
            "ref_id": d["id"],
        })

    # New CRITICAL items in last 24h
    crit_q = ("SELECT id, title, feed_label, fetched_at FROM threat_items "
              "WHERE severity = 'CRITICAL' AND fetched_at > ? ORDER BY fetched_at DESC LIMIT ?")
    async with db.execute(crit_q, (cutoff_24h, limit)) as cur:
        rows = await cur.fetchall()
    for r in rows:
        d = dict(r)
        notifications.append({
            "type": "critical_item",
            "severity": "CRITICAL",
            "title": f"New CRITICAL: {d['title'][:80]}",
            "detail": d["feed_label"],
            "timestamp": d["fetched_at"],
            "client_id": client_id,
            "ref_id": d["id"],
        })

    # SLA overdue count
    today = datetime.utcnow().strftime("%Y-%m-%d")
    overdue_q = "SELECT COUNT(*) FROM remediation_items WHERE status='open' AND due_date < ?"
    if client_id:
        overdue_q += " AND client_id = ?"
        async with db.execute(overdue_q, (today, client_id)) as cur:
            row = await cur.fetchone()
    else:
        async with db.execute(overdue_q, (today,)) as cur:
            row = await cur.fetchone()
    overdue_count = row[0] if row else 0
    if overdue_count > 0:
        notifications.append({
            "type": "sla_overdue",
            "severity": "HIGH",
            "title": f"{overdue_count} remediation items are past SLA",
            "detail": "Click to view remediation tracker",
            "timestamp": now,
            "client_id": client_id,
            "ref_id": None,
        })

    notifications.sort(key=lambda x: x["timestamp"], reverse=True)
    return notifications[:limit]


# ── CMMC Assessment CRUD ──────────────────────────────────────────────────────

async def get_cmmc_assessment(client_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM cmmc_assessments WHERE client_id = ? ORDER BY created_at DESC LIMIT 1",
        (client_id,),
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    import json as _json
    d["practices"] = _json.loads(d.get("practices_json") or "{}")
    return d


async def save_cmmc_assessment(client_id: str, practices: dict) -> dict:
    import json as _json
    db = get_db()
    now = datetime.utcnow().isoformat()
    # Check if row exists
    async with db.execute(
        "SELECT id FROM cmmc_assessments WHERE client_id = ?", (client_id,)
    ) as cur:
        existing = await cur.fetchone()
    practices_json = _json.dumps(practices)
    if existing:
        await db.execute(
            "UPDATE cmmc_assessments SET practices_json = ?, assessed_at = ? WHERE client_id = ?",
            (practices_json, now, client_id),
        )
    else:
        await db.execute(
            """INSERT INTO cmmc_assessments (id, client_id, practices_json, assessed_at)
               VALUES (?,?,?,?)""",
            (str(uuid.uuid4()), client_id, practices_json, now),
        )
    await db.commit()
    return {"client_id": client_id, "assessed_at": now}


# ── Scanner Config CRUD ───────────────────────────────────────────────────────

async def create_scanner_config(client_id: str, scanner_type: str, label: str,
                                 host_url: str = "", api_key_enc: str = "",
                                 secret_key_enc: str = "", username_enc: str = "",
                                 password_enc: str = "", extra_config: dict = None,
                                 poll_interval_hours: int = 6) -> dict:
    db = get_db()
    sid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO scanner_configs
           (id, client_id, scanner_type, label, host_url, api_key_enc, secret_key_enc,
            username_enc, password_enc, extra_config, poll_interval_hours, is_active,
            last_status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,1,'never',?)""",
        (sid, client_id, scanner_type, label, host_url, api_key_enc, secret_key_enc,
         username_enc, password_enc, json.dumps(extra_config or {}),
         poll_interval_hours, now),
    )
    await db.commit()
    return await get_scanner_config(sid)


async def get_scanner_config(scanner_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM scanner_configs WHERE id = ?", (scanner_id,)
    ) as cur:
        row = await cur.fetchone()
    return _scanner_row(row) if row else None


async def get_scanner_configs(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM scanner_configs WHERE client_id = ? ORDER BY created_at", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [_scanner_row(r) for r in rows]


async def get_all_active_scanner_configs() -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM scanner_configs WHERE is_active = 1"
    ) as cur:
        rows = await cur.fetchall()
    return [_scanner_row(r) for r in rows]


async def update_scanner_config(scanner_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"label", "host_url", "api_key_enc", "secret_key_enc", "username_enc",
               "password_enc", "extra_config", "poll_interval_hours", "is_active",
               "last_polled", "last_status"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if k == "extra_config" else v)
    if not sets:
        return await get_scanner_config(scanner_id)
    params.append(scanner_id)
    await db.execute(f"UPDATE scanner_configs SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_scanner_config(scanner_id)


async def delete_scanner_config(scanner_id: str):
    db = get_db()
    await db.execute("DELETE FROM scan_findings WHERE scanner_id = ?", (scanner_id,))
    await db.execute("DELETE FROM scanner_configs WHERE id = ?", (scanner_id,))
    await db.commit()


def _scanner_row(row) -> dict:
    d = dict(row)
    try:
        d["extra_config"] = json.loads(d.get("extra_config") or "{}")
    except Exception:
        d["extra_config"] = {}
    return d


# ── Scan Findings CRUD ────────────────────────────────────────────────────────

async def upsert_scan_finding(finding: dict) -> bool:
    """Upsert by (scanner_id, plugin_id, asset fingerprint). Returns True if new."""
    db = get_db()
    key = f"{finding['scanner_id']}:{finding.get('plugin_id','')}:{finding.get('hostname','')}{finding.get('ip_address','')}"
    fid = hashlib.md5(key.encode()).hexdigest()[:24]
    now = datetime.utcnow().isoformat()
    existing = None
    async with db.execute("SELECT id FROM scan_findings WHERE id = ?", (fid,)) as cur:
        existing = await cur.fetchone()
    if existing:
        await db.execute(
            "UPDATE scan_findings SET last_seen = ?, severity = ?, cvss = ?, raw = ? WHERE id = ?",
            (now, finding.get("severity", "INFO"), finding.get("cvss"),
             json.dumps(finding.get("raw")), fid),
        )
        await db.commit()
        return False
    await db.execute(
        """INSERT INTO scan_findings
           (id, client_id, scanner_id, scanner_type, asset_id, hostname, ip_address,
            cve_id, plugin_id, severity, cvss, title, description, solution,
            first_seen, last_seen, threat_item_id, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fid, finding["client_id"], finding["scanner_id"], finding.get("scanner_type", ""),
         finding.get("asset_id"), finding.get("hostname"), finding.get("ip_address"),
         finding.get("cve_id"), finding.get("plugin_id"),
         finding.get("severity", "INFO"), finding.get("cvss"),
         finding.get("title", ""), finding.get("description"), finding.get("solution"),
         now, now, finding.get("threat_item_id"), json.dumps(finding.get("raw"))),
    )
    await db.commit()
    return True


async def get_scan_findings(client_id: str, scanner_id: str = None,
                             severity: str = None, limit: int = 200) -> list[dict]:
    db = get_db()
    conditions = ["client_id = ?"]
    params: list = [client_id]
    if scanner_id:
        conditions.append("scanner_id = ?"); params.append(scanner_id)
    if severity:
        conditions.append("severity = ?"); params.append(severity)
    where = " AND ".join(conditions)
    async with db.execute(
        f"SELECT * FROM scan_findings WHERE {where} ORDER BY last_seen DESC LIMIT ?",
        params + [limit],
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["raw"] = json.loads(d.get("raw") or "null")
        except Exception:
            d["raw"] = None
        result.append(d)
    return result


async def count_scan_findings_by_severity(client_id: str) -> dict:
    db = get_db()
    async with db.execute(
        """SELECT severity, COUNT(*) as cnt FROM scan_findings
           WHERE client_id = ? GROUP BY severity""",
        (client_id,),
    ) as cur:
        rows = await cur.fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


# ── SIEM Config CRUD ──────────────────────────────────────────────────────────

async def create_siem_config(client_id: str, siem_type: str, label: str,
                              host_url: str = "", api_key_enc: str = "",
                              secret_key_enc: str = "", username_enc: str = "",
                              password_enc: str = "", extra_config: dict = None,
                              poll_interval_hours: int = 6) -> dict:
    db = get_db()
    sid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO siem_configs
           (id, client_id, siem_type, label, host_url, api_key_enc, secret_key_enc,
            username_enc, password_enc, extra_config, poll_interval_hours, is_active,
            last_status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,1,'never',?)""",
        (sid, client_id, siem_type, label, host_url, api_key_enc, secret_key_enc,
         username_enc, password_enc, json.dumps(extra_config or {}),
         poll_interval_hours, now),
    )
    await db.commit()
    return await get_siem_config(sid)


async def get_siem_config(siem_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM siem_configs WHERE id = ?", (siem_id,)) as cur:
        row = await cur.fetchone()
    return _siem_row(row) if row else None


async def get_siem_configs(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM siem_configs WHERE client_id = ? ORDER BY created_at", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [_siem_row(r) for r in rows]


async def get_all_active_siem_configs() -> list[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM siem_configs WHERE is_active = 1") as cur:
        rows = await cur.fetchall()
    return [_siem_row(r) for r in rows]


async def update_siem_config(siem_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"label", "host_url", "api_key_enc", "secret_key_enc", "username_enc",
               "password_enc", "extra_config", "poll_interval_hours", "is_active",
               "last_polled", "last_status"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if k == "extra_config" else v)
    if not sets:
        return await get_siem_config(siem_id)
    params.append(siem_id)
    await db.execute(f"UPDATE siem_configs SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_siem_config(siem_id)


async def delete_siem_config(siem_id: str):
    db = get_db()
    await db.execute("DELETE FROM siem_configs WHERE id = ?", (siem_id,))
    await db.commit()


def _siem_row(row) -> dict:
    d = dict(row)
    try:
        d["extra_config"] = json.loads(d.get("extra_config") or "{}")
    except Exception:
        d["extra_config"] = {}
    return d


# ── KSI Results CRUD ──────────────────────────────────────────────────────────

async def save_ksi_result(result: dict):
    db = get_db()
    await db.execute(
        """INSERT INTO ksi_results
           (id, client_id, ksi_id, ksi_name, status, score, details, validated_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (result["id"], result["client_id"], result["ksi_id"], result["ksi_name"],
         result["status"], result["score"], json.dumps(result.get("details", {})),
         result["validated_at"]),
    )
    await db.commit()


async def get_latest_ksi_results(client_id: str) -> list[dict]:
    """Return the most recent result for each KSI ID."""
    db = get_db()
    async with db.execute(
        """SELECT * FROM ksi_results WHERE client_id = ?
           AND validated_at = (
               SELECT MAX(r2.validated_at) FROM ksi_results r2
               WHERE r2.client_id = ksi_results.client_id
               AND r2.ksi_id = ksi_results.ksi_id
           )
           ORDER BY ksi_id""",
        (client_id,),
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d.get("details") or "{}")
        except Exception:
            d["details"] = {}
        result.append(d)
    return result


async def get_ksi_history(client_id: str, ksi_id: str, limit: int = 30) -> list[dict]:
    db = get_db()
    async with db.execute(
        """SELECT * FROM ksi_results WHERE client_id = ? AND ksi_id = ?
           ORDER BY validated_at DESC LIMIT ?""",
        (client_id, ksi_id, limit),
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d.get("details") or "{}")
        except Exception:
            d["details"] = {}
        result.append(d)
    return result


async def get_all_clients_ksi_summary() -> list[dict]:
    """Aggregate latest KSI pass/fail counts across all clients — for global dashboard."""
    db = get_db()
    async with db.execute("SELECT id, name FROM clients ORDER BY name") as cur:
        clients = await cur.fetchall()
    summaries = []
    for c in clients:
        cid = c["id"]
        results = await get_latest_ksi_results(cid)
        passing = sum(1 for r in results if r["status"] == "pass")
        conditional = sum(1 for r in results if r["status"] == "conditional")
        failing = sum(1 for r in results if r["status"] == "fail")
        avg_score = (sum(r["score"] for r in results) / len(results)) if results else None
        summaries.append({
            "client_id": cid,
            "client_name": c["name"],
            "total_ksis": len(results),
            "passing": passing,
            "conditional": conditional,
            "failing": failing,
            "avg_score": round(avg_score, 3) if avg_score is not None else None,
        })
    return summaries
