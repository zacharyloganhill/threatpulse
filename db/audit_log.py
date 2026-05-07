"""
FedRAMP 20x — Comprehensive audit log.
Stores every API call + explicit security events in a dedicated table.
"""

import json
import uuid
from datetime import datetime
from typing import Optional

import aiosqlite

import config

CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    id           TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    user_id      TEXT,
    username     TEXT,
    client_id    TEXT,
    method       TEXT,
    path         TEXT,
    status_code  INTEGER,
    ip_address   TEXT,
    user_agent   TEXT,
    request_body TEXT,
    details      TEXT DEFAULT '{}',
    duration_ms  REAL
);
"""

CREATE_AUDIT_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_client ON audit_log(client_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username);",
    "CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type);",
]

_db: Optional[aiosqlite.Connection] = None


async def init_audit_db():
    global _db
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute(CREATE_AUDIT_LOG)
    for idx in CREATE_AUDIT_INDEXES:
        await _db.execute(idx)
    await _db.commit()
    return _db


def get_audit_db() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Audit DB not initialized")
    return _db


async def log_event(
    event_type: str,
    user_id: str = None,
    username: str = None,
    client_id: str = None,
    method: str = None,
    path: str = None,
    status_code: int = None,
    ip_address: str = None,
    user_agent: str = None,
    request_body: str = None,
    details: dict = None,
    duration_ms: float = None,
):
    db = get_audit_db()
    event_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO audit_log
           (id, timestamp, event_type, user_id, username, client_id,
            method, path, status_code, ip_address, user_agent,
            request_body, details, duration_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (event_id, now, event_type, user_id, username, client_id,
         method, path, status_code, ip_address, user_agent,
         (request_body or "")[:2000],
         json.dumps(details or {}), duration_ms),
    )
    await db.commit()
    return event_id


async def get_audit_events(
    client_id: str = None,
    event_type: str = None,
    username: str = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    db = get_audit_db()
    conditions, params = [], []
    if client_id:
        conditions.append("client_id = ?"); params.append(client_id)
    if event_type:
        conditions.append("event_type = ?"); params.append(event_type)
    if username:
        conditions.append("username = ?"); params.append(username)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with db.execute(
        f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
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


async def count_audit_events(client_id: str = None, event_type: str = None) -> int:
    db = get_audit_db()
    conditions, params = [], []
    if client_id:
        conditions.append("client_id = ?"); params.append(client_id)
    if event_type:
        conditions.append("event_type = ?"); params.append(event_type)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with db.execute(f"SELECT COUNT(*) FROM audit_log {where}", params) as cur:
        row = await cur.fetchone()
    return row[0] if row else 0


def events_to_csv(events: list[dict]) -> str:
    import io, csv
    buf = io.StringIO()
    fieldnames = ["timestamp", "event_type", "username", "client_id",
                  "method", "path", "status_code", "ip_address",
                  "user_agent", "duration_ms"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(events)
    return buf.getvalue()
