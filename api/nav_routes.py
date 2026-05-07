"""
ThreatPulse — Navigation / Dashboard API endpoints.
Powers the index.html mission control page.
"""

import logging
from fastapi import APIRouter, Depends
import db.database as db
from auth.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Navigation"])


@router.get("/scanners/status", summary="Active scanner configs and poll status")
async def scanners_status(user=Depends(get_current_user)):
    configs = await db.get_all_active_scanner_configs()
    masked = []
    for c in configs:
        masked.append({
            "id": c["id"],
            "client_id": c["client_id"],
            "scanner_type": c["scanner_type"],
            "label": c["label"],
            "is_active": bool(c["is_active"]),
            "last_status": c.get("last_status"),
            "last_polled": c.get("last_polled"),
        })
    active = sum(1 for s in masked if s["is_active"])
    return {"scanners": masked, "total": len(masked), "active": active}


@router.get("/siems/status", summary="Active SIEM configs and poll status")
async def siems_status(user=Depends(get_current_user)):
    configs = await db.get_all_active_siem_configs()
    masked = []
    for c in configs:
        masked.append({
            "id": c["id"],
            "client_id": c["client_id"],
            "siem_type": c["siem_type"],
            "label": c["label"],
            "is_active": bool(c["is_active"]),
            "last_status": c.get("last_status"),
            "last_polled": c.get("last_polled"),
        })
    active = sum(1 for s in masked if s["is_active"])
    return {"siems": masked, "total": len(masked), "active": active}


@router.get("/ksi/summary", summary="Cross-client KSI pass rate summary")
async def ksi_summary(user=Depends(get_current_user)):
    clients_data = await db.get_all_clients_ksi_summary()
    total_pass = sum(c.get("passing",    0) for c in clients_data)
    total_ksi  = sum(c.get("total_ksis", 0) for c in clients_data)
    pass_rate  = round(total_pass / total_ksi, 3) if total_ksi else None
    return {
        "clients": clients_data,
        "aggregate": {
            "pass_rate": pass_rate,
            "total_passing": total_pass,
            "total_ksi": total_ksi,
        },
    }


@router.get("/notifications", summary="Recent platform notifications and alerts")
async def notifications(limit: int = 20, user=Depends(get_current_user)):
    conn = db.get_db()
    items = []

    # Recent CRITICAL/HIGH threat items
    async with conn.execute(
        "SELECT title, severity, feed_label, fetched_at FROM threat_items "
        "WHERE severity IN ('CRITICAL','HIGH') AND is_new = 1 "
        "ORDER BY fetched_at DESC LIMIT ?", (limit // 2,)
    ) as cur:
        for row in await cur.fetchall():
            items.append({
                "title": row["title"],
                "severity": row["severity"],
                "source": row["feed_label"],
                "ts": (row["fetched_at"] or "")[:16],
                "type": "threat",
            })

    # Recent scan findings (CRITICAL/HIGH)
    async with conn.execute(
        "SELECT title, severity, scanner_type, first_seen FROM scan_findings "
        "WHERE severity IN ('CRITICAL','HIGH') "
        "ORDER BY first_seen DESC LIMIT ?", (limit // 2,)
    ) as cur:
        for row in await cur.fetchall():
            items.append({
                "title": row["title"],
                "severity": row["severity"],
                "source": f"Scanner: {row['scanner_type']}",
                "ts": (row["first_seen"] or "")[:16],
                "type": "scan_finding",
            })

    # Sort by timestamp descending and trim
    items.sort(key=lambda x: x["ts"], reverse=True)
    return {"notifications": items[:limit], "total": len(items)}


@router.get("/clients/{client_id}/metrics", summary="Per-client security metrics")
async def client_metrics(client_id: str, user=Depends(get_current_user)):
    client = await db.get_client(client_id)
    if not client:
        from fastapi import HTTPException
        raise HTTPException(404, "Client not found")

    conn = db.get_db()

    # Scan findings breakdown
    findings = await db.count_scan_findings_by_severity(client_id)

    # KSI latest
    ksi_results = await db.get_latest_ksi_results(client_id)
    passing     = sum(1 for r in ksi_results if r["status"] == "pass")
    failing     = sum(1 for r in ksi_results if r["status"] == "fail")

    # Scanner count
    scanners = await db.get_scanner_configs(client_id)
    siems    = await db.get_siem_configs(client_id)

    # Remediation open items
    async with conn.execute(
        "SELECT COUNT(*) as cnt FROM remediation_items WHERE client_id=? AND status='open'",
        (client_id,)
    ) as cur:
        open_remediations = (await cur.fetchone() or {"cnt": 0})["cnt"]

    return {
        "client_id": client_id,
        "client_name": client.get("name"),
        "scan_findings": findings,
        "ksi": {
            "passing": passing,
            "failing": failing,
            "total": len(ksi_results),
        },
        "scanners": len(scanners),
        "siems": len(siems),
        "open_remediations": open_remediations,
    }
