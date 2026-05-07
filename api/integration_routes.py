"""
ThreatPulse — Integration management API.
Handles connection testing, pull history, all-integrations listing,
and background status computation.

Registered BEFORE scanner_routes / siem_routes so literal paths
(e.g. /scanners/test) take priority over /{scanner_id} parameters.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import db.database as db
from auth.auth import get_current_user
from security.encryption import encrypt

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Integrations"])


# ── Request models ─────────────────────────────────────────────────────────────

class ScannerTestRequest(BaseModel):
    scanner_type: str
    label: Optional[str] = ""
    host_url: Optional[str] = ""
    port: Optional[int] = None
    api_key: Optional[str] = ""
    secret_key: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    extra_config: Optional[dict] = {}


class SIEMTestRequest(BaseModel):
    siem_type: str
    label: Optional[str] = ""
    host_url: Optional[str] = ""
    port: Optional[int] = None
    api_key: Optional[str] = ""
    secret_key: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    query: Optional[str] = ""
    lookback_window: Optional[str] = "24h"
    max_results: Optional[int] = 100
    extra_config: Optional[dict] = {}


# ── Scanner test ───────────────────────────────────────────────────────────────

@router.post("/clients/{client_id}/scanners/test", summary="Test scanner credentials before saving")
async def test_scanner_connection(client_id: str, body: ScannerTestRequest,
                                   user=Depends(get_current_user)):
    """
    Attempt a live connection with provided credentials (not yet saved).
    Returns auth status, discovered counts, and sample field names.
    """
    host = body.host_url or ""
    if body.port and body.port not in (80, 443) and host and ":" not in host.split("/")[-1]:
        host = f"{host}:{body.port}"

    temp_config = {
        "id": "test",
        "client_id": client_id,
        "scanner_type": _canonical_scanner_type(body.scanner_type),
        "host_url": host,
        "api_key_enc":    encrypt(body.api_key)    if body.api_key    else "",
        "secret_key_enc": encrypt(body.secret_key) if body.secret_key else "",
        "username_enc":   encrypt(body.username)   if body.username   else "",
        "password_enc":   encrypt(body.password)   if body.password   else "",
        "extra_config": body.extra_config or {},
        "last_polled": None,
        "last_status": "never",
    }

    try:
        fetcher = _build_scanner_fetcher(body.scanner_type, temp_config)
        if fetcher is None:
            return {
                "success": False,
                "auth_status": "unsupported_type",
                "asset_count": 0,
                "vuln_count": 0,
                "rate_limit": None,
                "error_message": f"Unsupported scanner type: {body.scanner_type}",
                "sample_fields": [],
            }
        findings = await fetcher.fetch()
        asset_ids = {f.get("hostname") or f.get("ip_address") for f in findings if f.get("hostname") or f.get("ip_address")}
        sample_fields = list(findings[0].keys()) if findings else []
        return {
            "success": True,
            "auth_status": "authenticated",
            "asset_count": len(asset_ids),
            "vuln_count": len(findings),
            "rate_limit": None,
            "error_message": None,
            "sample_fields": sample_fields,
        }
    except Exception as exc:
        logger.warning("Scanner test failed (%s): %s", body.scanner_type, exc)
        return {
            "success": False,
            "auth_status": "failed",
            "asset_count": 0,
            "vuln_count": 0,
            "rate_limit": None,
            "error_message": str(exc),
            "sample_fields": [],
        }


# ── SIEM test ──────────────────────────────────────────────────────────────────

@router.post("/clients/{client_id}/siems/test", summary="Test SIEM credentials and run sample query")
async def test_siem_connection(client_id: str, body: SIEMTestRequest,
                                user=Depends(get_current_user)):
    host = body.host_url or ""
    if body.port and body.port not in (80, 443) and host and ":" not in host.split("/")[-1]:
        host = f"{host}:{body.port}"

    extra = dict(body.extra_config or {})
    if body.query:
        extra["query"] = body.query
    extra["lookback_window"] = body.lookback_window or "24h"
    extra["max_results"] = body.max_results or 100

    temp_config = {
        "id": "test",
        "client_id": client_id,
        "siem_type": body.siem_type,
        "host_url": host,
        "api_key_enc":    encrypt(body.api_key)    if body.api_key    else "",
        "secret_key_enc": encrypt(body.secret_key) if body.secret_key else "",
        "username_enc":   encrypt(body.username)   if body.username   else "",
        "password_enc":   encrypt(body.password)   if body.password   else "",
        "extra_config": extra,
        "last_polled": None,
        "last_status": "never",
    }

    try:
        fetcher = _build_siem_fetcher(body.siem_type, temp_config)
        if fetcher is None:
            return {
                "success": False,
                "auth_status": "unsupported_type",
                "results_count_24h": 0,
                "sample_events": [],
                "detected_fields": [],
                "error": f"Unsupported SIEM type: {body.siem_type}",
            }
        events = await fetcher.fetch()
        sample = events[:3]
        detected_fields = list(sample[0].keys()) if sample else []
        return {
            "success": True,
            "auth_status": "authenticated",
            "results_count_24h": len(events),
            "sample_events": sample,
            "detected_fields": detected_fields,
            "error": None,
        }
    except Exception as exc:
        logger.warning("SIEM test failed (%s): %s", body.siem_type, exc)
        return {
            "success": False,
            "auth_status": "failed",
            "results_count_24h": 0,
            "sample_events": [],
            "detected_fields": [],
            "error": str(exc),
        }


# ── Pull history ───────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/scanners/{scanner_id}/pull-history",
            summary="Last 10 pull records for a scanner")
async def scanner_pull_history(client_id: str, scanner_id: str,
                                user=Depends(get_current_user)):
    config = await db.get_scanner_config(scanner_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "Scanner not found")
    history = await db.get_pull_history(scanner_id)
    return {"scanner_id": scanner_id, "history": history}


@router.get("/clients/{client_id}/siems/{siem_id}/pull-history",
            summary="Last 10 pull records for a SIEM")
async def siem_pull_history(client_id: str, siem_id: str,
                             user=Depends(get_current_user)):
    config = await db.get_siem_config(siem_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "SIEM not found")
    history = await db.get_pull_history(siem_id)
    return {"siem_id": siem_id, "history": history}


# ── All integrations listing (sidebar) ────────────────────────────────────────

@router.get("/integrations/all", summary="All scanner and SIEM configs with client names")
async def all_integrations(user=Depends(get_current_user)):
    """Used by integrations.html sidebar — joins with clients for names."""
    conn = db.get_db()

    async with conn.execute("SELECT id, name FROM clients") as cur:
        client_rows = await cur.fetchall()
    client_names = {r["id"]: r["name"] for r in client_rows}

    scanners = await db.get_all_active_scanner_configs()
    siems    = await db.get_all_active_siem_configs()

    def _enrich_scanner(c: dict) -> dict:
        return {
            "id":               c["id"],
            "config_type":      "scanner",
            "type":             c["scanner_type"],
            "label":            c["label"],
            "client_id":        c["client_id"],
            "client_name":      client_names.get(c["client_id"], "Unknown"),
            "is_active":        bool(c.get("is_active")),
            "last_polled":      c.get("last_polled"),
            "last_status":      c.get("last_status", "never"),
            "connection_status": c.get("connection_status", "gray"),
            "poll_interval_hours": c.get("poll_interval_hours", 6),
        }

    def _enrich_siem(c: dict) -> dict:
        return {
            "id":               c["id"],
            "config_type":      "siem",
            "type":             c["siem_type"],
            "label":            c["label"],
            "client_id":        c["client_id"],
            "client_name":      client_names.get(c["client_id"], "Unknown"),
            "is_active":        bool(c.get("is_active")),
            "last_polled":      c.get("last_polled"),
            "last_status":      c.get("last_status", "never"),
            "connection_status": c.get("connection_status", "gray"),
            "poll_interval_hours": c.get("poll_interval_hours", 6),
        }

    return {
        "scanners": [_enrich_scanner(s) for s in scanners],
        "siems":    [_enrich_siem(s) for s in siems],
    }


# ── Status computation (called by scheduler every 5 min) ─────────────────────

async def update_all_integration_statuses():
    """
    Recompute connection_status for all active scanner and SIEM configs.
    green  = last pull within 2× interval, no errors
    amber  = last pull within 2-4× interval OR had partial errors
    red    = last pull failed OR no pull in 4× interval
    gray   = never pulled
    """
    now = datetime.utcnow()

    async def _compute(last_polled: Optional[str], last_status: Optional[str],
                       interval_h: int) -> str:
        if not last_polled or last_status == "never":
            return "gray"
        try:
            elapsed_h = (now - datetime.fromisoformat(last_polled)).total_seconds() / 3600
        except ValueError:
            return "gray"
        is_error = (last_status or "").startswith("error")
        if is_error and elapsed_h > interval_h * 4:
            return "red"
        if is_error:
            return "amber" if elapsed_h <= interval_h * 4 else "red"
        if elapsed_h <= interval_h * 2:
            return "green"
        if elapsed_h <= interval_h * 4:
            return "amber"
        return "red"

    try:
        for scanner in await db.get_all_active_scanner_configs():
            status = await _compute(
                scanner.get("last_polled"), scanner.get("last_status"),
                scanner.get("poll_interval_hours", 6)
            )
            if status != scanner.get("connection_status"):
                await db.update_scanner_config(scanner["id"], connection_status=status)
        for siem in await db.get_all_active_siem_configs():
            status = await _compute(
                siem.get("last_polled"), siem.get("last_status"),
                siem.get("poll_interval_hours", 6)
            )
            if status != siem.get("connection_status"):
                await db.update_siem_config(siem["id"], connection_status=status)
    except Exception as exc:
        logger.error("Status update error: %s", exc)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _canonical_scanner_type(scanner_type: str) -> str:
    """Map wizard sub-types to DB scanner_type values."""
    return {
        "tenable_io": "tenable",
        "tenable_sc": "tenable",
        "nexpose":    "rapid7",
    }.get(scanner_type, scanner_type)


def _build_scanner_fetcher(scanner_type: str, config: dict):
    db_type = _canonical_scanner_type(scanner_type)
    if db_type == "tenable":
        from ingest.scanners.tenable import TenableFetcher
        return TenableFetcher(config)
    if db_type == "qualys":
        from ingest.scanners.qualys import QualysFetcher
        return QualysFetcher(config)
    if db_type == "rapid7":
        from ingest.scanners.rapid7 import Rapid7Fetcher
        return Rapid7Fetcher(config)
    if db_type == "crowdstrike":
        from ingest.scanners.crowdstrike import CrowdStrikeFetcher
        return CrowdStrikeFetcher(config)
    return None


def _build_siem_fetcher(siem_type: str, config: dict):
    if siem_type == "splunk":
        from ingest.siems.splunk import SplunkFetcher
        return SplunkFetcher(config)
    if siem_type == "sentinel":
        from ingest.siems.sentinel import SentinelFetcher
        return SentinelFetcher(config)
    if siem_type == "qradar":
        from ingest.siems.qradar import QRadarFetcher
        return QRadarFetcher(config)
    if siem_type == "elastic":
        from ingest.siems.elastic import ElasticFetcher
        return ElasticFetcher(config)
    if siem_type == "chronicle":
        from ingest.siems.chronicle import ChronicleFetcher
        return ChronicleFetcher(config)
    return None
