"""
FedRAMP 20x — Scanner configuration and findings API.
All credential values are Fernet-encrypted before storage.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

import db.database as db
from auth.auth import get_current_user
from security.encryption import encrypt

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["scanners"])

SUPPORTED_TYPES = {"tenable", "rapid7", "qualys", "crowdstrike",
                   "tenable_io", "tenable_sc", "nexpose"}

# Wizard sub-types mapped to DB canonical types
_TYPE_MAP = {"tenable_io": "tenable", "tenable_sc": "tenable", "nexpose": "rapid7"}


class ScannerCreate(BaseModel):
    scanner_type: str
    label: str
    host_url: Optional[str] = ""
    api_key: Optional[str] = ""
    secret_key: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    extra_config: Optional[dict] = {}
    poll_interval_hours: Optional[int] = 6
    pull_on_save: Optional[bool] = False


class ScannerUpdate(BaseModel):
    label: Optional[str] = None
    host_url: Optional[str] = None
    api_key: Optional[str] = None
    secret_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    extra_config: Optional[dict] = None
    poll_interval_hours: Optional[int] = None
    is_active: Optional[int] = None


def _mask(config: dict) -> dict:
    """Strip encrypted credential fields from API response."""
    masked = {k: v for k, v in config.items()
              if not k.endswith("_enc")}
    for field in ("api_key_enc", "secret_key_enc", "username_enc", "password_enc"):
        masked[field.replace("_enc", "_set")] = bool(config.get(field))
    return masked


@router.get("/clients/{client_id}/scanners")
async def list_scanners(client_id: str, user=Depends(get_current_user)):
    configs = await db.get_scanner_configs(client_id)
    return {"scanners": [_mask(c) for c in configs]}


@router.post("/clients/{client_id}/scanners", status_code=201)
async def create_scanner(client_id: str, body: ScannerCreate,
                          background_tasks: BackgroundTasks,
                          user=Depends(get_current_user)):
    if body.scanner_type not in SUPPORTED_TYPES:
        raise HTTPException(400, f"Unsupported scanner type. Must be one of: {SUPPORTED_TYPES}")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    # Map wizard sub-types to canonical DB type; preserve original in extra_config
    db_type = _TYPE_MAP.get(body.scanner_type, body.scanner_type)
    extra = dict(body.extra_config or {})
    if body.scanner_type != db_type:
        extra.setdefault("scanner_subtype", body.scanner_type)
    config = await db.create_scanner_config(
        client_id=client_id,
        scanner_type=db_type,
        label=body.label,
        host_url=body.host_url or "",
        api_key_enc=encrypt(body.api_key) if body.api_key else "",
        secret_key_enc=encrypt(body.secret_key) if body.secret_key else "",
        username_enc=encrypt(body.username) if body.username else "",
        password_enc=encrypt(body.password) if body.password else "",
        extra_config=extra,
        poll_interval_hours=body.poll_interval_hours,
    )
    if body.pull_on_save:
        background_tasks.add_task(_run_scanner, config)
    return _mask(config)


@router.get("/clients/{client_id}/scanners/{scanner_id}")
async def get_scanner(client_id: str, scanner_id: str, user=Depends(get_current_user)):
    config = await db.get_scanner_config(scanner_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "Scanner not found")
    return _mask(config)


@router.patch("/clients/{client_id}/scanners/{scanner_id}")
async def update_scanner(client_id: str, scanner_id: str, body: ScannerUpdate,
                          user=Depends(get_current_user)):
    config = await db.get_scanner_config(scanner_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "Scanner not found")
    updates = {}
    if body.label is not None:
        updates["label"] = body.label
    if body.host_url is not None:
        updates["host_url"] = body.host_url
    if body.api_key is not None:
        updates["api_key_enc"] = encrypt(body.api_key)
    if body.secret_key is not None:
        updates["secret_key_enc"] = encrypt(body.secret_key)
    if body.username is not None:
        updates["username_enc"] = encrypt(body.username)
    if body.password is not None:
        updates["password_enc"] = encrypt(body.password)
    if body.extra_config is not None:
        updates["extra_config"] = body.extra_config
    if body.poll_interval_hours is not None:
        updates["poll_interval_hours"] = body.poll_interval_hours
    if body.is_active is not None:
        updates["is_active"] = body.is_active
    updated = await db.update_scanner_config(scanner_id, **updates)
    return _mask(updated)


@router.delete("/clients/{client_id}/scanners/{scanner_id}", status_code=204)
async def delete_scanner(client_id: str, scanner_id: str, user=Depends(get_current_user)):
    config = await db.get_scanner_config(scanner_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "Scanner not found")
    await db.delete_scanner_config(scanner_id)


@router.post("/clients/{client_id}/scanners/{scanner_id}/poll")
async def trigger_poll(client_id: str, scanner_id: str,
                        background_tasks: BackgroundTasks,
                        user=Depends(get_current_user)):
    """Manually trigger a scanner poll in the background."""
    config = await db.get_scanner_config(scanner_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "Scanner not found")
    background_tasks.add_task(_run_scanner, config)
    return {"message": "Poll triggered", "scanner_id": scanner_id}


@router.get("/clients/{client_id}/scan-findings")
async def list_findings(client_id: str, scanner_id: Optional[str] = None,
                         severity: Optional[str] = None, limit: int = 200,
                         user=Depends(get_current_user)):
    findings = await db.get_scan_findings(client_id, scanner_id=scanner_id,
                                           severity=severity, limit=limit)
    counts = await db.count_scan_findings_by_severity(client_id)
    return {"findings": findings, "counts": counts, "total": len(findings)}


@router.get("/clients/{client_id}/scan-findings/summary")
async def findings_summary(client_id: str, user=Depends(get_current_user)):
    counts = await db.count_scan_findings_by_severity(client_id)
    scanners = await db.get_scanner_configs(client_id)
    return {
        "severity_counts": counts,
        "total": sum(counts.values()),
        "scanners": [_mask(s) for s in scanners],
    }


async def _run_scanner(config: dict):
    """Instantiate and run the correct fetcher class."""
    try:
        scanner_type = config["scanner_type"]
        if scanner_type == "tenable":
            from ingest.scanners.tenable import TenableFetcher
            fetcher = TenableFetcher(config)
        elif scanner_type == "rapid7":
            from ingest.scanners.rapid7 import Rapid7Fetcher
            fetcher = Rapid7Fetcher(config)
        elif scanner_type == "qualys":
            from ingest.scanners.qualys import QualysFetcher
            fetcher = QualysFetcher(config)
        elif scanner_type == "crowdstrike":
            from ingest.scanners.crowdstrike import CrowdStrikeFetcher
            fetcher = CrowdStrikeFetcher(config)
        else:
            logger.warning("Unknown scanner type: %s", scanner_type)
            return
        await fetcher.run()
    except Exception as exc:
        logger.error("Scanner poll error (%s): %s", config.get("id"), exc)
