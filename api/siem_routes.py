"""
FedRAMP 20x — SIEM configuration and alert ingestion API.
Supports Splunk, Microsoft Sentinel, IBM QRadar, and Elastic Security.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

import db.database as db
from auth.auth import get_current_user
from security.encryption import encrypt

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["siems"])

SUPPORTED_TYPES = {"splunk", "sentinel", "qradar", "elastic"}


class SIEMCreate(BaseModel):
    siem_type: str
    label: str
    host_url: Optional[str] = ""
    api_key: Optional[str] = ""
    secret_key: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    extra_config: Optional[dict] = {}
    poll_interval_hours: Optional[int] = 6


class SIEMUpdate(BaseModel):
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
    masked = {k: v for k, v in config.items() if not k.endswith("_enc")}
    for field in ("api_key_enc", "secret_key_enc", "username_enc", "password_enc"):
        masked[field.replace("_enc", "_set")] = bool(config.get(field))
    return masked


@router.get("/clients/{client_id}/siems")
async def list_siems(client_id: str, user=Depends(get_current_user)):
    configs = await db.get_siem_configs(client_id)
    return {"siems": [_mask(c) for c in configs]}


@router.post("/clients/{client_id}/siems", status_code=201)
async def create_siem(client_id: str, body: SIEMCreate, user=Depends(get_current_user)):
    if body.siem_type not in SUPPORTED_TYPES:
        raise HTTPException(400, f"Unsupported SIEM type. Must be one of: {SUPPORTED_TYPES}")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    config = await db.create_siem_config(
        client_id=client_id,
        siem_type=body.siem_type,
        label=body.label,
        host_url=body.host_url or "",
        api_key_enc=encrypt(body.api_key) if body.api_key else "",
        secret_key_enc=encrypt(body.secret_key) if body.secret_key else "",
        username_enc=encrypt(body.username) if body.username else "",
        password_enc=encrypt(body.password) if body.password else "",
        extra_config=body.extra_config or {},
        poll_interval_hours=body.poll_interval_hours,
    )
    return _mask(config)


@router.get("/clients/{client_id}/siems/{siem_id}")
async def get_siem(client_id: str, siem_id: str, user=Depends(get_current_user)):
    config = await db.get_siem_config(siem_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "SIEM not found")
    return _mask(config)


@router.patch("/clients/{client_id}/siems/{siem_id}")
async def update_siem(client_id: str, siem_id: str, body: SIEMUpdate,
                       user=Depends(get_current_user)):
    config = await db.get_siem_config(siem_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "SIEM not found")
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
    updated = await db.update_siem_config(siem_id, **updates)
    return _mask(updated)


@router.delete("/clients/{client_id}/siems/{siem_id}", status_code=204)
async def delete_siem(client_id: str, siem_id: str, user=Depends(get_current_user)):
    config = await db.get_siem_config(siem_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "SIEM not found")
    await db.delete_siem_config(siem_id)


@router.post("/clients/{client_id}/siems/{siem_id}/poll")
async def trigger_siem_poll(client_id: str, siem_id: str,
                             background_tasks: BackgroundTasks,
                             user=Depends(get_current_user)):
    config = await db.get_siem_config(siem_id)
    if not config or config["client_id"] != client_id:
        raise HTTPException(404, "SIEM not found")
    background_tasks.add_task(_run_siem, config)
    return {"message": "SIEM poll triggered", "siem_id": siem_id}


async def _run_siem(config: dict):
    try:
        siem_type = config["siem_type"]
        if siem_type == "splunk":
            from ingest.siems.splunk import SplunkFetcher
            fetcher = SplunkFetcher(config)
        elif siem_type == "sentinel":
            from ingest.siems.sentinel import SentinelFetcher
            fetcher = SentinelFetcher(config)
        elif siem_type == "qradar":
            from ingest.siems.qradar import QRadarFetcher
            fetcher = QRadarFetcher(config)
        elif siem_type == "elastic":
            from ingest.siems.elastic import ElasticFetcher
            fetcher = ElasticFetcher(config)
        else:
            logger.warning("Unknown SIEM type: %s", siem_type)
            return
        await fetcher.run()
    except Exception as exc:
        logger.error("SIEM poll error (%s): %s", config.get("id"), exc)
