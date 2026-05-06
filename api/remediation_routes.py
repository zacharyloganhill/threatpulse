"""PhantomFeed — Remediation SLA API Routes"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from auth.auth import get_current_user
from db import database as db
from reports.sla_engine import SLAEngine, calculate_mttr, get_sla_compliance_rate

router = APIRouter()


class RemediationCreate(BaseModel):
    item_id: str
    priority: int = 0


class RemediationUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    patched_date: Optional[str] = None
    priority: Optional[int] = None


VALID_STATUSES = {"open", "in_progress", "patched", "accepted_risk", "false_positive", "wont_fix"}


@router.get("/clients/{client_id}/remediation", summary="List remediation items")
async def list_remediations(
    client_id: str,
    status: Optional[str] = Query(None),
    user: dict = Depends(get_current_user),
):
    rems = await db.get_remediations(client_id, status=status)
    today = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d")
    for r in rems:
        due = r.get("due_date") or ""
        r["days_remaining"] = (
            (__import__("datetime").datetime.strptime(due, "%Y-%m-%d")
             - __import__("datetime").datetime.utcnow()).days
            if due else None
        )
        r["is_overdue"] = bool(due and due < today and r.get("status") == "open")
    return {"client_id": client_id, "count": len(rems), "items": rems}


@router.post("/clients/{client_id}/remediation", summary="Create a remediation item")
async def create_remediation(
    client_id: str,
    req: RemediationCreate,
    user: dict = Depends(get_current_user),
):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    item = await db.get_item(req.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Threat item not found")

    sla_override = (client.get("stack_profile") or {}).get("sla")
    engine = SLAEngine(sla_override)
    due_date, sla_days = engine.assign_sla(item, client_id)

    result = await db.create_remediation(
        client_id=client_id,
        item_id=req.item_id,
        sla_days=sla_days,
        due_date=due_date,
        priority=req.priority,
    )
    return result


@router.patch("/clients/{client_id}/remediation/{rem_id}", summary="Update remediation status")
async def update_remediation(
    client_id: str,
    rem_id: str,
    req: RemediationUpdate,
    user: dict = Depends(get_current_user),
):
    if req.status and req.status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")

    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    result = await db.update_remediation(rem_id, **fields)
    if not result:
        raise HTTPException(status_code=404, detail="Remediation item not found")
    return result


@router.get("/clients/{client_id}/metrics", summary="Client remediation metrics")
async def client_metrics(
    client_id: str,
    days: int = Query(90, ge=7, le=365),
    user: dict = Depends(get_current_user),
):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    rems = await db.get_remediations(client_id)
    today = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d")

    open_items    = [r for r in rems if r.get("status") == "open"]
    overdue_items = [r for r in open_items if (r.get("due_date") or "") < today]

    # Counts by severity — join with threat_items inline
    sev_counts: dict = {}
    for r in open_items:
        item = await db.get_item(r["item_id"])
        if item:
            sev = item.get("severity", "MEDIUM")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    mttr = await calculate_mttr(client_id, days=days)
    compliance_rate = await get_sla_compliance_rate(client_id)

    return {
        "client_id": client_id,
        "period_days": days,
        "open_count": len(open_items),
        "overdue_count": len(overdue_items),
        "open_by_severity": sev_counts,
        "mttr_days": mttr,
        "sla_compliance_rate": compliance_rate,
    }
