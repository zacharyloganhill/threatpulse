"""PhantomFeed — Admin API Routes (client portal management)"""

import csv
import io
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel

from auth.auth import require_admin
from db import database as db

router = APIRouter()


class ClientCreate(BaseModel):
    name: str
    contact_email: str = ""
    stack_profile: dict = {}


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    stack_profile: Optional[dict] = None


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    client_id: Optional[str] = None


# ── Clients ───────────────────────────────────────────────────────────────────

@router.get("/clients", summary="List all clients")
async def list_clients(_: dict = Depends(require_admin)):
    return {"clients": await db.get_clients()}


@router.post("/clients", summary="Create a new client")
async def create_client(req: ClientCreate, _: dict = Depends(require_admin)):
    client = await db.create_client(
        name=req.name,
        contact_email=req.contact_email,
        stack_profile=req.stack_profile,
    )
    return client


@router.get("/clients/{client_id}", summary="Get a single client")
async def get_client(client_id: str, _: dict = Depends(require_admin)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.put("/clients/{client_id}", summary="Update a client")
async def update_client(client_id: str, req: ClientUpdate, _: dict = Depends(require_admin)):
    client = await db.update_client(
        client_id,
        name=req.name,
        contact_email=req.contact_email,
        stack_profile=req.stack_profile,
    )
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.delete("/clients/{client_id}", summary="Delete a client")
async def delete_client(client_id: str, _: dict = Depends(require_admin)):
    await db.delete_client(client_id)
    return {"status": "ok", "deleted": client_id}


@router.get("/clients/{client_id}/preview", summary="Preview filtered feed for a client")
async def preview_client_feed(client_id: str, limit: int = 50, _: dict = Depends(require_admin)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=limit, sort="risk")
    return {"client": client, "count": len(items), "items": items}


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/users", summary="List users for a client")
async def list_client_users(client_id: str, _: dict = Depends(require_admin)):
    conn = db.get_db()
    async with conn.execute(
        "SELECT id, username, role, client_id, created_at FROM users WHERE client_id = ? ORDER BY created_at",
        (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


@router.post("/users", summary="Create a new user")
async def create_user(req: UserCreate, _: dict = Depends(require_admin)):
    from auth.auth import hash_password
    existing = await db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    hashed = hash_password(req.password)
    user = await db.create_user(
        username=req.username,
        password_hash=hashed,
        role=req.role,
        client_id=req.client_id,
    )
    return {k: v for k, v in user.items() if k != "password_hash"}


# ── Reports ───────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/report.html", summary="Generate HTML report for a client")
async def client_report_html(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.pdf_generator import generate_client_report_html, _get_report_extras
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(client_id=client_id, limit=500, sort="risk")
    extras = await _get_report_extras(client_id, days)
    html = generate_client_report_html(client, items, days, extras=extras)
    # Add download PDF button at top
    btn = f'<div style="padding:12px;background:#1a1a2e;text-align:center"><a href="/api/v1/admin/clients/{client_id}/report.pdf?days={days}" style="color:#fff;background:#6b46c1;padding:8px 20px;text-decoration:none;font-family:sans-serif;font-size:13px">⬇ Download PDF</a></div>'
    html = html.replace("<body>", "<body>" + btn)
    return Response(content=html, media_type="text/html")


@router.get("/clients/{client_id}/report.pdf", summary="Generate PDF report for a client")
async def client_report_pdf(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.pdf_generator import generate_client_report, _get_report_extras
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(client_id=client_id, limit=500, sort="risk")
    extras = await _get_report_extras(client_id, days)
    content, media_type = generate_client_report(client, items, days, extras=extras)
    filename = f"phantomfeed-report-{client.get('name','client').replace(' ','-')}.pdf"
    headers = {}
    if media_type == "application/pdf":
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=content, media_type=media_type, headers=headers)


@router.post("/clients/{client_id}/send-digest", summary="Send email digest to client")
async def send_digest(
    client_id: str,
    days: int = Query(7, ge=1, le=365),
    _: dict = Depends(require_admin),
):
    from reports.email_digest import send_client_digest
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    items = await db.get_items(limit=500, sort="risk")
    result = await send_client_digest(client, items, days)
    return result


# ── Assets ────────────────────────────────────────────────────────────────────

@router.get("/clients/{client_id}/assets", summary="List client assets")
async def list_assets(client_id: str, _: dict = Depends(require_admin)):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    assets = await db.get_assets(client_id)
    return {"client_id": client_id, "count": len(assets), "assets": assets}


@router.post("/clients/{client_id}/assets/import", summary="Import assets from CSV")
async def import_assets(
    client_id: str,
    file: UploadFile = File(...),
    _: dict = Depends(require_admin),
):
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    imported = 0
    errors = []
    for i, row in enumerate(reader):
        software = (row.get("software") or "").strip()
        if not software:
            errors.append(f"Row {i+2}: missing 'software' column")
            continue
        try:
            await db.upsert_asset(
                client_id=client_id,
                software=software,
                version=(row.get("version") or "").strip(),
                hostname=(row.get("hostname") or "").strip(),
                ip_address=(row.get("ip_address") or "").strip(),
                os=(row.get("os") or "").strip(),
                os_version=(row.get("os_version") or "").strip(),
                cpe_string=(row.get("cpe_string") or "").strip(),
                asset_type=(row.get("asset_type") or "workstation").strip(),
            )
            imported += 1
        except Exception as exc:
            errors.append(f"Row {i+2}: {exc}")

    return {"imported": imported, "errors": errors[:20]}


@router.delete("/clients/{client_id}/assets/{asset_id}", summary="Delete an asset")
async def delete_asset(client_id: str, asset_id: str, _: dict = Depends(require_admin)):
    await db.delete_asset(asset_id)
    return {"status": "ok", "deleted": asset_id}


# ── Webhooks ──────────────────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    webhook_type: str  # generic, slack, splunk_hec, sentinel
    url: str
    secret: str = ""
    min_severity: str = "HIGH"
    categories: list = []


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    secret: Optional[str] = None
    min_severity: Optional[str] = None
    categories: Optional[list] = None
    is_active: Optional[int] = None


@router.get("/clients/{client_id}/webhooks", summary="List webhooks for a client")
async def list_webhooks(client_id: str, _: dict = Depends(require_admin)):
    return {"webhooks": await db.get_webhooks(client_id)}


@router.post("/clients/{client_id}/webhooks", summary="Create a webhook")
async def create_webhook(client_id: str, req: WebhookCreate, _: dict = Depends(require_admin)):
    wh = await db.create_webhook(
        client_id=client_id,
        webhook_type=req.webhook_type,
        url=req.url,
        secret=req.secret,
        min_severity=req.min_severity,
        categories=req.categories,
    )
    return wh


@router.put("/clients/{client_id}/webhooks/{wh_id}", summary="Update a webhook")
async def update_webhook(client_id: str, wh_id: str, req: WebhookUpdate, _: dict = Depends(require_admin)):
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    wh = await db.update_webhook(wh_id, **fields)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return wh


@router.delete("/clients/{client_id}/webhooks/{wh_id}", summary="Delete a webhook")
async def delete_webhook(client_id: str, wh_id: str, _: dict = Depends(require_admin)):
    await db.delete_webhook(wh_id)
    return {"status": "ok", "deleted": wh_id}


@router.post("/clients/{client_id}/webhooks/{wh_id}/test", summary="Send test payload to webhook")
async def test_webhook(client_id: str, wh_id: str, _: dict = Depends(require_admin)):
    from reports.webhook_dispatcher import WebhookDispatcher
    wh = await db.get_webhook(wh_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    test_item = {
        "id": "test-item-000",
        "title": "PhantomFeed Test Webhook",
        "severity": "HIGH",
        "cvss": 7.5,
        "risk_score": 6.0,
        "vendor": "PhantomFeed",
        "product": "Test",
        "published_at": "2025-01-01",
        "url": "https://github.com/zacharyloganhill/PhantomFeed",
        "cve_ids": ["CVE-2024-TEST"],
        "tags": ["Test", "Webhook"],
        "compliance_tags": ["CMMC-RA"],
        "category": "advisory",
    }
    dispatcher = WebhookDispatcher()
    result = await dispatcher.dispatch_to_webhook(wh, test_item)
    return {"status": result}
