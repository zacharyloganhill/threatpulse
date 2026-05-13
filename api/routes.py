"""
ThreatPulse — REST API Routes
Auto-docs available at http://localhost:8000/docs
"""

import json
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from typing import Optional
from api.rate_limit import check_rate_limit
from auth.auth import get_current_user, require_admin
from db import database as db
from ingest import scheduler
from ingest.risk_score import score_item

router = APIRouter()


@router.get("/items", summary="List threat items with filters")
async def list_items(
    severity: Optional[str] = Query(None, description="Comma-separated: CRITICAL,HIGH,MEDIUM,LOW,INFO"),
    category: Optional[str] = Query(None, description="cve, kev, advisory, vendor, ics, threat, malware, supply"),
    feed_id: Optional[str] = Query(None, description="Filter by specific feed ID"),
    is_new: Optional[bool] = Query(None, description="Filter to new/unseen items only"),
    search: Optional[str] = Query(None, max_length=200, description="Full-text search across title, desc, vendor, tags"),
    compliance: Optional[str] = Query(None, description="Filter by compliance tag: cmmc, nist, cis (partial match)"),
    sort: Optional[str] = Query(None, description="Sort order: 'risk' for risk score descending"),
    client_id: Optional[str] = Query(None, description="Filter to items exposed to this client's assets"),
    exposed_only: Optional[bool] = Query(None, description="When client_id set: show only items with confirmed exposures"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
):
    # Non-admin users may only filter by their own client
    if client_id and user.get("role") != "admin" and user.get("client_id") != client_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Resolve client stack profile into SQL-level filters
    stack_vendors = None
    stack_products = None
    if client_id and not exposed_only:
        client = await db.get_client(client_id)
        if client:
            sp = client.get("stack_profile") or {}
            if isinstance(sp, str):
                try: sp = json.loads(sp)
                except: sp = {}
            raw_vendors  = sp.get("vendors")  or []
            raw_products = sp.get("products") or []
            stack_vendors  = [v.lower() for v in raw_vendors]  if raw_vendors  else None
            stack_products = [p.lower() for p in raw_products] if raw_products else None
            # Apply min_severity from stack profile (if caller didn't specify severity)
            if not severity:
                min_sev = (sp.get("min_severity") or "").upper()
                if min_sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
                    idx = sev_order.index(min_sev)
                    severity = ",".join(sev_order[:idx+1])

    items = await db.get_items(
        severity=severity,
        category=category,
        feed_id=feed_id,
        is_new=is_new,
        search=search,
        compliance=compliance,
        sort=sort,
        limit=limit,
        offset=offset,
        stack_vendors=stack_vendors,
        stack_products=stack_products,
        user_id=user["id"],
    )
    # Exposure filter (post-query — needs asset match data)
    if client_id and exposed_only:
        exposed_ids = await db.get_exposed_item_ids(client_id)
        items = [i for i in items if i["id"] in exposed_ids]
    return {"count": len(items), "items": items}


@router.get("/items/{item_id}", summary="Get a single threat item by ID")
async def get_item(item_id: str, _: dict = Depends(get_current_user)):
    item = await db.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@router.post("/items/{item_id}/read", summary="Mark an item as read")
async def mark_read(item_id: str, user: dict = Depends(get_current_user)):
    await db.mark_read(item_id, user_id=user["id"])
    return {"status": "ok", "item_id": item_id}


@router.post("/items/read-all", summary="Mark all (or all in a feed) as read")
async def mark_all_read(feed_id: Optional[str] = Query(None), user: dict = Depends(get_current_user)):
    await db.mark_all_read(user_id=user["id"], feed_id=feed_id)
    return {"status": "ok"}


@router.get("/stats", summary="Counts, feed breakdown, and ingestion status")
async def stats(user: dict = Depends(get_current_user)):
    data = await db.get_stats()
    if user.get("role") != "admin":
        # Strip cross-client counts — not relevant to non-admin users
        data.pop("client_count", None)
        data.pop("scanner_count", None)
        data.pop("darkweb_alert_count", None)
    return data


@router.get("/feeds", summary="List all registered feed IDs")
async def list_feeds(_: dict = Depends(get_current_user)):
    feed_ids = scheduler.get_feed_ids()
    return {"feeds": feed_ids}


@router.get("/feeds/status", summary="Per-feed health: last run, last error, item count")
async def feed_status(_: dict = Depends(get_current_user)):
    """
    Returns in-memory health state for every registered feed.
    Status: 'ok' | 'error' | 'never'. Resets on server restart.
    """
    feeds = scheduler.get_feed_health()
    error_count = sum(1 for f in feeds if f["status"] == "error")
    never_count = sum(1 for f in feeds if f["status"] == "never")
    ok_count = sum(1 for f in feeds if f["status"] == "ok")
    return {
        "feeds": feeds,
        "summary": {"ok": ok_count, "error": error_count, "never": never_count, "total": len(feeds)},
    }


@router.post("/refresh", summary="Trigger an immediate poll of all feeds")
async def refresh_all(background_tasks: BackgroundTasks, admin: dict = Depends(require_admin)):
    """Fires all fetchers in the background. Returns immediately."""
    # 3 per 5 min — heavy background work; prevent accidental storm
    check_rate_limit(f"refresh:{admin.get('sub', 'anon')}", 3, 300)
    background_tasks.add_task(scheduler.run_all)
    return {"status": "refresh_started", "message": "All feeds are being polled in the background."}


@router.post("/refresh/{feed_id}", summary="Trigger an immediate poll of one feed")
async def refresh_feed(feed_id: str, background_tasks: BackgroundTasks, admin: dict = Depends(require_admin)):
    # 10 per 5 min per user — per-feed polls are lighter but still throttled
    check_rate_limit(f"refresh_feed:{admin.get('sub', 'anon')}", 10, 300)
    feed_ids = scheduler.get_feed_ids()
    if feed_id not in feed_ids:
        raise HTTPException(status_code=404, detail=f"Unknown feed: {feed_id}. Known feeds: {feed_ids}")
    background_tasks.add_task(scheduler.run_feed, feed_id)
    return {"status": "refresh_started", "feed_id": feed_id}


@router.delete("/items/purge", summary="Manually purge items older than retention period")
async def purge(admin: dict = Depends(require_admin)):
    # 2 per hour — purge is a heavy write; severe rate limit
    check_rate_limit(f"purge:{admin.get('sub', 'anon')}", 2, 3600)
    deleted = await db.purge_old_items()
    return {"status": "ok", "deleted": deleted}


@router.post("/items/{item_id}/rescore", summary="Recompute risk score for a single item")
async def rescore_item(item_id: str, _: dict = Depends(require_admin)):
    item = await db.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    rs = await score_item(item)
    await db.update_risk_score(item_id, rs)
    return {"item_id": item_id, "risk_score": rs}


async def _rescore_all_task():
    items = await db.get_items(limit=2000)
    for item in items:
        try:
            rs = await score_item(item)
            if rs > 0:
                await db.update_risk_score(item["id"], rs)
        except Exception:
            pass


@router.post("/rescore-all", summary="Recompute risk scores for all items in the background")
async def rescore_all(background_tasks: BackgroundTasks, admin: dict = Depends(require_admin)):
    # 2 per hour — iterates up to 2000 items; prevent queueing multiple runs
    check_rate_limit(f"rescore_all:{admin.get('sub', 'anon')}", 2, 3600)
    background_tasks.add_task(_rescore_all_task)
    return {"status": "rescore_started"}
