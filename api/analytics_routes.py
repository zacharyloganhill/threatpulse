"""PhantomFeed — Analytics API Routes"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Query
from db import database as db

router = APIRouter()


def _cutoff(days: int) -> str:
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")


@router.get("/analytics/trend", summary="Daily item counts by severity for trend chart")
async def trend(
    client_id: Optional[str] = Query(None),
    days: int = Query(90, ge=7, le=365),
):
    database = db.get_db()
    cut = _cutoff(days)
    async with database.execute(
        """SELECT date(published_at) as day, severity, COUNT(*) as cnt
           FROM threat_items
           WHERE published_at >= ?
           GROUP BY day, severity
           ORDER BY day""",
        (cut,),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    # If client_id given, filter to exposed items
    if client_id:
        exposed = await db.get_exposed_item_ids(client_id)
        if exposed:
            async with database.execute(
                f"""SELECT date(published_at) as day, severity, COUNT(*) as cnt
                    FROM threat_items
                    WHERE published_at >= ? AND id IN ({','.join('?'*len(exposed))})
                    GROUP BY day, severity ORDER BY day""",
                [cut] + list(exposed),
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]

    return {"days": days, "data": rows}


@router.get("/analytics/by-vendor", summary="Top 10 vendors by item count")
async def by_vendor(
    client_id: Optional[str] = Query(None),
    days: int = Query(30, ge=7, le=365),
):
    database = db.get_db()
    cut = _cutoff(days)
    async with database.execute(
        """SELECT vendor, severity, COUNT(*) as cnt
           FROM threat_items
           WHERE published_at >= ? AND vendor != '' AND vendor IS NOT NULL
           GROUP BY vendor, severity
           ORDER BY cnt DESC""",
        (cut,),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    # Aggregate by vendor
    vendors: dict = {}
    for r in rows:
        v = r["vendor"]
        vendors.setdefault(v, {"vendor": v, "total": 0, "by_severity": {}})
        vendors[v]["total"] += r["cnt"]
        vendors[v]["by_severity"][r["severity"]] = r["cnt"]

    top = sorted(vendors.values(), key=lambda x: x["total"], reverse=True)[:10]
    return {"days": days, "vendors": top}


@router.get("/analytics/by-category", summary="Item counts per category")
async def by_category(
    client_id: Optional[str] = Query(None),
    days: int = Query(30, ge=7, le=365),
):
    database = db.get_db()
    cut = _cutoff(days)
    async with database.execute(
        """SELECT category, severity, COUNT(*) as cnt
           FROM threat_items
           WHERE published_at >= ?
           GROUP BY category, severity""",
        (cut,),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]
    return {"days": days, "data": rows}


@router.get("/analytics/heatmap", summary="Vendor vs severity heatmap matrix")
async def heatmap(
    client_id: Optional[str] = Query(None),
    days: int = Query(30, ge=7, le=365),
):
    database = db.get_db()
    cut = _cutoff(days)
    async with database.execute(
        """SELECT vendor, severity, COUNT(*) as cnt
           FROM threat_items
           WHERE published_at >= ? AND vendor != '' AND vendor IS NOT NULL
           GROUP BY vendor, severity
           ORDER BY cnt DESC
           LIMIT 200""",
        (cut,),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    # Get top 10 vendors
    vendor_totals: dict = {}
    for r in rows:
        vendor_totals[r["vendor"]] = vendor_totals.get(r["vendor"], 0) + r["cnt"]
    top_vendors = [v for v, _ in sorted(vendor_totals.items(), key=lambda x: x[1], reverse=True)[:10]]

    matrix = {v: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0} for v in top_vendors}
    for r in rows:
        if r["vendor"] in matrix:
            matrix[r["vendor"]][r["severity"]] = r["cnt"]

    return {"days": days, "vendors": top_vendors, "matrix": matrix}


@router.get("/analytics/remediation-trend", summary="MTTR trend over time")
async def remediation_trend(
    client_id: Optional[str] = Query(None),
    days: int = Query(90, ge=30, le=365),
):
    if not client_id:
        return {"days": days, "data": []}
    database = db.get_db()
    cut = _cutoff(days)
    async with database.execute(
        """SELECT ri.patched_date, ti.severity,
                  julianday(ri.patched_date) - julianday(ri.created_at) as ttd
           FROM remediation_items ri
           JOIN threat_items ti ON ri.item_id = ti.id
           WHERE ri.client_id = ? AND ri.status = 'patched' AND ri.patched_date >= ?
           ORDER BY ri.patched_date""",
        (client_id, cut),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]
    return {"days": days, "client_id": client_id, "data": rows}


@router.get("/analytics/top-risks", summary="Top items by risk score")
async def top_risks(
    client_id: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=50),
):
    items = await db.get_items(limit=limit, sort="risk")
    if client_id:
        exposed = await db.get_exposed_item_ids(client_id)
        items = [i for i in items if i["id"] in exposed] if exposed else items
    return {"count": len(items), "items": items}


@router.get("/analytics/summary", summary="Overall stat card data")
async def summary(
    client_id: Optional[str] = Query(None),
    days: int = Query(30, ge=7, le=365),
):
    database = db.get_db()
    cut = _cutoff(days)
    cut_prev = _cutoff(days * 2)

    async with database.execute(
        "SELECT COUNT(*) as cnt FROM threat_items WHERE published_at >= ?", (cut,)
    ) as cur:
        total = (await cur.fetchone())["cnt"]

    async with database.execute(
        "SELECT COUNT(*) as cnt FROM threat_items WHERE published_at >= ? AND severity = 'CRITICAL'", (cut,)
    ) as cur:
        critical = (await cur.fetchone())["cnt"]

    overdue_count = 0
    mttr_avg = None
    if client_id:
        from db import database as db_mod
        async with database.execute(
            "SELECT COUNT(*) as cnt FROM remediation_items WHERE client_id = ? AND is_overdue = 1",
            (client_id,),
        ) as cur:
            overdue_count = (await cur.fetchone())["cnt"]
        from reports.sla_engine import calculate_mttr
        mttr = await calculate_mttr(client_id, days=days)
        if mttr:
            mttr_avg = round(sum(mttr.values()) / len(mttr), 1)

    return {
        "period_days": days,
        "total_items": total,
        "critical_items": critical,
        "overdue_remediations": overdue_count,
        "mttr_avg_days": mttr_avg,
    }


# ── Posture & Benchmarking ──────────────────────────────────────────────────

@router.get("/clients/{client_id}/posture", summary="Calculate posture score for a client")
async def client_posture(client_id: str):
    from analytics.benchmarking import BenchmarkingEngine
    engine = BenchmarkingEngine()
    return await engine.calculate_posture(client_id)


@router.get("/clients/{client_id}/posture/history", summary="Posture score history")
async def posture_history(client_id: str, limit: int = Query(30, ge=1, le=90)):
    from analytics.benchmarking import BenchmarkingEngine
    engine = BenchmarkingEngine()
    return await engine.get_posture_history(client_id, limit=limit)


@router.get("/benchmarks/{industry}", summary="Industry benchmark statistics")
async def industry_benchmark(industry: str):
    from analytics.benchmarking import BenchmarkingEngine
    engine = BenchmarkingEngine()
    return await engine.get_industry_benchmark(industry)


@router.get("/benchmarks", summary="All clients ranked by posture score")
async def all_clients_ranking():
    from analytics.benchmarking import BenchmarkingEngine
    engine = BenchmarkingEngine()
    return await engine.get_all_clients_ranking()


# ── Breach Cost & ROI ──────────────────────────────────────────────────────

@router.get("/clients/{client_id}/risk-portfolio", summary="Full breach cost and ROI analysis")
async def risk_portfolio(client_id: str):
    from analytics.breach_cost import get_client_risk_portfolio
    return await get_client_risk_portfolio(client_id)


@router.get("/breach-cost/industries", summary="IBM 2024 breach cost by industry")
async def breach_cost_industries():
    from analytics.breach_cost import INDUSTRY_BREACH_COSTS
    return {"source": "IBM Cost of a Data Breach Report 2024", "costs": INDUSTRY_BREACH_COSTS}
