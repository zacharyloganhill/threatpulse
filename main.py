"""
ThreatPulse — Main Application Entry Point

Run with:
    python main.py
    
Or directly:
    uvicorn main:app --reload --host 127.0.0.1 --port 8000

API docs: http://localhost:8000/docs
"""

import asyncio
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from db import database as db
from ingest import scheduler
from api.routes import router
from api.auth_routes import router as auth_router
from api.admin_routes import router as admin_router
from api.taxii_routes import router as taxii_router
from api.remediation_routes import router as rem_router
from api.analytics_routes import router as analytics_router
from api.ioc_routes import router as ioc_router
from api.upload_routes import router as upload_router
from api.export_routes import router as export_router
from api.darkweb_routes import router as darkweb_router
from api.actor_routes import router as actor_router
from api.misp_routes import router as misp_router
from api.deck_routes import router as deck_router
from api.cmmc_routes import router as cmmc_router
from api.tabletop_routes import router as tabletop_router
from api.supply_chain_routes import router as supply_chain_router
from api.scanner_routes import router as scanner_router
from api.siem_routes import router as siem_router
from api.oscal_routes import router as oscal_router
from api.ksi_routes import router as ksi_router
from api.audit_routes import router as audit_router

console = Console()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    console.print(Panel.fit(
        "[bold cyan]ThreatPulse Intelligence Feed[/]\n"
        f"[dim]API:  http://{config.HOST}:{config.PORT}[/]\n"
        f"[dim]Docs: http://{config.HOST}:{config.PORT}/docs[/]\n"
        f"[dim]DB:   {config.DB_PATH}[/]",
        border_style="cyan"
    ))

    # Connect to database
    await db.connect()
    console.print("[green]✓ Database connected[/]")

    # Initialize audit log (same SQLite file, separate connection)
    from db.audit_log import init_audit_db
    await init_audit_db()
    console.print("[green]✓ Audit log ready[/]")

    # Seed admin user
    from auth.auth import seed_admin_user
    await seed_admin_user()
    console.print("[green]✓ Admin user ready[/]")

    # Start polling scheduler
    scheduler.start_scheduler()

    # Seed threat actors (no-op if already populated)
    from threat_actors.seed_data import seed_threat_actors
    actor_count = await seed_threat_actors()
    if actor_count > 0:
        console.print(f"[green]Seeded {actor_count} threat actors[/]")

    # Do an initial poll of all feeds on startup
    console.print("[cyan]Running initial feed poll...[/]")
    asyncio.create_task(initial_poll())

    yield

    # Shutdown
    console.print("[yellow]Shutting down ThreatPulse...[/]")
    scheduler.stop_scheduler()
    await db.close()
    console.print("[green]✓ Clean shutdown complete[/]")


async def initial_poll():
    """Run all fetchers once at startup so the DB isn't empty on first launch."""
    await asyncio.sleep(2)  # brief delay to let the server fully start
    try:
        results = await scheduler.run_all()
        total_new = sum(v for v in results.values() if v > 0)
        console.print(f"[green]✓ Initial poll complete — {total_new} new items ingested[/]")
    except Exception as e:
        console.print(f"[red]Initial poll error: {e}[/]")


app = FastAPI(
    title="ThreatPulse Intelligence Feed",
    description=(
        "Real-time threat intelligence aggregation API.\n\n"
        "Ingests CVEs, CISA KEV, vendor advisories, ICS alerts, threat intel, "
        "and supply chain warnings into a unified, searchable feed.\n\n"
        "Use `POST /refresh` to trigger an immediate poll of all sources."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allows the frontend dashboard to call this API from any origin locally
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# FedRAMP 20x audit logging middleware
from api.audit_middleware import AuditMiddleware
app.add_middleware(AuditMiddleware)

app.include_router(router, prefix="/api/v1", tags=["Threat Feed"])
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])
app.include_router(taxii_router, prefix="/api/v1", tags=["TAXII"])
app.include_router(rem_router, prefix="/api/v1", tags=["Remediation"])
app.include_router(analytics_router, prefix="/api/v1", tags=["Analytics"])
app.include_router(ioc_router, prefix="/api/v1", tags=["IOC"])
app.include_router(upload_router, prefix="/api/v1", tags=["Upload"])
app.include_router(export_router, prefix="/api/v1", tags=["Export"])
app.include_router(darkweb_router, prefix="/api/v1", tags=["Dark Web"])
app.include_router(actor_router, prefix="/api/v1", tags=["Threat Actors"])
app.include_router(misp_router, prefix="/api/v1", tags=["MISP"])
app.include_router(deck_router, prefix="/api/v1", tags=["Briefing Deck"])
app.include_router(cmmc_router, prefix="/api/v1", tags=["CMMC"])
app.include_router(tabletop_router, prefix="/api/v1", tags=["Tabletop"])
app.include_router(supply_chain_router, prefix="/api/v1", tags=["Supply Chain"])
app.include_router(scanner_router, tags=["FedRAMP Scanners"])
app.include_router(siem_router, tags=["FedRAMP SIEMs"])
app.include_router(oscal_router, tags=["FedRAMP OSCAL"])
app.include_router(ksi_router, tags=["FedRAMP KSI"])
app.include_router(audit_router, tags=["FedRAMP Audit"])


@app.api_route("/api/ollama/{path:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
async def ollama_proxy(path: str, request: Request):
    body = await request.body()

    async def _stream():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                method=request.method,
                url=f"http://localhost:11434/{path}",
                content=body,
                headers={"Content-Type": request.headers.get("content-type", "application/json")},
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(_stream(), media_type="application/json")


@app.get("/", include_in_schema=False)
async def root():
    stats = await db.get_stats()
    return {
        "service": "ThreatPulse Intelligence Feed",
        "version": "1.0.0",
        "status": "running",
        "docs": f"http://{config.HOST}:{config.PORT}/docs",
        "stats": stats,
    }


app.mount("/", StaticFiles(directory=".", html=True), name="static")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level="warning",  # suppress uvicorn noise; we use rich for logging
    )
