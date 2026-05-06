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

console = Console()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    console.print(Panel.fit(
        "[bold cyan]ThreatPulse Intelligence Feed[/]\n"
        f"[dim]API → http://{config.HOST}:{config.PORT}[/]\n"
        f"[dim]Docs → http://{config.HOST}:{config.PORT}/docs[/]\n"
        f"[dim]Database → {config.DB_PATH}[/]",
        border_style="cyan"
    ))

    # Connect to database
    await db.connect()
    console.print("[green]✓ Database connected[/]")

    # Seed admin user
    from auth.auth import seed_admin_user
    await seed_admin_user()
    console.print("[green]✓ Admin user ready[/]")

    # Start polling scheduler
    scheduler.start_scheduler()

    # Do an initial poll of all feeds on startup
    console.print("[cyan]↓ Running initial feed poll...[/]")
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

app.include_router(router, prefix="/api/v1", tags=["Threat Feed"])
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(admin_router, prefix="/api/v1/admin", tags=["Admin"])
app.include_router(taxii_router, prefix="/api/v1", tags=["TAXII"])
app.include_router(rem_router, prefix="/api/v1", tags=["Remediation"])
app.include_router(analytics_router, prefix="/api/v1", tags=["Analytics"])
app.include_router(ioc_router, prefix="/api/v1", tags=["IOC"])


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
