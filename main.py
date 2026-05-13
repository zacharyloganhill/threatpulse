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
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from api.rate_limit import check_rate_limit
from auth.auth import get_current_user
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
from api.integration_routes import router as integration_router
from api.scanner_routes import router as scanner_router
from api.siem_routes import router as siem_router
from api.oscal_routes import router as oscal_router
from api.ksi_routes import router as ksi_router
from api.audit_routes import router as audit_router
from api.nav_routes import router as nav_router
from api.report_routes import router as report_router

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

    # Warn on insecure defaults — never silently run with known credentials
    _defaults = {
        "SECRET_KEY": ("change-me-in-production", config.SECRET_KEY),
        "ADMIN_PASSWORD": ("phantomfeed-admin", config.ADMIN_PASSWORD),
    }
    for var, (bad, actual) in _defaults.items():
        if actual == bad:
            console.print(
                f"[bold red]⚠ WARNING: {var} is set to the default value. "
                f"Set a strong value in your .env file before exposing this server.[/]"
            )

    # Hard-fail if the server is network-exposed without an explicit encryption key.
    # Locally (127.0.0.1) the auto-generated key is acceptable for development;
    # any other bind address means real scanner/SIEM credentials could be at risk.
    _is_local = config.HOST in ("127.0.0.1", "localhost", "::1")
    if not config.PHANTOMFEED_ENCRYPTION_KEY and not _is_local:
        raise RuntimeError(
            "PHANTOMFEED_ENCRYPTION_KEY must be set when HOST is not localhost. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )

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

    # Purge expired token denylist entries from previous runs
    from db.database import purge_expired_tokens
    await purge_expired_tokens()

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
    # Disable built-in docs/schema routes; re-exposed below with auth
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# CORS — only allow the origins this server is known to be served from.
# Override with the CORS_ORIGINS env var (comma-separated) in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# FedRAMP 20x audit logging middleware
from api.audit_middleware import AuditMiddleware
app.add_middleware(AuditMiddleware)

_MAX_JSON_BODY = 1 * 1024 * 1024  # 1 MB — generous for any legitimate API call


@app.middleware("http")
async def limit_json_body(request: Request, call_next):
    ct = request.headers.get("content-type", "")
    if "application/json" in ct:
        cl = request.headers.get("content-length")
        if cl and int(cl) > _MAX_JSON_BODY:
            return Response(
                content='{"detail":"Request body too large (max 1 MB for JSON)"}',
                status_code=413,
                media_type="application/json",
            )
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Only set HSTS when served over HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Content-Security-Policy
    # 'unsafe-inline' is required because the current frontend uses inline <script>
    # and style= attributes throughout. Migrating to nonces would allow removing it.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://d3js.org; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    return response

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
app.include_router(integration_router, tags=["Integrations"])
app.include_router(scanner_router, tags=["FedRAMP Scanners"])
app.include_router(siem_router, tags=["FedRAMP SIEMs"])
app.include_router(oscal_router, tags=["FedRAMP OSCAL"])
app.include_router(ksi_router, tags=["FedRAMP KSI"])
app.include_router(audit_router, tags=["FedRAMP Audit"])
app.include_router(nav_router, tags=["Navigation"])
app.include_router(report_router, tags=["Reports"])


@app.get("/docs", include_in_schema=False)
async def swagger_ui(_: dict = Depends(get_current_user)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="ThreatPulse API — Docs")


@app.get("/redoc", include_in_schema=False)
async def redoc_ui(_: dict = Depends(get_current_user)):
    return get_redoc_html(openapi_url="/openapi.json", title="ThreatPulse API — ReDoc")


@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema(_: dict = Depends(get_current_user)):
    return app.openapi()


@app.api_route("/api/ollama/{path:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
async def ollama_proxy(path: str, request: Request, user: dict = Depends(get_current_user)):
    # 30 req/min per user — prevents runaway LLM call loops
    check_rate_limit(f"ollama:{user.get('sub', 'anon')}", 30, 60)
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


@app.get("/health", include_in_schema=False)
async def health():
    """Unauthenticated liveness + readiness probe for load balancers and Docker HEALTHCHECK."""
    from fastapi.responses import JSONResponse
    try:
        _db = db.get_db()
        async with _db.execute("SELECT 1") as cur:
            await cur.fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    if not db_ok:
        return JSONResponse(status_code=503, content={"status": "degraded", "db": "error"})
    return {"status": "ok", "db": "ok"}


@app.get("/", include_in_schema=False)
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/index.html")


app.mount("/", StaticFiles(directory=".", html=True), name="static")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level="warning",  # suppress uvicorn noise; we use rich for logging
    )
