"""
PhantomFeed — Upload API Routes

POST /api/v1/upload/scan               Auto-detect and preview scan file
POST /api/v1/upload/scan/{id}/confirm  Confirm and import scan
POST /api/v1/upload/assets             Preview asset CSV/XLSX
POST /api/v1/upload/assets/{id}/confirm Confirm asset import
POST /api/v1/upload/iocs               Preview IOC list
POST /api/v1/upload/stix               Import STIX bundle
POST /api/v1/upload/clients            Bulk client import preview
GET  /api/v1/upload/history            Upload log
GET  /api/v1/upload/templates/{type}   Download CSV templates
"""

import csv
import io
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse

router = APIRouter()

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


def _check_size(data: bytes) -> None:
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File too large (max {MAX_UPLOAD_BYTES // (1024*1024)} MB)")


def _scope_client(user: dict, client_id: Optional[str]) -> Optional[str]:
    """Non-admins may only operate on their own client_id."""
    if user.get("role") == "admin":
        return client_id
    own = user.get("client_id")
    if client_id and client_id != own:
        raise HTTPException(403, "Access denied")
    return client_id

from auth.auth import get_current_user, decode_token, require_client_access

TEMP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads", "temp")
os.makedirs(TEMP_DIR, exist_ok=True)


def _temp_path(upload_id: str, ext: str = ".bin") -> str:
    return os.path.join(TEMP_DIR, f"{upload_id}{ext}")


def _save_temp(data: bytes, upload_id: str, filename: str) -> str:
    ext = os.path.splitext(filename)[1] or ".bin"
    path = _temp_path(upload_id, ext)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _load_temp(upload_id: str, filename: str) -> bytes:
    ext = os.path.splitext(filename)[1] or ".bin"
    path = _temp_path(upload_id, ext)
    if not os.path.exists(path):
        # try any extension
        for f in os.listdir(TEMP_DIR):
            if f.startswith(upload_id):
                path = os.path.join(TEMP_DIR, f)
                break
    if not os.path.exists(path):
        raise HTTPException(404, "Upload file not found. Re-upload the file.")
    with open(path, "rb") as f:
        return f.read()


def _cleanup_temp(upload_id: str):
    for f in os.listdir(TEMP_DIR):
        if f.startswith(upload_id):
            try:
                os.remove(os.path.join(TEMP_DIR, f))
            except OSError:
                pass


async def _cleanup_old_temp():
    """Remove temp files older than 1 hour."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    for fname in os.listdir(TEMP_DIR):
        fpath = os.path.join(TEMP_DIR, fname)
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc).replace(tzinfo=None)
            if mtime < cutoff:
                os.remove(fpath)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# POST /upload/scan
# ---------------------------------------------------------------------------

@router.post("/upload/scan")
async def upload_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    client_id: Optional[str] = Query(None),
    user: dict = Depends(get_current_user),
):
    """Auto-detect scan format, parse, return preview."""
    client_id = _scope_client(user, client_id)
    if background_tasks:
        background_tasks.add_task(_cleanup_old_temp)

    data = await file.read()
    _check_size(data)
    filename = file.filename or "upload.bin"

    from uploads.parsers import detect_parser
    fmt, parser = detect_parser(data, filename)

    try:
        result = parser.parse(data, filename)
    except Exception as e:
        raise HTTPException(400, f"Parse error: {e}")

    upload_id = str(uuid.uuid4())
    _save_temp(data, upload_id, filename)

    from uploads.upload_log import create_upload_log
    log = await create_upload_log(filename=filename, file_type=fmt, client_id=client_id, status="preview")
    upload_id = log["id"]
    _save_temp(data, upload_id, filename)

    assets = result.get("assets", [])
    findings = result.get("findings", [])

    return {
        "upload_id": upload_id,
        "detected_format": fmt,
        "assets_found": len(assets),
        "findings_found": len(findings),
        "preview_rows": findings[:5],
        "asset_preview": assets[:5],
        "field_mapping": result.get("field_mapping", {}),
    }


# ---------------------------------------------------------------------------
# POST /upload/scan/{upload_id}/confirm
# ---------------------------------------------------------------------------

@router.post("/upload/scan/{upload_id}/confirm")
async def confirm_scan(upload_id: str, _: dict = Depends(get_current_user)):
    """Confirm and import a previously previewed scan file."""
    from uploads.upload_log import get_upload_log, update_upload_log
    log = await get_upload_log(upload_id)
    if not log:
        raise HTTPException(404, "Upload not found")

    filename = log["filename"]
    client_id = log.get("client_id")
    fmt = log["file_type"]

    try:
        data = _load_temp(upload_id, filename)
    except HTTPException:
        raise

    from uploads.parsers import detect_parser
    _, parser = detect_parser(data, filename)
    result = parser.parse(data, filename)

    assets = result.get("assets", [])
    findings = result.get("findings", [])

    imported_assets = 0
    imported_findings = 0
    matched_cves = 0
    errors = []

    if client_id:
        from db import database as db
        from ingest.cpe_matcher import match_item_to_assets
        from compliance.mappings import tag_item
        from ingest.risk_score import score_item

        # Import assets
        asset_ids = []
        for asset in assets:
            try:
                aid = await db.upsert_asset(
                    client_id=client_id,
                    software=asset.get("software") or asset.get("os") or "Unknown",
                    version=asset.get("version", ""),
                    hostname=asset.get("hostname", ""),
                    ip_address=asset.get("ip_address", ""),
                    os=asset.get("os", ""),
                    os_version=asset.get("os_version", ""),
                )
                asset_ids.append(aid)
                imported_assets += 1
            except Exception as e:
                errors.append(str(e)[:100])

        # Import findings as threat items
        all_assets = await db.get_assets(client_id)
        for finding in findings:
            cves = finding.get("cve_ids", [])
            matched_cves += len(cves)
            title = finding.get("title", "")
            if not title:
                continue
            from ingest.base import BaseFetcher
            item = {
                "feed_id": f"scan_upload_{fmt}",
                "feed_label": f"Scan Upload ({fmt.upper()})",
                "category": "cve" if cves else "advisory",
                "severity": finding.get("severity", "MEDIUM"),
                "title": title[:250],
                "description": finding.get("description", "")[:2000],
                "vendor": "",
                "product": "",
                "url": "",
                "published_at": datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d"),
                "cve_ids": cves,
                "tags": [finding.get("hostname", ""), finding.get("ip_address", "")],
                "raw": {"solution": finding.get("solution", "")},
                "compliance_tags": [],
            }
            item["compliance_tags"] = tag_item(item)
            try:
                inserted = await db.upsert_item(item)
                if inserted:
                    imported_findings += 1
                    # CPE match new finding against assets
                    matches = match_item_to_assets(item, all_assets)
                    item_id = db.make_id(item["feed_id"], item["title"], item.get("published_at", ""))
                    for m in matches:
                        await db.upsert_exposure(
                            client_id=m["client_id"],
                            item_id=item_id,
                            asset_id=m["asset_id"],
                            match_type=m["match_type"],
                            confidence=m["confidence"],
                        )
            except Exception as e:
                errors.append(str(e)[:100])

    await update_upload_log(
        upload_id=upload_id,
        status="imported" if not errors else "partial",
        records_total=len(assets) + len(findings),
        records_imported=imported_assets + imported_findings,
        records_skipped=max(0, len(assets) + len(findings) - imported_assets - imported_findings),
        error_message="; ".join(errors[:5]) if errors else None,
        completed=True,
    )
    _cleanup_temp(upload_id)

    return {
        "upload_id": upload_id,
        "imported_assets": imported_assets,
        "imported_findings": imported_findings,
        "matched_cves": matched_cves,
        "errors": errors[:10],
    }


# ---------------------------------------------------------------------------
# POST /upload/assets
# ---------------------------------------------------------------------------

@router.post("/upload/assets")
async def upload_assets(
    file: UploadFile = File(...),
    client_id: Optional[str] = Query(None),
    user: dict = Depends(get_current_user),
):
    """Preview an asset CSV/XLSX upload."""
    client_id = _scope_client(user, client_id)
    data = await file.read()
    _check_size(data)
    filename = file.filename or "assets.csv"

    from uploads.parsers import GenericCSVParser
    parser = GenericCSVParser()
    result = parser.parse(data, filename)

    from uploads.upload_log import create_upload_log
    log = await create_upload_log(
        filename=filename,
        file_type=result.get("format", "generic_csv"),
        client_id=client_id,
        status="preview",
    )
    upload_id = log["id"]
    _save_temp(data, upload_id, filename)

    return {
        "upload_id": upload_id,
        "assets_found": len(result.get("assets", [])),
        "preview": result.get("preview", []),
        "field_mapping": result.get("field_mapping", {}),
        "detected_format": result.get("format"),
    }


# ---------------------------------------------------------------------------
# POST /upload/assets/{upload_id}/confirm
# ---------------------------------------------------------------------------

@router.post("/upload/assets/{upload_id}/confirm")
async def confirm_assets(
    upload_id: str,
    body: Optional[dict] = None,
    _: dict = Depends(get_current_user),
):
    """Confirm asset import with optional field mapping override."""
    from uploads.upload_log import get_upload_log, update_upload_log
    log = await get_upload_log(upload_id)
    if not log:
        raise HTTPException(404, "Upload not found")

    client_id = log.get("client_id")
    filename = log["filename"]

    data = _load_temp(upload_id, filename)
    from uploads.parsers import GenericCSVParser
    parser = GenericCSVParser()
    result = parser.parse(data, filename)

    # Allow field mapping override from body
    if body and body.get("field_mapping"):
        result["field_mapping"] = body["field_mapping"]
        assets, _ = parser._extract(result.get("preview", []), result["field_mapping"])
        result["assets"] = assets

    assets = result.get("assets", [])
    imported = 0
    errors = []

    if client_id:
        from db import database as db
        for asset in assets:
            try:
                await db.upsert_asset(
                    client_id=client_id,
                    software=asset.get("software") or "Unknown",
                    version=asset.get("version", ""),
                    hostname=asset.get("hostname", ""),
                    ip_address=asset.get("ip_address", ""),
                    os=asset.get("os", ""),
                )
                imported += 1
            except Exception as e:
                errors.append(str(e)[:100])

    await update_upload_log(
        upload_id=upload_id,
        status="imported" if not errors else "partial",
        records_total=len(assets),
        records_imported=imported,
        records_skipped=len(assets) - imported,
        error_message="; ".join(errors[:3]) if errors else None,
        completed=True,
    )
    _cleanup_temp(upload_id)
    return {"upload_id": upload_id, "imported_assets": imported, "errors": errors[:5]}


# ---------------------------------------------------------------------------
# POST /upload/iocs
# ---------------------------------------------------------------------------

@router.post("/upload/iocs")
async def upload_iocs(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    client_id: Optional[str] = Query(None),
    user: dict = Depends(get_current_user),
):
    """Preview IOC list; triggers enrichment as background task."""
    client_id = _scope_client(user, client_id)
    data = await file.read()
    _check_size(data)
    filename = file.filename or "iocs.txt"

    from uploads.parsers import IOCParser
    parser = IOCParser()
    result = parser.parse(data, filename)
    iocs = result.get("iocs", [])

    from uploads.upload_log import create_upload_log
    log = await create_upload_log(
        filename=filename,
        file_type=result.get("format", "ioc_txt"),
        client_id=client_id,
        status="imported",
    )
    upload_id = log["id"]

    # Store each IOC in ioc_cache (without enrichment yet) and trigger enrichment
    from db import database as db
    from ingest.ioc_enricher import IOCEnricher, detect_ioc_type
    enricher = IOCEnricher()

    async def _enrich_all(ioc_list):
        for ioc in ioc_list:
            try:
                await enricher.enrich(ioc["value"])
            except Exception:
                pass
        from uploads.upload_log import update_upload_log as _update
        await _update(upload_id=upload_id, status="enriched", records_imported=len(ioc_list), completed=True)

    background_tasks.add_task(_enrich_all, iocs)

    return {
        "upload_id": upload_id,
        "iocs_found": len(iocs),
        "preview": iocs[:20],
        "format": result.get("format"),
    }


# ---------------------------------------------------------------------------
# POST /upload/stix
# ---------------------------------------------------------------------------

@router.post("/upload/stix")
async def upload_stix(file: UploadFile = File(...), _: dict = Depends(get_current_user)):
    """Parse a STIX 2.1 JSON bundle and import objects as threat items."""
    data = await file.read()
    _check_size(data)
    filename = file.filename or "bundle.json"

    from uploads.parsers import STIXBundleParser
    parser = STIXBundleParser()
    result = parser.parse(data, filename)

    if result.get("error"):
        raise HTTPException(400, result["error"])

    items = result.get("items", [])
    imported = 0
    from db import database as db
    from compliance.mappings import tag_item

    for item in items:
        item["compliance_tags"] = tag_item(item)
        try:
            inserted = await db.upsert_item(item)
            if inserted:
                imported += 1
        except Exception:
            pass

    return {
        "imported": imported,
        "total": len(items),
        "counts": result.get("counts", {}),
    }


# ---------------------------------------------------------------------------
# POST /upload/clients
# ---------------------------------------------------------------------------

@router.post("/upload/clients")
async def upload_clients(
    file: UploadFile = File(...),
    _: dict = Depends(get_current_user),
):
    """Preview bulk client import from CSV/XLSX."""
    data = await file.read()
    _check_size(data)
    filename = file.filename or "clients.csv"

    text = data.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = [dict(r) for r in reader]
    preview = rows[:5]

    from uploads.upload_log import create_upload_log
    log = await create_upload_log(filename=filename, file_type="client_csv", status="preview")
    upload_id = log["id"]
    _save_temp(data, upload_id, filename)

    return {
        "upload_id": upload_id,
        "clients_found": len(rows),
        "preview": preview,
        "columns": reader.fieldnames or [],
    }


@router.post("/upload/clients/{upload_id}/confirm")
async def confirm_clients(upload_id: str, _: dict = Depends(get_current_user)):
    """Confirm bulk client import."""
    from uploads.upload_log import get_upload_log, update_upload_log
    log = await get_upload_log(upload_id)
    if not log:
        raise HTTPException(404, "Upload not found")

    data = _load_temp(upload_id, log["filename"])
    text = data.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)

    from db import database as db
    imported = 0
    errors = []
    for row in rows:
        name = (row.get("name") or row.get("Name") or "").strip()
        if not name:
            continue
        contact = (row.get("contact_email") or row.get("email") or "").strip()
        vendors = [v.strip() for v in (row.get("vendors") or "").split(";") if v.strip()]
        products = [p.strip() for p in (row.get("products") or "").split(";") if p.strip()]
        min_sev = (row.get("min_severity") or "MEDIUM").strip().upper()
        stack = {"vendors": vendors, "products": products, "min_severity": min_sev}
        try:
            await db.create_client(name=name, contact_email=contact, stack_profile=stack)
            imported += 1
        except Exception as e:
            errors.append(str(e)[:100])

    await update_upload_log(
        upload_id=upload_id,
        status="imported",
        records_total=len(rows),
        records_imported=imported,
        completed=True,
    )
    _cleanup_temp(upload_id)
    return {"imported_clients": imported, "errors": errors[:5]}


# ---------------------------------------------------------------------------
# GET /upload/history
# ---------------------------------------------------------------------------

@router.get("/upload/history")
async def upload_history(
    client_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    user: dict = Depends(get_current_user),
):
    client_id = _scope_client(user, client_id)
    from uploads.upload_log import list_upload_logs
    return await list_upload_logs(client_id=client_id, limit=limit)


# ---------------------------------------------------------------------------
# GET /upload/templates/{type}
# ---------------------------------------------------------------------------

TEMPLATES = {
    "assets": {
        "headers": ["hostname", "ip_address", "os", "os_version", "software", "version", "cpe_string", "asset_type"],
        "rows": [
            ["srv01", "10.0.0.1", "Windows", "2019", "Microsoft Windows Server", "2019", "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", "server"],
            ["web01", "10.0.0.2", "Linux", "Ubuntu 22.04", "Apache HTTP Server", "2.4.58", "", "server"],
        ],
    },
    "clients": {
        "headers": ["name", "industry", "contact_email", "min_severity", "vendors", "products"],
        "rows": [
            ["Acme Corp", "Finance", "security@acme.com", "HIGH", "Microsoft;Cisco", "Windows Server;IOS"],
            ["Beta Ltd", "Healthcare", "it@beta.com", "MEDIUM", "Oracle;VMware", "Database;vSphere"],
        ],
    },
    "iocs": {
        "headers": ["type", "value", "source", "confidence", "notes"],
        "rows": [
            ["ip", "192.168.1.1", "manual", "high", ""],
            ["sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "manual", "medium", "empty file hash"],
        ],
    },
}


async def _auth_token_or_header(request: Request, token: Optional[str] = Query(None)) -> dict:
    raw = token
    if not raw:
        h = request.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            raw = h[7:]
    if not raw:
        raise HTTPException(401, "Not authenticated")
    payload = decode_token(raw)
    if not payload.get("sub"):
        raise HTTPException(401, "Invalid token")
    return payload


@router.get("/upload/templates/{template_type}")
async def download_template(template_type: str, _: dict = Depends(_auth_token_or_header)):
    tmpl = TEMPLATES.get(template_type)
    if not tmpl:
        raise HTTPException(404, f"Unknown template type '{template_type}'. Choose: {', '.join(TEMPLATES)}")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(tmpl["headers"])
    writer.writerows(tmpl["rows"])

    content = buf.getvalue().encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="phantomfeed_{template_type}_template.csv"'},
    )
