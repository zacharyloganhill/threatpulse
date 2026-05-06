"""PhantomFeed — IOC Lookup API Routes"""

from fastapi import APIRouter, Query, HTTPException
from db import database as db
from ingest.ioc_enricher import get_enricher, detect_ioc_type

router = APIRouter()


@router.get("/ioc/lookup", summary="Lookup and enrich an IOC (IP, hash, domain, URL)")
async def ioc_lookup(value: str = Query(..., description="IP, MD5/SHA1/SHA256, domain, or URL")):
    value = value.strip()
    ioc_type = detect_ioc_type(value)
    if ioc_type == "unknown":
        raise HTTPException(status_code=422, detail=f"Cannot detect IOC type for: {value!r}")
    enricher = get_enricher()
    result = await enricher.enrich(value)
    return result


@router.get("/ioc/cache", summary="List recent IOC cache entries")
async def ioc_cache_list(limit: int = Query(100, ge=1, le=500)):
    entries = await db.list_ioc_cache(limit=limit)
    return {"count": len(entries), "entries": entries}
