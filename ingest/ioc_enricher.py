"""
PhantomFeed — IOC Enrichment Engine

Enriches IPs, domains, URLs, and file hashes using:
  AbuseIPDB  — IP reputation (requires ABUSEIPDB_API_KEY)
  GreyNoise  — IP classification (requires GREYNOISE_API_KEY)
  VirusTotal — hash/domain/URL scanning (requires VIRUSTOTAL_API_KEY)

All enrichment is cached for 24 hours in the ioc_cache table.
All methods skip gracefully when no API key is configured.
"""

import re
import socket
from datetime import datetime, timedelta
from typing import Optional

import httpx

import config

_IOC_TTL = 24 * 3600  # 24 hours

_IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_MD5  = re.compile(r"^[a-fA-F0-9]{32}$")
_HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_URL_RE    = re.compile(r"^https?://")


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if _HASH_SHA256.match(v): return "sha256"
    if _HASH_SHA1.match(v):   return "sha1"
    if _HASH_MD5.match(v):    return "md5"
    if _IP_RE.match(v):       return "ip"
    if _URL_RE.match(v):      return "url"
    if _DOMAIN_RE.match(v):   return "domain"
    return "unknown"


class IOCEnricher:

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=15.0)

    async def enrich(self, ioc_value: str) -> dict:
        """Auto-detect type and enrich. Returns enrichment dict."""
        from db import database as db

        ioc_value = ioc_value.strip()
        ioc_type = detect_ioc_type(ioc_value)

        # Check cache first
        cached = await db.get_ioc_cache(ioc_value)
        if cached:
            return cached

        result: dict = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "enriched_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(seconds=_IOC_TTL)).isoformat(),
        }

        if ioc_type == "ip":
            ip_data = await self.enrich_ip(ioc_value)
            result.update(ip_data)
        elif ioc_type in ("sha256", "sha1", "md5"):
            hash_data = await self.enrich_hash(ioc_value)
            result.update(hash_data)
        elif ioc_type == "domain":
            dom_data = await self.enrich_domain(ioc_value)
            result.update(dom_data)
        elif ioc_type == "url":
            url_data = await self.enrich_url(ioc_value)
            result.update(url_data)

        # Store in cache
        await db.upsert_ioc_cache(result)
        return result

    async def enrich_ip(self, ip: str) -> dict:
        result = {}
        # AbuseIPDB
        if config.ABUSEIPDB_API_KEY:
            try:
                r = await self._client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    result["abuseipdb_score"]   = d.get("abuseConfidenceScore")
                    result["abuseipdb_country"] = d.get("countryCode")
            except Exception:
                pass

        # GreyNoise
        if config.GREYNOISE_API_KEY:
            try:
                r = await self._client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"key": config.GREYNOISE_API_KEY},
                )
                if r.status_code == 200:
                    d = r.json()
                    result["greynoise_classification"] = d.get("classification")
                    result["greynoise_name"]           = d.get("name")
            except Exception:
                pass

        return result

    async def enrich_hash(self, file_hash: str) -> dict:
        result = {}
        if not config.VIRUSTOTAL_API_KEY:
            return result
        try:
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["vt_malicious"] = stats.get("malicious", 0)
                result["vt_total"]     = sum(stats.values()) if stats else 0
                # Popular threat name
                names = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
                if not names:
                    names_raw = attrs.get("names") or []
                    names = names_raw[0] if names_raw else None
                result["vt_name"] = names
        except Exception:
            pass
        return result

    async def enrich_domain(self, domain: str) -> dict:
        result = {}
        if not config.VIRUSTOTAL_API_KEY:
            return result
        try:
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["vt_malicious"] = stats.get("malicious", 0)
                result["vt_total"]     = sum(stats.values()) if stats else 0
                result["vt_name"]      = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        except Exception:
            pass
        return result

    async def enrich_url(self, url: str) -> dict:
        result = {}
        if not config.VIRUSTOTAL_API_KEY:
            return result
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            r = await self._client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            )
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["vt_malicious"] = stats.get("malicious", 0)
                result["vt_total"]     = sum(stats.values()) if stats else 0
        except Exception:
            pass
        return result

    async def close(self):
        await self._client.aclose()


_enricher: Optional[IOCEnricher] = None


def get_enricher() -> IOCEnricher:
    global _enricher
    if _enricher is None:
        _enricher = IOCEnricher()
    return _enricher


async def auto_enrich_item(item: dict):
    """
    Extract IOC values from a malware/threat item and enrich them.
    Stores enrichment results back onto the item's raw field in DB.
    """
    from db import database as db

    raw = item.get("raw") or {}
    enricher = get_enricher()

    candidates = []
    # IOC value from abuse.ch style items
    if raw.get("ioc_value"):
        candidates.append(raw["ioc_value"])
    if raw.get("ip"):
        candidates.append(raw["ip"])
    if raw.get("sha256"):
        candidates.append(raw["sha256"])

    for val in candidates[:3]:
        if not val:
            continue
        try:
            enrichment = await enricher.enrich(str(val))
            # Merge into raw and update DB
            merged_raw = {**raw, "enrichment": enrichment}
            database = db.get_db()
            import json
            await database.execute(
                "UPDATE threat_items SET raw = ? WHERE id = ?",
                (json.dumps(merged_raw), item.get("id")),
            )
            await database.commit()
        except Exception:
            pass
