"""
ThreatPulse — Base Feed Fetcher
All ingestors inherit from BaseFetcher. Handles HTTP, retries, and logging.
"""

import asyncio
import httpx
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from rich.console import Console

console = Console()

DEFAULT_HEADERS = {
    "User-Agent": "ThreatPulse/1.0 (+https://github.com/yourorg/threatpulse)",
    "Accept": "application/json, application/xml, text/xml, */*",
}


class BaseFetcher(ABC):
    """Abstract base for all feed ingestors."""

    feed_id: str = ""
    feed_label: str = ""
    category: str = "advisory"
    poll_interval: int = 60  # minutes

    def __init__(self):
        self.client = httpx.AsyncClient(
            headers=DEFAULT_HEADERS,
            timeout=30.0,
            follow_redirects=True,
        )

    async def close(self):
        await self.client.aclose()

    async def fetch_json(self, url: str, params: dict = None, headers: dict = None) -> Optional[dict]:
        try:
            r = await self.client.get(url, params=params, headers=headers)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red][{self.feed_id}] HTTP {e.response.status_code} for {url}[/]")
        except httpx.RequestError as e:
            console.print(f"[yellow][{self.feed_id}] Request error: {e}[/]")
        except Exception as e:
            console.print(f"[red][{self.feed_id}] Unexpected error: {e}[/]")
        return None

    async def fetch_json_post(self, url: str, data: dict = None, json_body: dict = None, headers: dict = None) -> Optional[dict]:
        try:
            r = await self.client.post(url, data=data, json=json_body, headers=headers)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red][{self.feed_id}] HTTP {e.response.status_code} for {url}[/]")
        except httpx.RequestError as e:
            console.print(f"[yellow][{self.feed_id}] Request error: {e}[/]")
        except Exception as e:
            console.print(f"[red][{self.feed_id}] Unexpected error: {e}[/]")
        return None

    async def fetch_text(self, url: str, headers: dict = None) -> Optional[str]:
        try:
            r = await self.client.get(url, headers=headers)
            r.raise_for_status()
            return r.text
        except Exception as e:
            console.print(f"[yellow][{self.feed_id}] Fetch error: {e}[/]")
        return None

    @abstractmethod
    async def fetch(self) -> list[dict]:
        """
        Fetch and normalize items from the source.
        Must return a list of dicts conforming to the threat_items schema.
        """
        ...

    async def run(self) -> int:
        """Fetch, insert new items, score & tag them, return count of new insertions."""
        from db import database as db
        from compliance.mappings import tag_item
        from ingest.risk_score import score_item

        console.print(f"[cyan]↓ Polling [{self.feed_label}]...[/]")
        start = datetime.utcnow()
        try:
            items = await self.fetch()
        except Exception as e:
            console.print(f"[red][{self.feed_id}] fetch() raised: {e}[/]")
            return 0

        new_count = 0
        new_ids = []
        for item in items:
            # Compliance tagging is pure in-process; add before insert
            if not item.get("compliance_tags"):
                item["compliance_tags"] = tag_item(item)
            inserted = await db.upsert_item(item)
            if inserted:
                new_count += 1
                # Stash id so we can rescore after the batch
                new_ids.append(
                    item.get("id") or db.make_id(
                        item["feed_id"], item["title"], item.get("published_at", "")
                    )
                )

        # Score new items and run asset matching
        if new_ids:
            all_assets = await db.get_all_assets_for_matching()
            from ingest.cpe_matcher import match_item_to_assets

        for item in items:
            item_id = item.get("id") or db.make_id(
                item["feed_id"], item["title"], item.get("published_at", "")
            )
            if item_id in new_ids:
                try:
                    rs = await score_item(item)
                    if rs > 0:
                        await db.update_risk_score(item_id, rs)
                except Exception:
                    pass
                # Fire webhooks for new items
                try:
                    from reports.webhook_dispatcher import get_dispatcher
                    dispatcher = get_dispatcher()
                    await dispatcher.dispatch(item)
                except Exception:
                    pass
                # Auto-enrich IOCs for malware/threat items
                if item.get("category") in ("malware", "threat"):
                    try:
                        from ingest.ioc_enricher import auto_enrich_item
                        await auto_enrich_item({**item, "id": item_id})
                    except Exception:
                        pass
                # Asset matching
                if new_ids and all_assets:
                    try:
                        matches = match_item_to_assets(item, all_assets)
                        for m in matches:
                            await db.upsert_exposure(
                                client_id=m["client_id"],
                                item_id=item_id,
                                asset_id=m["asset_id"],
                                match_type=m["match_type"],
                                confidence=m["confidence"],
                            )
                    except Exception:
                        pass

        elapsed = (datetime.utcnow() - start).total_seconds()
        console.print(
            f"[green]✓ [{self.feed_label}][/] {len(items)} fetched, "
            f"[bold]{new_count} new[/] ({elapsed:.1f}s)"
        )
        return new_count

    def _parse_date(self, entry) -> str:
        """Parse RSS entry date fields to YYYY-MM-DD."""
        from email.utils import parsedate_to_datetime
        for field in ("published", "updated", "created"):
            val = entry.get(field, "")
            if val:
                try:
                    dt = parsedate_to_datetime(val)
                    return dt.strftime("%Y-%m-%d")
                except Exception:
                    try:
                        return val[:10]
                    except Exception:
                        pass
        return datetime.utcnow().strftime("%Y-%m-%d")

    @staticmethod
    def extract_cves(text: str) -> list[str]:
        """Pull all CVE IDs from any text blob."""
        import re
        return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))

    @staticmethod
    def truncate(text: str, max_len: int = 2000) -> str:
        if not text:
            return ""
        return text[:max_len] + ("…" if len(text) > max_len else "")
