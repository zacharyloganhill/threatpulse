"""
PhantomFeed — SIEM Webhook Dispatcher

Supports: generic, slack, splunk_hec, sentinel
Retry logic: 3 attempts with exponential backoff.
Errors logged to webhook_errors table.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Optional

import httpx

SEV_COLORS = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#d69e2e",
    "LOW":      "#38a169",
    "INFO":     "#718096",
}


def _item_payload(item: dict) -> dict:
    return {
        "id":             item.get("id"),
        "title":          item.get("title"),
        "severity":       item.get("severity"),
        "cvss":           item.get("cvss"),
        "risk_score":     item.get("risk_score"),
        "vendor":         item.get("vendor"),
        "product":        item.get("product"),
        "published_at":   item.get("published_at"),
        "url":            item.get("url"),
        "cve_ids":        item.get("cve_ids") or [],
        "tags":           item.get("tags") or [],
        "compliance":     item.get("compliance_tags") or [],
        "category":       item.get("category"),
        "feed_label":     item.get("feed_label"),
        "source":         "PhantomFeed",
    }


def _slack_blocks(item: dict) -> dict:
    sev = item.get("severity", "INFO")
    color = SEV_COLORS.get(sev, "#718096")
    rs = item.get("risk_score")
    rs_str = f"{rs:.1f}" if rs is not None else "N/A"
    cves = ", ".join(item.get("cve_ids") or []) or "None"
    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*[{sev}] {item.get('title','')[:100]}*"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{sev}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:*\n{rs_str} / 10"},
                        {"type": "mrkdwn", "text": f"*CVSS:*\n{item.get('cvss','N/A')}"},
                        {"type": "mrkdwn", "text": f"*CVEs:*\n{cves}"},
                        {"type": "mrkdwn", "text": f"*Vendor:*\n{item.get('vendor','—')}"},
                        {"type": "mrkdwn", "text": f"*Published:*\n{item.get('published_at','—')}"},
                    ]
                },
                {
                    "type": "actions",
                    "elements": [{
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "url": item.get("url") or "https://github.com/zacharyloganhill/PhantomFeed",
                        "style": "danger" if sev in ("CRITICAL", "HIGH") else "primary"
                    }]
                }
            ]
        }]
    }


def _splunk_payload(item: dict) -> dict:
    return {
        "time": datetime.utcnow().timestamp(),
        "sourcetype": "phantomfeed:threat",
        "source": "PhantomFeed",
        "event": _item_payload(item),
    }


def _sentinel_signature(workspace_key: str, date: str, content_length: int) -> str:
    """Build HMAC-SHA256 authorization header for Azure Sentinel."""
    string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
    decoded_key = base64.b64decode(workspace_key)
    signature = base64.b64encode(
        hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")
    return signature


class WebhookDispatcher:

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=15.0)

    async def dispatch(self, item: dict, client_id: Optional[str] = None):
        """Find all matching webhooks and fire them."""
        from db import database as db
        webhooks = await db.get_active_webhooks_for_severity(
            item.get("severity", "INFO"),
            item.get("category", ""),
        )
        # If client_id given, filter to that client's webhooks only
        if client_id:
            webhooks = [w for w in webhooks if w.get("client_id") == client_id]

        for wh in webhooks:
            await self.dispatch_to_webhook(wh, item)

    async def dispatch_to_webhook(self, wh: dict, item: dict) -> str:
        """Fire a single webhook. Returns 'ok' or error message."""
        for attempt in range(3):
            try:
                result = await self._fire(wh, item)
                # Update last_fired
                from db import database as db
                await db.update_webhook(wh["id"], last_fired=datetime.utcnow().isoformat())
                return result
            except Exception as exc:
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                else:
                    await self._log_error(wh["id"], str(exc))
                    return f"error: {exc}"
        return "failed"

    async def _fire(self, wh: dict, item: dict) -> str:
        wtype = wh.get("webhook_type", "generic")
        url = wh.get("url", "")
        headers = {"Content-Type": "application/json"}

        if wtype == "generic":
            body = json.dumps(_item_payload(item))

        elif wtype == "slack":
            body = json.dumps(_slack_blocks(item))

        elif wtype == "splunk_hec":
            body = json.dumps(_splunk_payload(item))
            token = wh.get("secret", "")
            if token:
                headers["Authorization"] = f"Splunk {token}"

        elif wtype == "sentinel":
            payload = _item_payload(item)
            body = json.dumps([payload])
            date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers["x-ms-date"] = date
            headers["Log-Type"] = "PhantomFeed"
            workspace_key = wh.get("secret", "")
            if workspace_key:
                sig = _sentinel_signature(workspace_key, date, len(body))
                workspace_id = url.split(".")[0].replace("https://", "")
                headers["Authorization"] = f"SharedKey {workspace_id}:{sig}"
        else:
            body = json.dumps(_item_payload(item))

        r = await self._client.post(url, content=body.encode(), headers=headers)
        if r.status_code >= 400:
            raise ValueError(f"HTTP {r.status_code}: {r.text[:200]}")
        return "ok"

    async def _log_error(self, webhook_id: str, error: str):
        try:
            from db import database as db_mod
            database = db_mod.get_db()
            await database.execute(
                "INSERT INTO webhook_errors (id, webhook_id, error, created_at) VALUES (?,?,?,?)",
                (str(uuid.uuid4()), webhook_id, error[:500], datetime.utcnow().isoformat()),
            )
            await database.commit()
        except Exception:
            pass

    async def close(self):
        await self._client.aclose()


_dispatcher: Optional[WebhookDispatcher] = None


def get_dispatcher() -> WebhookDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = WebhookDispatcher()
    return _dispatcher
