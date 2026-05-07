"""Google Chronicle SIEM fetcher (UDM query via Chronicle API v2)."""

import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

from ingest.siems.base import BaseSIEMFetcher

logger = logging.getLogger(__name__)

_CHRONICLE_BASE = "https://backstory.googleapis.com/v2"


class ChronicleFetcher(BaseSIEMFetcher):
    siem_type = "chronicle"

    def _service_account(self) -> dict:
        """Parse service-account JSON from api_key field or extra_config."""
        raw = self._api_key()
        if not raw:
            raw = self.extra.get("service_account_json", "")
        if not raw:
            raise ValueError("Chronicle requires a service account JSON credential")
        return json.loads(raw)

    async def _get_access_token(self, sa: dict) -> str:
        """Exchange service account credentials for a Bearer token."""
        try:
            import google.auth.transport.requests
            import google.oauth2.service_account
            creds = google.oauth2.service_account.Credentials.from_service_account_info(
                sa,
                scopes=["https://www.googleapis.com/auth/chronicle-backstory"],
            )
            req = google.auth.transport.requests.Request()
            creds.refresh(req)
            return creds.token
        except ImportError:
            raise RuntimeError(
                "google-auth package not installed. Run: pip install google-auth"
            )

    async def fetch(self) -> list[dict]:
        sa = self._service_account()
        token = await self._get_access_token(sa)

        query = self.extra.get("query") or (
            'severity = "CRITICAL" OR severity = "HIGH"'
        )
        lookback_h = int(str(self.extra.get("lookback_window", "24h")).replace("h", "")) if "h" in str(self.extra.get("lookback_window", "24h")) else 24
        max_results = int(self.extra.get("max_results", 100))
        start = (datetime.now(timezone.utc) - timedelta(hours=lookback_h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "query": query,
            "timeRange": {"startTime": start, "endTime": end},
            "maxEvents": max_results,
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{_CHRONICLE_BASE}/detect/rules:runQuery", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        events = data.get("events", [])
        findings = []
        for ev in events:
            metadata = ev.get("udm", {}).get("metadata", {})
            principal = ev.get("udm", {}).get("principal", {})
            sec_result = ev.get("udm", {}).get("securityResult", [{}])[0] if ev.get("udm", {}).get("securityResult") else {}
            sev_label = sec_result.get("severity", "UNKNOWN")
            findings.append({
                "title":       metadata.get("description") or sec_result.get("ruleName") or "Chronicle Alert",
                "severity":    self._sev(sev_label),
                "hostname":    principal.get("hostname"),
                "ip_address":  principal.get("ip", [None])[0] if principal.get("ip") else None,
                "description": sec_result.get("description"),
                "raw":         ev,
            })
        return findings
