"""
Microsoft Sentinel SIEM fetcher.
Azure AD client_credentials OAuth2, then Log Analytics KQL incidents query.
"""

import logging

import httpx

from .base import BaseSIEMFetcher

logger = logging.getLogger(__name__)

TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
LA_QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"


class SentinelFetcher(BaseSIEMFetcher):
    siem_type = "sentinel"

    async def fetch(self) -> list[dict]:
        tenant_id = self.extra.get("tenant_id", "")
        workspace_id = self.extra.get("workspace_id", "")
        client_id = self._api_key()      # Azure app client_id stored as api_key
        client_secret = self._secret_key()
        async with httpx.AsyncClient(timeout=60) as client:
            token = await self._get_token(client, tenant_id, client_id, client_secret)
            return await self._query_incidents(client, token, workspace_id)

    async def _get_token(self, client, tenant_id, client_id, client_secret) -> str:
        resp = await client.post(
            TOKEN_URL.format(tenant_id=tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://api.loganalytics.io/.default",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def _query_incidents(self, client, token, workspace_id) -> list[dict]:
        kql = self.extra.get(
            "kql_query",
            "SecurityIncident | where TimeGenerated > ago(24h) "
            "| where Severity in ('High','Critical') "
            "| project IncidentName, Title, Severity, Status, AlertsCount, "
            "          FirstActivityTime, LastModifiedTime, Description "
            "| top 200 by LastModifiedTime desc"
        )
        resp = await client.post(
            LA_QUERY_URL.format(workspace_id=workspace_id),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"query": kql},
        )
        resp.raise_for_status()
        alerts = []
        data = resp.json()
        tables = data.get("tables", [])
        if not tables:
            return alerts
        cols = [c["name"] for c in tables[0].get("columns", [])]
        for row in tables[0].get("rows", []):
            record = dict(zip(cols, row))
            try:
                alerts.append({
                    "plugin_id": f"sentinel:{record.get('IncidentName','')}",
                    "title": record.get("Title", "Sentinel Incident"),
                    "severity": self._sev(record.get("Severity", "medium")),
                    "cvss": None,
                    "cve_id": "",
                    "hostname": "",
                    "ip_address": "",
                    "description": (record.get("Description") or "")[:2000],
                    "solution": "",
                    "raw": {
                        "incident": record.get("IncidentName"),
                        "status": record.get("Status"),
                        "alert_count": record.get("AlertsCount"),
                        "first_activity": record.get("FirstActivityTime"),
                    },
                })
            except Exception as exc:
                logger.debug("Sentinel row parse error: %s", exc)
        return alerts
