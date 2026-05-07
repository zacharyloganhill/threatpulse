"""
Splunk SIEM fetcher.
Session key auth via /services/auth/login, then saved-search job polling.
"""

import asyncio
import logging
from xml.etree import ElementTree as ET

import httpx

from .base import BaseSIEMFetcher

logger = logging.getLogger(__name__)


class SplunkFetcher(BaseSIEMFetcher):
    siem_type = "splunk"

    async def fetch(self) -> list[dict]:
        base = self.host_url  # e.g. https://splunk:8089
        username = self._username()
        password = self._password()
        search_query = self.extra.get(
            "search_query",
            "search index=main severity=critical OR severity=high earliest=-24h | head 200"
        )
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            session_key = await self._login(client, base, username, password)
            headers = {"Authorization": f"Splunk {session_key}"}
            job_id = await self._create_job(client, base, headers, search_query)
            await self._wait_for_job(client, base, headers, job_id)
            return await self._get_results(client, base, headers, job_id)

    async def _login(self, client, base, username, password) -> str:
        resp = await client.post(
            f"{base}/services/auth/login",
            data={"username": username, "password": password},
        )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text)
        ns = {"s": "http://dev.splunk.com/ns/rest"}
        key_el = tree.find(".//s:key[@name='sessionKey']", ns)
        if key_el is None:
            key_el = tree.find(".//{http://dev.splunk.com/ns/rest}key")
        return key_el.text if key_el is not None else ""

    async def _create_job(self, client, base, headers, search) -> str:
        resp = await client.post(
            f"{base}/services/search/jobs",
            headers=headers,
            data={"search": search, "output_mode": "json"},
        )
        resp.raise_for_status()
        return resp.json().get("sid", "")

    async def _wait_for_job(self, client, base, headers, job_id):
        for _ in range(30):
            resp = await client.get(
                f"{base}/services/search/jobs/{job_id}",
                headers=headers,
                params={"output_mode": "json"},
            )
            entry = resp.json().get("entry", [{}])[0]
            state = entry.get("content", {}).get("dispatchState", "")
            if state == "DONE":
                return
            await asyncio.sleep(2)

    async def _get_results(self, client, base, headers, job_id) -> list[dict]:
        resp = await client.get(
            f"{base}/services/search/jobs/{job_id}/results",
            headers=headers,
            params={"output_mode": "json", "count": 500},
        )
        resp.raise_for_status()
        alerts = []
        for result in resp.json().get("results", []):
            try:
                severity = result.get("severity") or result.get("urgency") or "medium"
                alerts.append({
                    "plugin_id": f"splunk:{result.get('_serial','')}{result.get('_time','')}",
                    "title": result.get("search_name") or result.get("message") or "Splunk Alert",
                    "severity": self._sev(severity),
                    "cvss": None,
                    "cve_id": result.get("cve_id", ""),
                    "hostname": result.get("host", ""),
                    "ip_address": result.get("src_ip") or result.get("dest_ip", ""),
                    "description": str(result)[:2000],
                    "solution": "",
                    "raw": {k: result.get(k) for k in ("_time", "source", "sourcetype", "host")},
                })
            except Exception as exc:
                logger.debug("Splunk result parse error: %s", exc)
        return alerts
