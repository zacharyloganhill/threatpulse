"""
IBM QRadar SIEM fetcher.
SEC token header auth, offenses API with pagination.
"""

import logging

import httpx

from .base import BaseSIEMFetcher

logger = logging.getLogger(__name__)


class QRadarFetcher(BaseSIEMFetcher):
    siem_type = "qradar"

    async def fetch(self) -> list[dict]:
        base = self.host_url  # e.g. https://qradar.example.com
        sec_token = self._api_key()
        headers = {
            "SEC": sec_token,
            "Accept": "application/json",
            "Version": "17.0",
        }
        # Severity filter: 5=Critical, 4=High, 3=Medium
        severity_filter = self.extra.get("min_severity", 3)
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            return await self._get_offenses(client, base, headers, severity_filter)

    async def _get_offenses(self, client, base, headers, min_severity) -> list[dict]:
        alerts = []
        start, page_size = 0, 50
        while True:
            resp = await client.get(
                f"{base}/api/siem/offenses",
                headers=headers,
                params={
                    "filter": f"status=OPEN and magnitude>={min_severity}",
                    "fields": "id,description,offense_name,offense_type,severity,"
                              "magnitude,source_address_ids,destination_networks,"
                              "start_time,last_updated_time,category_count",
                    "sort": "-last_updated_time",
                    "Range": f"items={start}-{start+page_size-1}",
                },
            )
            if resp.status_code not in (200, 206):
                break
            batch = resp.json()
            if not batch:
                break
            for offense in batch:
                f = self._normalize(offense)
                if f:
                    alerts.append(f)
            if len(batch) < page_size:
                break
            start += page_size
            if start > 500:
                break
        return alerts

    def _normalize(self, offense: dict) -> dict | None:
        try:
            severity = offense.get("severity", 3)
            # QRadar severity 1-10
            if severity >= 9:
                sev = "CRITICAL"
            elif severity >= 7:
                sev = "HIGH"
            elif severity >= 4:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            return {
                "plugin_id": f"qradar:{offense.get('id','')}",
                "title": offense.get("offense_name") or offense.get("description") or "QRadar Offense",
                "severity": sev,
                "cvss": None,
                "cve_id": "",
                "hostname": "",
                "ip_address": "",
                "description": (offense.get("description") or "")[:2000],
                "solution": "",
                "raw": {
                    "offense_id": offense.get("id"),
                    "magnitude": offense.get("magnitude"),
                    "last_updated": offense.get("last_updated_time"),
                },
            }
        except Exception as exc:
            logger.debug("QRadar normalize error: %s", exc)
            return None
