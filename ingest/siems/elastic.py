"""
Elastic Security SIEM fetcher.
ApiKey auth, detection engine signals/alerts API.
"""

import logging

import httpx

from .base import BaseSIEMFetcher

logger = logging.getLogger(__name__)


class ElasticFetcher(BaseSIEMFetcher):
    siem_type = "elastic"

    async def fetch(self) -> list[dict]:
        base = self.host_url  # e.g. https://elastic:9200
        api_key = self._api_key()
        space = self.extra.get("space", "default")
        headers = {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
        }
        # Use Kibana detection engine alerts endpoint
        kibana_base = self.extra.get("kibana_url", base)
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            return await self._get_alerts(client, kibana_base, headers, space)

    async def _get_alerts(self, client, kibana_base, headers, space) -> list[dict]:
        url = f"{kibana_base}/s/{space}/api/detection_engine/signals/search"
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"signal.status": "open"}},
                        {"range": {"signal.original_time": {"gte": "now-24h"}}},
                        {"terms": {"signal.rule.severity": ["critical", "high", "medium"]}},
                    ]
                }
            },
            "size": 500,
            "_source": [
                "signal.rule.name", "signal.rule.severity", "signal.rule.description",
                "signal.rule.id", "signal.rule.risk_score", "signal.original_event",
                "host.name", "source.ip", "destination.ip",
                "@timestamp",
            ],
        }
        try:
            resp = await client.post(url, headers=headers, json=query)
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [self._normalize(h) for h in hits if self._normalize(h)]
        except Exception as exc:
            logger.error("Elastic alerts query failed: %s", exc)
            # Fallback: index-based query
            return await self._fallback_query(client, kibana_base, headers)

    async def _fallback_query(self, client, kibana_base, headers) -> list[dict]:
        try:
            url = f"{kibana_base}/api/alerts/find"
            resp = await client.get(
                url, headers=headers,
                params={"filter": "alert.attributes.executionStatus.status:active",
                        "per_page": 100},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            results = []
            for alert in data.get("data", []):
                results.append({
                    "plugin_id": f"elastic:{alert.get('id','')}",
                    "title": alert.get("name", "Elastic Alert"),
                    "severity": self._sev(alert.get("tags", ["medium"])[0] if alert.get("tags") else "medium"),
                    "cvss": None, "cve_id": "", "hostname": "", "ip_address": "",
                    "description": alert.get("alertTypeId", "")[:2000],
                    "solution": "", "raw": {"alert_id": alert.get("id")},
                })
            return results
        except Exception:
            return []

    def _normalize(self, hit: dict) -> dict | None:
        try:
            src = hit.get("_source", {})
            signal = src.get("signal", {})
            rule = signal.get("rule", {})
            evt = signal.get("original_event", {})
            severity = rule.get("severity", "medium")
            host = src.get("host", {}).get("name", "")
            src_ip = src.get("source", {}).get("ip", "")
            return {
                "plugin_id": f"elastic:{hit.get('_id','')}",
                "title": rule.get("name", "Elastic Detection"),
                "severity": self._sev(severity),
                "cvss": float(rule.get("risk_score", 0) or 0) / 10 or None,
                "cve_id": "",
                "hostname": host,
                "ip_address": src_ip,
                "description": (rule.get("description") or "")[:2000],
                "solution": "",
                "raw": {
                    "rule_id": rule.get("id"),
                    "risk_score": rule.get("risk_score"),
                    "timestamp": src.get("@timestamp"),
                },
            }
        except Exception as exc:
            logger.debug("Elastic normalize error: %s", exc)
            return None
