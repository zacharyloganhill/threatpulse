"""Base class for all SIEM fetchers."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime

import db.database as db
from security.encryption import decrypt

logger = logging.getLogger(__name__)


class BaseSIEMFetcher(ABC):
    siem_type: str = ""

    def __init__(self, config: dict):
        self.config = config
        self.siem_id = config["id"]
        self.client_id = config["client_id"]
        self.host_url = config.get("host_url", "").rstrip("/")
        self.extra = config.get("extra_config", {})

    def _api_key(self) -> str:
        return decrypt(self.config.get("api_key_enc", ""))

    def _secret_key(self) -> str:
        return decrypt(self.config.get("secret_key_enc", ""))

    def _username(self) -> str:
        return decrypt(self.config.get("username_enc", ""))

    def _password(self) -> str:
        return decrypt(self.config.get("password_enc", ""))

    @abstractmethod
    async def fetch(self) -> list[dict]:
        """Return list of normalized alert dicts."""

    async def run(self) -> int:
        now = datetime.utcnow().isoformat()
        try:
            alerts = await self.fetch()
            new_count = 0
            for alert in alerts:
                alert["client_id"] = self.client_id
                alert["scanner_id"] = self.siem_id
                alert["scanner_type"] = f"siem:{self.siem_type}"
                if await db.upsert_scan_finding(alert):
                    new_count += 1
            await db.update_siem_config(
                self.siem_id,
                last_polled=now,
                last_status=f"ok:{len(alerts)} alerts ({new_count} new)",
            )
            await db.add_pull_record(
                self.siem_id, "siem", self.client_id, "ok",
                finding_count=len(alerts),
            )
            logger.info("%s SIEM %s: %d alerts, %d new",
                        self.siem_type, self.siem_id, len(alerts), new_count)
            return new_count
        except Exception as exc:
            logger.error("%s SIEM %s failed: %s", self.siem_type, self.siem_id, exc)
            await db.update_siem_config(
                self.siem_id,
                last_polled=now,
                last_status=f"error:{exc}",
            )
            await db.add_pull_record(
                self.siem_id, "siem", self.client_id, "error",
                error_message=str(exc)[:500],
            )
            return 0

    @staticmethod
    def _sev(label: str) -> str:
        label = (label or "").lower()
        if label in ("critical", "5", "high", "4"):
            return "CRITICAL" if label in ("critical", "5") else "HIGH"
        if label in ("medium", "3"):
            return "MEDIUM"
        if label in ("low", "2", "informational", "1", "info"):
            return "LOW"
        return "INFO"
