"""Base class for all scanner fetchers."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime

import db.database as db
from security.encryption import decrypt


logger = logging.getLogger(__name__)


class BaseScannerFetcher(ABC):
    scanner_type: str = ""

    def __init__(self, config: dict):
        self.config = config
        self.scanner_id = config["id"]
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
        """Return list of normalized finding dicts."""

    async def run(self) -> int:
        """Fetch findings, upsert, update last_polled/last_status. Returns new finding count."""
        now = datetime.utcnow().isoformat()
        try:
            findings = await self.fetch()
            new_count = 0
            asset_ids: set = set()
            for f in findings:
                f["client_id"] = self.client_id
                f["scanner_id"] = self.scanner_id
                f["scanner_type"] = self.scanner_type
                if await db.upsert_scan_finding(f):
                    new_count += 1
                if f.get("hostname") or f.get("ip_address"):
                    asset_ids.add(f.get("hostname") or f.get("ip_address"))
            await db.update_scanner_config(
                self.scanner_id,
                last_polled=now,
                last_status=f"ok:{len(findings)} findings ({new_count} new)",
            )
            await db.add_pull_record(
                self.scanner_id, "scanner", self.client_id, "ok",
                finding_count=len(findings), asset_count=len(asset_ids),
            )
            logger.info("%s scanner %s: %d findings, %d new",
                        self.scanner_type, self.scanner_id, len(findings), new_count)
            return new_count
        except Exception as exc:
            logger.error("%s scanner %s failed: %s", self.scanner_type, self.scanner_id, exc)
            await db.update_scanner_config(
                self.scanner_id,
                last_polled=now,
                last_status=f"error:{exc}",
            )
            await db.add_pull_record(
                self.scanner_id, "scanner", self.client_id, "error",
                error_message=str(exc)[:500],
            )
            return 0

    @staticmethod
    def _sev(cvss: float) -> str:
        if cvss is None:
            return "INFO"
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        if cvss > 0:
            return "LOW"
        return "INFO"
