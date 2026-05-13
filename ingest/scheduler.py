"""
ThreatPulse — Ingestion Scheduler
Runs all fetchers on configurable intervals using APScheduler.
Also exposes a manual trigger for immediate on-demand polling.
"""

import asyncio
from datetime import datetime
from typing import Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from rich.console import Console

import config
from ingest.nvd import NVDFetcher
from ingest.cisa import CISAKEVFetcher, CISAAdvisoriesFetcher, CISAICSFetcher
from ingest.rss_feeds import build_all_vendor_fetchers
from ingest.threat_intel import URLHausFetcher, OTXFetcher, NPMAdvisoryFetcher, PyPIAdvisoryFetcher
from ingest.abuse_feeds import ThreatFoxFetcher, FeodoTrackerFetcher, MalwareBazaarFetcher
from ingest.free_feeds import (
    EPSSFetcher, VulnCheckKEVFetcher, CIRCLCVEFetcher,
    GitHubAdvisoryGoFetcher, GitHubAdvisoryRustFetcher,
    GitHubAdvisoryMavenFetcher, GitHubAdvisoryNugetFetcher,
)
from ingest.taxii_feeds import build_taxii_fetchers

console = Console()
scheduler: Optional[AsyncIOScheduler] = None

# Registry: feed_id → fetcher instance
_fetchers: dict = {}


def _build_fetchers() -> dict:
    fetchers = {}

    # Core feeds
    for f in [
        NVDFetcher(lookback_hours=26),  # slightly more than poll interval to avoid gaps
        CISAKEVFetcher(),
        CISAAdvisoriesFetcher(),
        CISAICSFetcher(),
        URLHausFetcher(),
        OTXFetcher(),
        # abuse.ch feeds
        ThreatFoxFetcher(),
        FeodoTrackerFetcher(),
        MalwareBazaarFetcher(),
        # free enrichment feeds
        EPSSFetcher(),
        VulnCheckKEVFetcher(),
        CIRCLCVEFetcher(),
        # supply chain
        NPMAdvisoryFetcher(),
        PyPIAdvisoryFetcher(),
        GitHubAdvisoryGoFetcher(),
        GitHubAdvisoryRustFetcher(),
        GitHubAdvisoryMavenFetcher(),
        GitHubAdvisoryNugetFetcher(),
    ]:
        fetchers[f.feed_id] = f

    # Vendor RSS feeds
    for f in build_all_vendor_fetchers():
        fetchers[f.feed_id] = f

    # TAXII 2.1 feeds
    for f in build_taxii_fetchers():
        fetchers[f.feed_id] = f

    return fetchers


async def _run_fetcher(feed_id: str):
    fetcher = _fetchers.get(feed_id)
    if not fetcher:
        console.print(f"[red]No fetcher found for feed_id={feed_id}[/]")
        return
    try:
        await fetcher.run()
    except Exception as e:
        console.print(f"[red]Scheduler error for {feed_id}: {e}[/]")


async def run_all() -> dict:
    """Run all fetchers immediately and return counts."""
    results = {}
    for feed_id, fetcher in _fetchers.items():
        try:
            count = await fetcher.run()
            results[feed_id] = count
        except Exception as e:
            console.print(f"[red]Error running {feed_id}: {e}[/]")
            results[feed_id] = -1
    return results


async def run_feed(feed_id: str) -> int:
    """Run a single fetcher by ID. Used by API for on-demand refresh."""
    fetcher = _fetchers.get(feed_id)
    if not fetcher:
        return -1
    return await fetcher.run()


def get_feed_ids() -> list[str]:
    return list(_fetchers.keys())


def get_feed_health() -> list[dict]:
    """Return in-memory health state for every registered feed."""
    return [f.get_health() for f in _fetchers.values()]


def start_scheduler():
    global scheduler, _fetchers
    _fetchers = _build_fetchers()
    scheduler = AsyncIOScheduler()

    # Group fetchers by interval
    fast_feeds = [f for f in _fetchers.values() if f.poll_interval <= config.POLL_FAST]
    slow_feeds = [f for f in _fetchers.values() if f.poll_interval > config.POLL_FAST]

    # Fast polling group (KEV, NVD, URLhaus)
    for fetcher in fast_feeds:
        scheduler.add_job(
            _run_fetcher,
            trigger=IntervalTrigger(minutes=fetcher.poll_interval),
            args=[fetcher.feed_id],
            id=f"poll_{fetcher.feed_id}",
            name=fetcher.feed_label,
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=60,
        )

    # Slow polling group (vendor RSS, threat intel)
    for fetcher in slow_feeds:
        scheduler.add_job(
            _run_fetcher,
            trigger=IntervalTrigger(minutes=fetcher.poll_interval),
            args=[fetcher.feed_id],
            id=f"poll_{fetcher.feed_id}",
            name=fetcher.feed_label,
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=300,
        )

    # Daily cleanup job
    from db import database as db
    scheduler.add_job(
        db.purge_old_items,
        trigger=IntervalTrigger(hours=24),
        id="purge_old",
        name="Purge old items",
        replace_existing=True,
    )

    from apscheduler.triggers.cron import CronTrigger

    # Daily SLA overdue check — 7am UTC
    from reports.sla_engine import check_overdue
    scheduler.add_job(
        check_overdue,
        trigger=CronTrigger(hour=7, minute=0),
        id="sla_overdue",
        name="SLA Overdue Check",
        replace_existing=True,
    )

    # Weekly email digest — every Monday at 08:00 UTC
    scheduler.add_job(
        _send_weekly_digests,
        trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
        id="weekly_digest",
        name="Weekly Email Digest",
        replace_existing=True,
    )

    # Hourly temp file cleanup
    async def _cleanup_temp():
        from api.upload_routes import _cleanup_old_temp
        await _cleanup_old_temp()

    scheduler.add_job(
        _cleanup_temp,
        trigger=IntervalTrigger(hours=1),
        id="temp_cleanup",
        name="Upload Temp Cleanup",
        replace_existing=True,
    )

    # Dark web monitors — every 30 minutes
    from ingest.darkweb import run_all_darkweb_monitors
    scheduler.add_job(
        run_all_darkweb_monitors,
        trigger=IntervalTrigger(minutes=30),
        id="darkweb_monitor",
        name="Dark Web Monitor",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=300,
    )

    # MISP pull — every 6 hours (if configured)
    from ingest.misp_connector import pull_misp_events
    scheduler.add_job(
        pull_misp_events,
        trigger=IntervalTrigger(hours=6),
        id="misp_pull",
        name="MISP Event Pull",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=600,
    )

    # FedRAMP KSI validation — every 6 hours
    from api.ksi_routes import run_all_ksi_validations
    scheduler.add_job(
        run_all_ksi_validations,
        trigger=IntervalTrigger(hours=6),
        id="ksi_validation",
        name="FedRAMP KSI Validation",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=600,
    )

    # FedRAMP scanner polls — every hour, pick up configs from DB
    scheduler.add_job(
        _poll_all_scanners_and_siems,
        trigger=IntervalTrigger(hours=1),
        id="fedramp_scanner_poll",
        name="FedRAMP Scanner/SIEM Poll",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=300,
    )

    # Integration status indicators — every 5 minutes
    from api.integration_routes import update_all_integration_statuses
    scheduler.add_job(
        update_all_integration_statuses,
        trigger=IntervalTrigger(minutes=5),
        id="integration_status_check",
        name="Integration Status Check",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )

    scheduler.start()
    console.print(
        f"[green]✓ Scheduler started[/] — "
        f"{len(fast_feeds)} fast feeds (every {config.POLL_FAST}m), "
        f"{len(slow_feeds)} slow feeds (every {config.POLL_SLOW}m)"
    )


async def _poll_all_scanners_and_siems():
    """Hourly job: poll any scanner/SIEM whose interval has elapsed."""
    from datetime import timezone
    from db import database as _db
    from api.scanner_routes import _run_scanner
    from api.siem_routes import _run_siem
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        for scanner in await _db.get_all_active_scanner_configs():
            last = scanner.get("last_polled")
            interval_h = scanner.get("poll_interval_hours", 6)
            if last:
                try:
                    elapsed = (now - datetime.fromisoformat(last)).total_seconds() / 3600
                    if elapsed < interval_h:
                        continue
                except ValueError:
                    pass
            await _run_scanner(scanner)
    except Exception as exc:
        console.print(f"[red]Scanner poll error: {exc}[/]")
    try:
        for siem in await _db.get_all_active_siem_configs():
            last = siem.get("last_polled")
            interval_h = siem.get("poll_interval_hours", 6)
            if last:
                try:
                    elapsed = (now - datetime.fromisoformat(last)).total_seconds() / 3600
                    if elapsed < interval_h:
                        continue
                except ValueError:
                    pass
            await _run_siem(siem)
    except Exception as exc:
        console.print(f"[red]SIEM poll error: {exc}[/]")


async def _send_weekly_digests():
    """Send weekly email digests to all clients with a contact_email."""
    from db import database as db
    from reports.email_digest import send_client_digest
    from ingest.risk_score import score_item

    clients = await db.get_clients()
    items = await db.get_items(limit=500, sort="risk")
    for client in clients:
        if not client.get("contact_email"):
            continue
        result = await send_client_digest(client, items, days=7)
        console.print(f"[cyan]Digest → {client['name']}: {result.get('status')}[/]")


def stop_scheduler():
    global scheduler
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)
        scheduler = None
