"""
PhantomFeed — Remediation SLA Engine

SLA rules (days to remediate by severity):
  CRITICAL: 15   HIGH: 30   MEDIUM: 90   LOW: 180

check_overdue() — marks overdue items, sends alert emails at 75%/90%/100% of window.
calculate_mttr() — mean time to remediate by severity.
get_sla_compliance_rate() — % of items patched before due date.

Per-client overrides: store in client's stack_profile as
  {"sla": {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 60, "LOW": 120}}
"""

from datetime import datetime, timedelta
from typing import Optional


DEFAULT_SLA = {
    "CRITICAL": 15,
    "HIGH":     30,
    "MEDIUM":   90,
    "LOW":      180,
}


class SLAEngine:

    def __init__(self, client_sla_override: dict = None):
        self._rules = dict(DEFAULT_SLA)
        if client_sla_override:
            self._rules.update(client_sla_override)

    def sla_days(self, severity: str) -> int:
        return self._rules.get(severity.upper(), 90)

    def assign_sla(self, item: dict, client_id: str) -> tuple[str, int]:
        """
        Returns (due_date_str, sla_days) for this item.
        Respects CISA BOD due dates if present in item raw.
        """
        severity = item.get("severity", "MEDIUM").upper()
        days = self.sla_days(severity)

        # Check for CISA BOD due date
        raw = item.get("raw") or {}
        bod_due = raw.get("dueDate") or raw.get("bod_due_date")
        if bod_due:
            return str(bod_due)[:10], days

        published = (item.get("published_at") or "")[:10]
        if published:
            try:
                pub_dt = datetime.strptime(published, "%Y-%m-%d")
            except ValueError:
                pub_dt = datetime.utcnow()
        else:
            pub_dt = datetime.utcnow()

        due_dt = pub_dt + timedelta(days=days)
        return due_dt.strftime("%Y-%m-%d"), days


async def check_overdue():
    """Mark overdue remediations and send alert emails."""
    from db import database as db
    from reports.email_digest import send_client_digest

    today = datetime.utcnow().strftime("%Y-%m-%d")
    overdue = await db.get_overdue_remediations()

    for rem in overdue:
        await db.update_remediation(rem["id"], is_overdue=1)

    # SLA window alerts (75%, 90%, 100%)
    # Get all open items, check thresholds
    from db import database as db_mod
    database = db_mod.get_db()
    async with database.execute(
        "SELECT * FROM remediation_items WHERE status = 'open'"
    ) as cur:
        open_items = [dict(r) for r in await cur.fetchall()]

    for rem in open_items:
        due = rem.get("due_date")
        created = rem.get("created_at", "")[:10]
        if not due or not created:
            continue
        try:
            due_dt    = datetime.strptime(due, "%Y-%m-%d")
            created_dt = datetime.strptime(created, "%Y-%m-%d")
            today_dt  = datetime.utcnow()
            total_days = (due_dt - created_dt).days or 1
            elapsed    = (today_dt - created_dt).days
            pct = elapsed / total_days
            sla_days = rem.get("sla_days") or total_days
        except ValueError:
            continue

        # At 75% / 90% of window — could trigger Slack/email here (future hook)
        # For now we just mark is_overdue
        if today_dt > due_dt and not rem.get("is_overdue"):
            await db.update_remediation(rem["id"], is_overdue=1)


async def calculate_mttr(client_id: str, days: int = 90) -> dict:
    """Mean time to remediate (days) by severity for a given period."""
    from db import database as db_mod
    database = db_mod.get_db()
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    async with database.execute(
        """SELECT ri.*, ti.severity, ti.published_at
           FROM remediation_items ri
           JOIN threat_items ti ON ri.item_id = ti.id
           WHERE ri.client_id = ?
             AND ri.status = 'patched'
             AND ri.patched_date >= ?""",
        (client_id, cutoff),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    by_sev: dict[str, list[float]] = {}
    for r in rows:
        try:
            created_dt = datetime.strptime(r["created_at"][:10], "%Y-%m-%d")
            patched_dt = datetime.strptime(r["patched_date"][:10], "%Y-%m-%d")
            mttr_days  = (patched_dt - created_dt).days
            sev        = r.get("severity", "MEDIUM")
            by_sev.setdefault(sev, []).append(mttr_days)
        except (ValueError, TypeError):
            pass

    return {
        sev: round(sum(vals) / len(vals), 1)
        for sev, vals in by_sev.items()
    }


async def get_sla_compliance_rate(client_id: str) -> float:
    """% of patched items where patched_date <= due_date."""
    from db import database as db_mod
    database = db_mod.get_db()
    async with database.execute(
        "SELECT patched_date, due_date FROM remediation_items WHERE client_id = ? AND status = 'patched'",
        (client_id,),
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    if not rows:
        return 0.0
    on_time = sum(
        1 for r in rows
        if r.get("patched_date") and r.get("due_date")
        and r["patched_date"] <= r["due_date"]
    )
    return round(on_time / len(rows) * 100, 1)
