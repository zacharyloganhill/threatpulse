"""
PhantomFeed — Breach Cost & ROI Calculator

Based on IBM Cost of a Data Breach Report 2024 and Ponemon Institute models.
Calculates expected loss per threat item and total portfolio exposure.

Key 2024 benchmarks used:
  - Global average breach cost: $4.88M
  - Healthcare: $9.77M
  - Finance: $6.08M
  - Technology: $5.10M
  - Retail/Hospitality: $3.75M
  - Energy: $4.72M
  - Government: $2.60M
  - Education: $3.58M
  Ransomware multiplier: 2.3x average
  Mega breach (>1M records): $332M average
  MTTR reduction value: $1.12M saved per 100-day MTTR reduction
  MFA reduces breach cost by avg 33%
  IR team reduces cost by avg 58%
"""

# IBM 2024 average breach cost by industry (in USD)
INDUSTRY_BREACH_COSTS = {
    "Healthcare":       9_770_000,
    "Finance":          6_080_000,
    "Technology":       5_100_000,
    "Energy":           4_720_000,
    "Retail":           3_750_000,
    "Manufacturing":    4_200_000,
    "Government":       2_600_000,
    "Education":        3_580_000,
    "Legal":            4_900_000,
    "Transportation":   3_700_000,
}

DEFAULT_BREACH_COST = 4_880_000  # Global average 2024

# Severity multipliers on probability and cost impact
SEVERITY_PROBABILITY = {
    "CRITICAL": 0.45,   # ~45% chance a critical CVE leads to incident
    "HIGH":     0.25,
    "MEDIUM":   0.10,
    "LOW":      0.03,
    "INFO":     0.01,
}

SEVERITY_COST_FRACTION = {
    "CRITICAL": 0.85,   # exploited critical = near-full breach cost
    "HIGH":     0.45,
    "MEDIUM":   0.20,
    "LOW":      0.05,
    "INFO":     0.01,
}

CATEGORY_MULTIPLIERS = {
    "kev": 1.8,         # CISA KEV = actively exploited, higher probability
    "ransomware": 2.3,  # IBM ransomware multiplier
    "threat": 1.2,
    "cve": 1.0,
    "advisory": 0.8,
    "supply_chain": 1.4,
}

# EPSS-derived adjustments (if EPSS score available)
# EPSS > 0.5 → multiply probability by 2
# EPSS > 0.9 → multiply by 3


def calculate_item_loss(item: dict, industry: str = "Technology") -> dict:
    """
    Calculate expected financial loss for a single threat item.
    Returns expected_loss, remediation_cost, risk_reduction.
    """
    base_cost = INDUSTRY_BREACH_COSTS.get(industry, DEFAULT_BREACH_COST)
    severity = item.get("severity", "MEDIUM")
    category = item.get("category", "cve")

    probability = SEVERITY_PROBABILITY.get(severity, 0.10)
    cost_fraction = SEVERITY_COST_FRACTION.get(severity, 0.20)
    cat_multiplier = CATEGORY_MULTIPLIERS.get(category, 1.0)

    # EPSS adjustment
    epss = item.get("epss_score") or 0
    if epss > 0.9:
        probability = min(0.95, probability * 3)
    elif epss > 0.5:
        probability = min(0.90, probability * 2)

    expected_loss = round(base_cost * probability * cost_fraction * cat_multiplier)

    # Remediation cost estimate (based on severity)
    rem_cost_map = {"CRITICAL": 15000, "HIGH": 8000, "MEDIUM": 3000, "LOW": 500, "INFO": 100}
    remediation_cost = rem_cost_map.get(severity, 3000)

    # Risk reduction value = expected_loss - remediation_cost (ROI of patching)
    risk_reduction = max(0, expected_loss - remediation_cost)
    roi_ratio = round(expected_loss / max(1, remediation_cost), 1)

    return {
        "expected_loss": expected_loss,
        "remediation_cost": remediation_cost,
        "risk_reduction": risk_reduction,
        "roi_ratio": roi_ratio,
        "probability": round(probability * 100, 1),
        "industry": industry,
    }


def calculate_portfolio_roi(items: list, remediations: list, industry: str = "Technology") -> dict:
    """
    Calculate total portfolio financial exposure and patching ROI.
    """
    base_cost = INDUSTRY_BREACH_COSTS.get(industry, DEFAULT_BREACH_COST)

    total_expected_loss = 0
    total_remediation_cost = 0
    patched_loss_avoided = 0
    unpatched_exposure = 0

    patched_ids = {r.get("item_id") for r in remediations if r.get("status") in ("patched", "mitigated", "accepted")}
    open_items = {r.get("item_id") for r in remediations if r.get("status") not in ("patched", "mitigated", "accepted")}

    by_severity: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    top_items = []

    for item in items:
        calc = calculate_item_loss(item, industry)
        loss = calc["expected_loss"]
        rem_cost = calc["remediation_cost"]
        total_expected_loss += loss
        total_remediation_cost += rem_cost

        sev = item.get("severity", "MEDIUM")
        by_severity[sev] = by_severity.get(sev, 0) + loss

        if item.get("id") in patched_ids:
            patched_loss_avoided += loss
        else:
            unpatched_exposure += loss

        if loss > 0:
            top_items.append({
                "id": item.get("id"),
                "title": item.get("title", "")[:80],
                "severity": sev,
                "expected_loss": loss,
                "remediation_cost": rem_cost,
                "roi_ratio": calc["roi_ratio"],
                "is_patched": item.get("id") in patched_ids,
            })

    top_items.sort(key=lambda x: x["expected_loss"], reverse=True)

    total_rem_cost = sum(calculate_item_loss(i, industry)["remediation_cost"]
                         for i in items if i.get("id") not in patched_ids)

    portfolio_roi = round(unpatched_exposure / max(1, total_rem_cost), 1) if total_rem_cost > 0 else 0
    annual_risk_reduction = round(patched_loss_avoided * 0.7)  # 70% realized once patched

    return {
        "industry": industry,
        "total_expected_loss": total_expected_loss,
        "unpatched_exposure": unpatched_exposure,
        "patched_loss_avoided": patched_loss_avoided,
        "total_remediation_cost": total_rem_cost,
        "portfolio_roi": portfolio_roi,
        "annual_risk_reduction": annual_risk_reduction,
        "loss_by_severity": by_severity,
        "ibm_baseline_cost": base_cost,
        "top_items": top_items[:20],
        "total_items_analyzed": len(items),
    }


async def get_client_risk_portfolio(client_id: str) -> dict:
    """Full risk portfolio calculation for a client."""
    from db import database as db

    client = await db.get_client(client_id)
    if not client:
        return {"error": "Client not found"}

    stack = client.get("stack_profile") or {}
    industry = client.get("industry") or stack.get("industry") or "Technology"

    items = await db.get_items(limit=500, sort="risk", client_id=client_id)
    if not items:
        items = await db.get_items(limit=200, sort="risk")

    remediations = await db.get_remediations(client_id)

    portfolio = calculate_portfolio_roi(items, remediations, industry)
    portfolio["client_id"] = client_id
    portfolio["client_name"] = client.get("name")

    # Persist expected_loss on individual items (batch update)
    try:
        db_conn = db.get_db()
        for item in items[:100]:
            calc = calculate_item_loss(item, industry)
            if calc["expected_loss"] != item.get("expected_loss"):
                await db_conn.execute(
                    "UPDATE threat_items SET expected_loss = ?, remediation_cost = ? WHERE id = ?",
                    (calc["expected_loss"], calc["remediation_cost"], item["id"]),
                )
        await db_conn.commit()
    except Exception:
        pass

    return portfolio
