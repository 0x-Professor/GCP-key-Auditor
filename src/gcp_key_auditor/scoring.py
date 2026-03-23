from __future__ import annotations

from gcp_key_auditor.models import KeyAudit


def _severity_for_score(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_key(audit: KeyAudit) -> KeyAudit:
    score = 0

    accepted = [r for r in audit.probe_results if r.auth_signal == "accepted"]
    service_disabled = [r for r in audit.probe_results if r.auth_signal == "valid_key_service_disabled"]
    restricted = [r for r in audit.probe_results if r.auth_signal == "restricted"]
    denied_or_quota = [r for r in audit.probe_results if r.auth_signal == "denied_or_quota"]

    score += sum(r.impact_weight for r in accepted)
    score += sum(max(4, r.impact_weight // 4) for r in service_disabled)
    score += sum(2 for _ in denied_or_quota)

    # Restriction evidence lowers practical exploitation risk.
    score -= 10 if restricted else 0

    # Keep score in a stable range.
    score = max(0, min(100, score))

    audit.score = score
    audit.severity = _severity_for_score(score)

    if accepted:
        top = sorted(accepted, key=lambda x: x.impact_weight, reverse=True)[:3]
        services = ", ".join(r.service for r in top)
        audit.summary = f"Key accepted by {len(accepted)} service(s), including: {services}."
    elif service_disabled:
        audit.summary = (
            "Key appears valid but target service(s) were disabled or blocked at project level."
        )
    elif restricted:
        audit.summary = "Key appears restricted by referrer/IP/app constraints."
    else:
        audit.summary = "No strong evidence of usable key access from tested probes."

    return audit
