from __future__ import annotations

from gcp_key_auditor.config import AuditorConfig
from gcp_key_auditor.models import KeyAudit


def _severity_for_score(score: int, config: AuditorConfig) -> str:
    if score >= config.severity_thresholds.critical:
        return "critical"
    if score >= config.severity_thresholds.high:
        return "high"
    if score >= config.severity_thresholds.medium:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def score_key(audit: KeyAudit, config: AuditorConfig) -> KeyAudit:
    score = 0

    accepted = [r for r in audit.probe_results if r.auth_signal == "accepted"]
    service_disabled = [r for r in audit.probe_results if r.auth_signal == "valid_key_service_disabled"]
    restricted = [r for r in audit.probe_results if r.auth_signal == "restricted"]
    denied_or_quota = [r for r in audit.probe_results if r.auth_signal == "denied_or_quota"]
    invalid = [r for r in audit.probe_results if r.auth_signal == "invalid"]

    score += int(
        sum(r.impact_weight for r in accepted) * config.scoring_weights.accepted_multiplier
    )
    score += int(
        sum(r.impact_weight * config.scoring_weights.service_disabled_factor for r in service_disabled)
    )
    score += config.scoring_weights.denied_or_quota_points * len(denied_or_quota)

    # Restriction evidence lowers practical exploitation risk.
    score -= config.scoring_weights.restricted_penalty if restricted else 0
    score -= config.scoring_weights.invalid_penalty * len(invalid)

    # Keep score in a stable range.
    score = max(0, min(100, score))

    audit.score = score
    audit.severity = _severity_for_score(score, config)

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
