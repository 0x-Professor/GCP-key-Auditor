from gcp_key_auditor.config import AuditorConfig
from gcp_key_auditor.models import KeyAudit, ProbeResult
from gcp_key_auditor.scoring import score_key


def test_score_key_acceptance_yields_high_or_critical() -> None:
    audit = KeyAudit(key="AIza" + "A" * 35)
    audit.probe_results = [
        ProbeResult(
            service="maps_places_nearby",
            endpoint="https://example",
            method="POST",
            success=True,
            auth_signal="accepted",
            impact_weight=25,
            http_status=200,
            service_status="OK",
            evidence="success",
            latency_ms=10,
        ),
        ProbeResult(
            service="maps_geolocation",
            endpoint="https://example",
            method="POST",
            success=True,
            auth_signal="accepted",
            impact_weight=25,
            http_status=200,
            service_status="OK",
            evidence="success",
            latency_ms=10,
        ),
    ]

    scored = score_key(audit, AuditorConfig())
    assert scored.score >= 45
    assert scored.severity in {"high", "critical"}


def test_custom_thresholds_change_severity() -> None:
    config = AuditorConfig()
    config.severity_thresholds.critical = 90
    config.severity_thresholds.high = 60
    config.severity_thresholds.medium = 30

    audit = KeyAudit(key="AIza" + "A" * 35)
    audit.probe_results = [
        ProbeResult(
            service="maps_geolocation",
            endpoint="https://example",
            method="POST",
            success=True,
            auth_signal="accepted",
            impact_weight=35,
            http_status=200,
            service_status="OK",
            evidence="success",
            latency_ms=10,
        )
    ]

    scored = score_key(audit, config)
    assert scored.score == 35
    assert scored.severity == "medium"
