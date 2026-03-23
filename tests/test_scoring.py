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

    scored = score_key(audit)
    assert scored.score >= 45
    assert scored.severity in {"high", "critical"}
