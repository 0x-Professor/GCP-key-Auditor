from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ProbeResult:
    service: str
    endpoint: str
    method: str
    success: bool
    auth_signal: str
    impact_weight: int
    http_status: int | None
    service_status: str | None
    evidence: str
    latency_ms: float | None = None


@dataclass(slots=True)
class KeyAudit:
    key: str
    source_paths: list[str] = field(default_factory=list)
    probe_results: list[ProbeResult] = field(default_factory=list)
    score: int = 0
    severity: str = "info"
    summary: str = ""


@dataclass(slots=True)
class AuditReport:
    target: str
    created_at: str
    version: str
    findings: list[KeyAudit]
    total_keys: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "created_at": self.created_at,
            "version": self.version,
            "total_keys": self.total_keys,
            "findings": [
                {
                    **asdict(finding),
                    "probe_results": [asdict(result) for result in finding.probe_results],
                }
                for finding in self.findings
            ],
        }


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
