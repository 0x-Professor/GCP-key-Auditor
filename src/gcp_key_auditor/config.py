from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(slots=True)
class SeverityThresholds:
    critical: int = 70
    high: int = 45
    medium: int = 20


@dataclass(slots=True)
class ScoringWeights:
    accepted_multiplier: float = 1.0
    service_disabled_factor: float = 0.25
    denied_or_quota_points: int = 2
    restricted_penalty: int = 10
    invalid_penalty: int = 4


@dataclass(slots=True)
class AuditorConfig:
    severity_thresholds: SeverityThresholds = field(default_factory=SeverityThresholds)
    scoring_weights: ScoringWeights = field(default_factory=ScoringWeights)
    service_weights: dict[str, int] = field(default_factory=dict)


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_config(config_path: Path | None) -> AuditorConfig:
    config = AuditorConfig()
    if config_path is None or not config_path.exists():
        return config

    data = tomllib.loads(config_path.read_text(encoding="utf-8"))

    thresholds = data.get("severity_thresholds", {})
    if isinstance(thresholds, dict):
        config.severity_thresholds.critical = _to_int(
            thresholds.get("critical"), config.severity_thresholds.critical
        )
        config.severity_thresholds.high = _to_int(
            thresholds.get("high"), config.severity_thresholds.high
        )
        config.severity_thresholds.medium = _to_int(
            thresholds.get("medium"), config.severity_thresholds.medium
        )

    weights = data.get("scoring_weights", {})
    if isinstance(weights, dict):
        config.scoring_weights.accepted_multiplier = _to_float(
            weights.get("accepted_multiplier"),
            config.scoring_weights.accepted_multiplier,
        )
        config.scoring_weights.service_disabled_factor = _to_float(
            weights.get("service_disabled_factor"),
            config.scoring_weights.service_disabled_factor,
        )
        config.scoring_weights.denied_or_quota_points = _to_int(
            weights.get("denied_or_quota_points"),
            config.scoring_weights.denied_or_quota_points,
        )
        config.scoring_weights.restricted_penalty = _to_int(
            weights.get("restricted_penalty"),
            config.scoring_weights.restricted_penalty,
        )
        config.scoring_weights.invalid_penalty = _to_int(
            weights.get("invalid_penalty"),
            config.scoring_weights.invalid_penalty,
        )

    service_weights = data.get("service_weights", {})
    if isinstance(service_weights, dict):
        normalized: dict[str, int] = {}
        for service, value in service_weights.items():
            normalized[str(service)] = max(0, _to_int(value, 0))
        config.service_weights = normalized

    return config
