from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import httpx

from gcp_key_auditor.models import ProbeResult


@dataclass(slots=True)
class ProbeDefinition:
    service: str
    endpoint: str
    method: str
    impact_weight: int
    request_kind: str


PROBE_DEFINITIONS: list[ProbeDefinition] = [
    ProbeDefinition(
        service="maps_geocoding",
        endpoint="https://maps.googleapis.com/maps/api/geocode/json",
        method="GET",
        impact_weight=20,
        request_kind="maps_geocode",
    ),
    ProbeDefinition(
        service="maps_timezone",
        endpoint="https://maps.googleapis.com/maps/api/timezone/json",
        method="GET",
        impact_weight=15,
        request_kind="maps_timezone",
    ),
    ProbeDefinition(
        service="maps_elevation",
        endpoint="https://maps.googleapis.com/maps/api/elevation/json",
        method="GET",
        impact_weight=15,
        request_kind="maps_elevation",
    ),
    ProbeDefinition(
        service="maps_places_nearby",
        endpoint="https://places.googleapis.com/v1/places:searchNearby",
        method="POST",
        impact_weight=25,
        request_kind="places_nearby",
    ),
    ProbeDefinition(
        service="maps_geolocation",
        endpoint="https://www.googleapis.com/geolocation/v1/geolocate",
        method="POST",
        impact_weight=25,
        request_kind="geolocation",
    ),
    ProbeDefinition(
        service="cloud_translation",
        endpoint="https://translation.googleapis.com/language/translate/v2",
        method="POST",
        impact_weight=20,
        request_kind="translation",
    ),
    ProbeDefinition(
        service="cloud_natural_language",
        endpoint="https://language.googleapis.com/v1/documents:analyzeSentiment",
        method="POST",
        impact_weight=20,
        request_kind="natural_language",
    ),
    ProbeDefinition(
        service="cloud_vision",
        endpoint="https://vision.googleapis.com/v1/images:annotate",
        method="POST",
        impact_weight=25,
        request_kind="vision",
    ),
    ProbeDefinition(
        service="cloud_text_to_speech",
        endpoint="https://texttospeech.googleapis.com/v1/voices",
        method="GET",
        impact_weight=15,
        request_kind="text_to_speech",
    ),
]


class RateLimiter:
    def __init__(self, rate_per_sec: float | None) -> None:
        self.rate_per_sec = rate_per_sec
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if not self.rate_per_sec or self.rate_per_sec <= 0:
            return

        min_interval = 1.0 / self.rate_per_sec
        with self._lock:
            now = time.perf_counter()
            if now < self._next_allowed:
                sleep_for = self._next_allowed - now
                time.sleep(sleep_for)
                now = self._next_allowed
            self._next_allowed = now + min_interval


def _pick(d: dict[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        value = d.get(key)
        if isinstance(value, str) and value:
            return value
    return default


def _extract_error_text(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        msg = _pick(error, ["message", "status"], default="")
        if msg:
            return msg

    return _pick(payload, ["error_message", "errorMessage", "status"], default="")


def _auth_signal(http_status: int | None, service_status: str | None, message: str) -> str:
    msg = (message or "").lower()
    status = (service_status or "").upper()

    if http_status == 200 and status in {"OK", ""}:
        return "accepted"

    restricted_hints = (
        "referer",
        "referrer",
        "ip address",
        "android",
        "ios",
        "bundle",
        "api key not allowed",
    )
    if any(hint in msg for hint in restricted_hints):
        return "restricted"

    if "api has not been used" in msg or "is not enabled" in msg:
        return "valid_key_service_disabled"

    if "invalid api key" in msg or "api key is invalid" in msg:
        return "invalid"

    if status in {"REQUEST_DENIED", "OVER_DAILY_LIMIT", "OVER_QUERY_LIMIT"}:
        # These can still indicate a real key that hit auth/billing/quota boundaries.
        return "denied_or_quota"

    if http_status and http_status >= 500:
        return "inconclusive_server_error"

    return "inconclusive"


def _is_success(http_status: int | None, auth_signal: str) -> bool:
    if auth_signal == "accepted":
        return True
    if auth_signal == "valid_key_service_disabled":
        # The key appears real and tied to a project, but service isn't enabled.
        return True
    return False


def _parse_service_status(payload: Any) -> str | None:
    if isinstance(payload, dict):
        for key in ("status", "error_status"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
        error = payload.get("error")
        if isinstance(error, dict):
            status = error.get("status")
            if isinstance(status, str):
                return status
    return None


def _parse_response(resp: httpx.Response) -> tuple[str | None, str]:
    payload: Any = None
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        text = resp.text.strip()
        return None, text[:240]

    status = _parse_service_status(payload)
    if isinstance(payload, dict):
        err = _extract_error_text(payload)
        if err:
            return status, err[:240]

    return status, "success"


def _headers_with_key(
    key: str,
    android_package: str | None,
    android_cert_sha1: str | None,
    ios_bundle_id: str | None,
) -> dict[str, str]:
    headers = {"X-Goog-Api-Key": key}
    if android_package and android_cert_sha1:
        headers["X-Android-Package"] = android_package
        headers["X-Android-Cert"] = android_cert_sha1
    if ios_bundle_id:
        headers["X-Ios-Bundle-Identifier"] = ios_bundle_id
    return headers


def _build_request(
    definition: ProbeDefinition,
    key: str,
) -> tuple[str, dict[str, str], dict[str, Any], dict[str, Any] | None]:
    headers: dict[str, str] = {}
    params: dict[str, Any] = {}
    body: dict[str, Any] | None = None

    if definition.request_kind == "maps_geocode":
        params = {"address": "New York", "key": key}
    elif definition.request_kind == "maps_timezone":
        params = {"location": "39.6034810,-119.6822510", "timestamp": "1733428634", "key": key}
    elif definition.request_kind == "maps_elevation":
        params = {"locations": "39.7391536,-104.9847034", "key": key}
    elif definition.request_kind == "places_nearby":
        headers = {"X-Goog-FieldMask": "places.displayName"}
        body = {
            "includedTypes": ["restaurant"],
            "maxResultCount": 1,
            "locationRestriction": {
                "circle": {
                    "center": {"latitude": 37.7937, "longitude": -122.3965},
                    "radius": 50.0,
                }
            },
        }
    elif definition.request_kind == "geolocation":
        params = {"key": key}
        body = {"considerIp": True}
    elif definition.request_kind == "translation":
        body = {"q": "hello", "target": "es", "source": "en", "format": "text"}
    elif definition.request_kind == "natural_language":
        body = {"document": {"type": "PLAIN_TEXT", "content": "security test"}}
    elif definition.request_kind == "vision":
        body = {
            "requests": [
                {
                    "image": {"content": ""},
                    "features": [{"type": "LABEL_DETECTION", "maxResults": 1}],
                }
            ]
        }
    elif definition.request_kind == "text_to_speech":
        params = {"key": key}

    return definition.endpoint, headers, params, body


def run_probes(
    key: str,
    timeout_seconds: float = 7.0,
    android_package: str | None = None,
    android_cert_sha1: str | None = None,
    ios_bundle_id: str | None = None,
    probe_workers: int = 1,
    rate_limit_per_sec: float | None = None,
    service_weight_overrides: dict[str, int] | None = None,
    limiter: RateLimiter | None = None,
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    key_headers = _headers_with_key(key, android_package, android_cert_sha1, ios_bundle_id)
    service_weight_overrides = service_weight_overrides or {}
    limiter = limiter or RateLimiter(rate_limit_per_sec)

    def run_single_probe(definition: ProbeDefinition) -> ProbeResult:
        endpoint, headers, params, body = _build_request(definition, key)
        merged_headers = {**headers, **key_headers}

        # Some legacy endpoints only document query-param keys. Keep both for compatibility.
        if "key" not in params and definition.request_kind in {
            "translation",
            "natural_language",
            "vision",
        }:
            params["key"] = key

        limiter.wait()
        started = time.perf_counter()
        http_status: int | None = None
        service_status: str | None = None
        evidence = ""

        try:
            if definition.method == "GET":
                resp = client.get(endpoint, params=params, headers=merged_headers)
            else:
                resp = client.post(endpoint, params=params, headers=merged_headers, json=body)

            http_status = resp.status_code
            service_status, evidence = _parse_response(resp)
        except httpx.TimeoutException:
            evidence = "timeout"
        except httpx.HTTPError as exc:
            evidence = f"network_error: {exc.__class__.__name__}"

        latency_ms = (time.perf_counter() - started) * 1000
        auth_signal = _auth_signal(http_status, service_status, evidence)
        success = _is_success(http_status, auth_signal)
        impact_weight = service_weight_overrides.get(definition.service, definition.impact_weight)

        return ProbeResult(
            service=definition.service,
            endpoint=definition.endpoint,
            method=definition.method,
            success=success,
            auth_signal=auth_signal,
            impact_weight=impact_weight,
            http_status=http_status,
            service_status=service_status,
            evidence=evidence,
            latency_ms=round(latency_ms, 2),
        )

    with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
        worker_count = max(1, min(probe_workers, len(PROBE_DEFINITIONS)))
        if worker_count == 1:
            for definition in PROBE_DEFINITIONS:
                results.append(run_single_probe(definition))
            return results

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(run_single_probe, definition) for definition in PROBE_DEFINITIONS]
            for future in futures:
                results.append(future.result())

    return results
