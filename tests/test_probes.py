import httpx
import respx

from gcp_key_auditor.probes import run_probes


@respx.mock
def test_run_probes_parses_responses() -> None:
    # Mock one accepted endpoint and default others to a denied shape.
    respx.get("https://maps.googleapis.com/maps/api/geocode/json").respond(
        200, json={"status": "OK", "results": []}
    )

    deny_payload = {"error": {"status": "PERMISSION_DENIED", "message": "API key not valid"}}

    for method, url in [
        ("GET", "https://maps.googleapis.com/maps/api/timezone/json"),
        ("GET", "https://maps.googleapis.com/maps/api/elevation/json"),
        ("POST", "https://places.googleapis.com/v1/places:searchNearby"),
        ("POST", "https://www.googleapis.com/geolocation/v1/geolocate"),
        ("POST", "https://translation.googleapis.com/language/translate/v2"),
        ("POST", "https://language.googleapis.com/v1/documents:analyzeSentiment"),
        ("POST", "https://vision.googleapis.com/v1/images:annotate"),
        ("GET", "https://texttospeech.googleapis.com/v1/voices"),
    ]:
        route = respx.route(method=method, url=url)
        route.respond(403, json=deny_payload)

    results = run_probes("AIza" + "A" * 35, timeout_seconds=2)

    assert len(results) == 9
    geocode = next(r for r in results if r.service == "maps_geocoding")
    assert geocode.auth_signal == "accepted"

    denied = [r for r in results if r.service != "maps_geocoding"]
    assert all(r.http_status == 403 for r in denied)


@respx.mock
def test_run_probes_applies_service_weight_override() -> None:
    respx.get("https://maps.googleapis.com/maps/api/geocode/json").respond(
        200, json={"status": "OK", "results": []}
    )
    for method, url in [
        ("GET", "https://maps.googleapis.com/maps/api/timezone/json"),
        ("GET", "https://maps.googleapis.com/maps/api/elevation/json"),
        ("POST", "https://places.googleapis.com/v1/places:searchNearby"),
        ("POST", "https://www.googleapis.com/geolocation/v1/geolocate"),
        ("POST", "https://translation.googleapis.com/language/translate/v2"),
        ("POST", "https://language.googleapis.com/v1/documents:analyzeSentiment"),
        ("POST", "https://vision.googleapis.com/v1/images:annotate"),
        ("GET", "https://texttospeech.googleapis.com/v1/voices"),
    ]:
        respx.route(method=method, url=url).respond(
            403, json={"error": {"status": "PERMISSION_DENIED", "message": "API key not valid"}}
        )

    results = run_probes(
        "AIza" + "A" * 35,
        timeout_seconds=2,
        service_weight_overrides={"maps_geocoding": 99},
    )
    geocode = next(r for r in results if r.service == "maps_geocoding")
    assert geocode.impact_weight == 99
