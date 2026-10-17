"""API smoke tests: routes are registered and exposed in the OpenAPI schema."""

from __future__ import annotations

from backend.main import app


def test_health_route_exists():
    paths = {getattr(route, "path", "") for route in app.routes}

    assert "/health" in paths


def test_engine_routes_are_registered():
    paths = set(app.openapi()["paths"])

    expected = {
        "/captures",
        "/captures/{capture_id}/packets",
        "/captures/{capture_id}/packets/{packet_index}/tree",
        "/captures/{capture_id}/flows",
        "/captures/{capture_id}/flows/{flow_id}",
        "/captures/{capture_id}/statistics",
        "/query",
        "/query/fields",
    }

    assert expected <= paths


def test_app_metadata():
    assert app.title == "Mini Shark"
    assert app.version == "0.2.0"
