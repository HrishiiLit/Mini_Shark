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
        "/probes",
    }

    assert expected <= paths


def test_probe_status_endpoint_returns_expected_structure():
    from backend.api.routes import get_connected_probes, get_hub, _get_probes_status
    status = get_connected_probes()
    assert isinstance(status, dict)
    assert "probe1_connected" in status
    assert "probe2_connected" in status
    assert "active_clients" in status
    assert "total_connected" in status

    # Verify connected probe reflection
    hub = get_hub()
    import time
    hub.connected_probes[1] = {
        "probe_id": 1,
        "ip": "192.168.130.128",
        "port": 42508,
        "connected_at": time.time(),
        "last_seen": time.time(),
        "records": 10,
    }
    res = _get_probes_status(hub)
    assert res["probe1_connected"] is True
    assert res["probe1_ip"] == "192.168.130.128"
    assert res["total_connected"] == 1
    # Cleanup
    hub.connected_probes.clear()


def test_app_metadata():
    assert app.title == "Mini Shark"
    assert app.version in ("0.2.0", "0.4.0")
