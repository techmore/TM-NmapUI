from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from nmapui.jobs import ClientJobRegistry


def test_fence_requires_idle_and_owner_release():
    registry = ClientJobRegistry()
    assert registry.start("owner", "scan")
    assert registry.acquire_maintenance() is None
    registry.complete("owner", "scan")
    token = registry.acquire_maintenance()
    assert token and len(token) == 32
    assert registry.snapshot()["maintenance_active"]
    assert token not in str(registry.snapshot())
    assert not registry.start("other", "report")
    assert "maintenance" in registry.get_start_rejection_reason("other", "report")
    assert not registry.release_maintenance("0" * 32)
    assert registry.acquire_maintenance() is None
    assert registry.acquire_maintenance(token) == token
    assert registry.release_maintenance(token)
    assert not registry.release_maintenance(token)
    assert registry.start("other", "report")


def test_fence_and_job_admission_share_one_atomic_decision():
    for _ in range(100):
        registry = ClientJobRegistry()
        barrier = Barrier(2)
        def job():
            barrier.wait()
            return registry.start("owner", "scan")
        def fence():
            barrier.wait()
            return registry.acquire_maintenance()
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(job), pool.submit(fence)
            started, token = a.result(), b.result()
        assert bool(started) != bool(token)
        if token:
            assert not registry.snapshot()["has_active_jobs"]
        else:
            assert not registry.snapshot()["maintenance_active"]


def test_cancelling_work_and_tracked_children_block_maintenance():
    registry = ClientJobRegistry()
    assert registry.start("owner", "scan")
    assert registry.cancel("owner", "scan")
    assert registry.acquire_maintenance() is None
    registry.complete("owner", "scan")
    registry.attach_process("owner", "scan", object())
    assert registry.acquire_maintenance() is None
    registry.clear_process("owner", "scan")
    assert registry.acquire_maintenance()


def test_maintenance_route_requires_local_auth_and_matching_browser_origin(monkeypatch):
    import base64
    from flask import Flask
    from nmapui.handlers.routes import register_core_routes
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")
    monkeypatch.setenv("NMAPUI_USERNAME", "fixture-user")
    monkeypatch.setenv("NMAPUI_PASSWORD", "fixture-password")
    registry = ClientJobRegistry()
    app = Flask(__name__)
    register_core_routes(app, {"build_liveness_payload": lambda **kw: {},
        "build_readiness_payload": lambda **kw: ({}, 200), "get_app_version": lambda: "fixture",
        "get_default_interface_cached": lambda: None, "get_versions": lambda: {},
        "job_registry": registry, "settings_state": {}, "startup_state": {}, "get_auto_scan_thread": lambda: None})
    client = app.test_client()
    path = "/api/runtime/maintenance"
    headers = {"Authorization": "Basic " + base64.b64encode(b"fixture-user:fixture-password").decode()}
    assert client.post(path).status_code == 401
    assert client.post(path, headers={**headers, "Origin": "https://outside.invalid"}).status_code == 403
    assert client.post(path, headers=headers, environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 403
    response = client.post(path, headers=headers)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    token = response.json["token"]
    assert client.post(path, headers=headers).status_code == 409
    assert client.post(path, headers=headers, json={"token": token}).json["token"] == token
    assert client.post(path, headers=headers, json={"token": "0" * 32}).status_code == 409
    assert client.post(path, headers=headers, json={"token": "invalid"}).status_code == 400
    assert client.get("/api/runtime/status").json["maintenance_active"] is True
    assert token not in str(client.get("/api/runtime/status").json)
    assert client.delete(path, headers=headers, json={"token": "0" * 32}).status_code == 409
    assert client.delete(path, headers=headers, json={"token": token}).status_code == 200
    assert registry.start("owner", "scan")
    assert client.post(path, headers=headers).status_code == 409
