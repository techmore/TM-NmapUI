from nmapui.bootstrap import (
    DEFAULT_RUNTIME_PORT,
    begin_startup_state,
    build_runtime_options,
    create_web_app,
    complete_startup_state,
    get_allowed_origins,
    run_socketio_server,
    select_runtime_port,
)


def test_build_runtime_options_uses_env_and_argv(monkeypatch):
    monkeypatch.setenv("NMAPUI_HOST", "0.0.0.0")
    monkeypatch.setenv("NMAPUI_PORT", "9100")
    monkeypatch.setenv("NMAPUI_DEBUG", "true")
    monkeypatch.setenv("NMAPUI_ALLOW_UNSAFE_WERKZEUG", "true")

    options = build_runtime_options(["app.py", "--quick"])

    assert options == {
        "quick_mode": True,
        "host": "0.0.0.0",
        "port": 9100,
        "requested_port": 9100,
        "port_auto_selected": False,
        "debug": True,
        "allow_unsafe_werkzeug": True,
    }


def test_get_allowed_origins_defaults_to_local_ui_hosts(monkeypatch):
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)

    assert get_allowed_origins() == [
        f"http://127.0.0.1:{DEFAULT_RUNTIME_PORT}",
        f"http://localhost:{DEFAULT_RUNTIME_PORT}",
        f"http://[::1]:{DEFAULT_RUNTIME_PORT}",
    ]


def test_get_allowed_origins_uses_environment_allowlist(monkeypatch):
    monkeypatch.setenv(
        "NMAPUI_ALLOWED_ORIGINS",
        "https://scanner.example.com, https://ops.example.com ",
    )

    assert get_allowed_origins() == [
        "https://scanner.example.com",
        "https://ops.example.com",
    ]


def test_get_allowed_origins_uses_selected_port_when_not_explicitly_configured(monkeypatch):
    monkeypatch.delenv("NMAPUI_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("NMAPUI_PORT", raising=False)

    assert get_allowed_origins(port=9101) == [
        "http://127.0.0.1:9101",
        "http://localhost:9101",
        "http://[::1]:9101",
    ]


def test_select_runtime_port_falls_back_when_default_port_is_busy(monkeypatch):
    monkeypatch.setattr(
        "nmapui.bootstrap._is_port_available",
        lambda host, port: port == 9001,
    )

    assert select_runtime_port("127.0.0.1", 9000, explicit=False) == 9001


def test_select_runtime_port_rejects_busy_explicit_port(monkeypatch):
    monkeypatch.setattr("nmapui.bootstrap._is_port_available", lambda host, port: False)

    try:
        select_runtime_port("127.0.0.1", 9100, explicit=True)
    except RuntimeError as exc:
        assert "9100" in str(exc)
    else:  # pragma: no cover - defensive failure path only
        raise AssertionError("Expected explicit busy port selection to fail")


def test_begin_startup_state_resets_transient_fields():
    state = {
        "startup_complete": True,
        "dependency_checks_skipped": False,
        "dependencies_ok": True,
        "traceroute_initialized": True,
        "last_started_at": None,
        "errors": ["old error"],
    }

    begin_startup_state(state, quick=True)

    assert state["startup_complete"] is False
    assert state["dependency_checks_skipped"] is True
    assert state["dependencies_ok"] is False
    assert state["traceroute_initialized"] is False
    assert state["errors"] == []
    assert state["last_started_at"] is not None


def test_complete_startup_state_marks_startup_complete():
    state = {
        "startup_complete": False,
        "dependency_checks_skipped": False,
        "dependencies_ok": True,
        "traceroute_initialized": False,
        "last_started_at": None,
        "errors": [],
    }

    complete_startup_state(state, traceroute_initialized=True)

    assert state["startup_complete"] is True
    assert state["traceroute_initialized"] is True


def test_create_web_app_initializes_flask_and_socketio():
    created = {}

    class FlaskStub:
        def __init__(self, import_name):
            created["import_name"] = import_name

    class SocketIOStub:
        def __init__(self, app, cors_allowed_origins):
            created["socketio_app"] = app
            created["cors_allowed_origins"] = cors_allowed_origins

    def cors_stub(app, resources):
        created["cors_app"] = app
        created["cors_resources"] = resources

    import nmapui.bootstrap as bootstrap

    original_flask = bootstrap.Flask
    original_socketio = bootstrap.SocketIO
    original_cors = bootstrap.CORS
    original_get_allowed_origins = bootstrap.get_allowed_origins
    bootstrap.Flask = FlaskStub
    bootstrap.SocketIO = SocketIOStub
    bootstrap.CORS = cors_stub
    bootstrap.get_allowed_origins = lambda *, port=None: ["https://scanner.example.com"]
    try:
        app, socketio = create_web_app("nmapui.app", port=9102)
    finally:
        bootstrap.Flask = original_flask
        bootstrap.SocketIO = original_socketio
        bootstrap.CORS = original_cors
        bootstrap.get_allowed_origins = original_get_allowed_origins

    assert created["import_name"] == "nmapui.app"
    assert created["socketio_app"] is app
    assert socketio is not None
    assert created["cors_allowed_origins"] == ["https://scanner.example.com"]
    assert created["cors_app"] is app
    assert created["cors_resources"] == {
        r"/api/*": {"origins": ["https://scanner.example.com"]}
    }


def test_run_socketio_server_requires_debug_even_for_loopback_hosts():
    calls = {}

    class SocketIOStub:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            calls["app"] = app
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug
            calls["allow_unsafe_werkzeug"] = allow_unsafe_werkzeug

    app = object()
    runtime_options = {
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": False,
    }

    run_socketio_server(SocketIOStub(), app, runtime_options)

    assert calls == {
        "app": app,
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": False,
    }


def test_run_socketio_server_requires_debug_for_non_loopback_hosts():
    calls = {}

    class SocketIOStub:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            calls["app"] = app
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug
            calls["allow_unsafe_werkzeug"] = allow_unsafe_werkzeug

    app = object()
    runtime_options = {
        "host": "0.0.0.0",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": False,
    }

    run_socketio_server(SocketIOStub(), app, runtime_options)

    assert calls == {
        "app": app,
        "host": "0.0.0.0",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": False,
    }


def test_run_socketio_server_allows_werkzeug_in_explicit_debug_mode():
    calls = {}

    class SocketIOStub:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            calls["app"] = app
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug
            calls["allow_unsafe_werkzeug"] = allow_unsafe_werkzeug

    app = object()
    runtime_options = {
        "host": "127.0.0.1",
        "port": 9000,
        "debug": True,
        "allow_unsafe_werkzeug": False,
    }

    run_socketio_server(SocketIOStub(), app, runtime_options)

    assert calls == {
        "app": app,
        "host": "127.0.0.1",
        "port": 9000,
        "debug": True,
        "allow_unsafe_werkzeug": True,
    }


def test_run_socketio_server_allows_explicit_unsafe_werkzeug_override():
    calls = {}

    class SocketIOStub:
        def run(self, app, host, port, debug, allow_unsafe_werkzeug):
            calls["app"] = app
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug
            calls["allow_unsafe_werkzeug"] = allow_unsafe_werkzeug

    app = object()
    runtime_options = {
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": True,
    }

    run_socketio_server(SocketIOStub(), app, runtime_options)

    assert calls == {
        "app": app,
        "host": "127.0.0.1",
        "port": 9000,
        "debug": False,
        "allow_unsafe_werkzeug": True,
    }
