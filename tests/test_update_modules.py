from flask import Flask
from flask_socketio import SocketIO

from nmapui.handlers.updates import register_update_handlers
import nmapui.runtime as runtime


def test_check_for_updates_selects_mac_installer_asset(monkeypatch):
    runtime.APP_VERSION = None
    monkeypatch.setattr(runtime, "get_app_version", lambda: "v2026.1.1.00_00")
    monkeypatch.setattr(runtime.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(runtime.sys, "platform", "darwin")

    class ResponseStub:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v2026.1.9.12_53",
                "html_url": "https://github.com/techmore/TM-NmapUI/releases/tag/v2026.1.9.12_53",
                "body": "release notes",
                "assets": [
                    {"name": "NmapUI.pkg", "browser_download_url": "https://github.com/techmore/TM-NmapUI/releases/download/v2026.1.9.12_53/NmapUI.pkg"},
                    {"name": "NmapUI.dmg", "browser_download_url": "https://github.com/techmore/TM-NmapUI/releases/download/v2026.1.9.12_53/NmapUI.dmg"},
                ],
            }

    monkeypatch.setattr(runtime.requests, "get", lambda url, timeout=10: ResponseStub())

    result = runtime.check_for_updates()

    assert result["available"] is True
    assert result["current_version"] == "v2026.1.1.00_00"
    assert result["latest_version"] == "v2026.1.9.12_53"
    assert result["asset_name"] == "NmapUI.dmg"
    assert result["download_url"] == "https://github.com/techmore/TM-NmapUI/releases/download/v2026.1.9.12_53/NmapUI.dmg"
    assert result["install_method"] == "manual_download"


def test_check_for_updates_reports_current_version_when_no_update(monkeypatch):
    runtime.APP_VERSION = None
    monkeypatch.setattr(runtime, "get_app_version", lambda: "v2026.1.9.12_53")

    class ResponseStub:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v2026.1.9.12_53",
                "html_url": "https://github.com/techmore/TM-NmapUI/releases/tag/v2026.1.9.12_53",
                "body": "release notes",
                "assets": [],
            }

    monkeypatch.setattr(runtime.requests, "get", lambda url, timeout=10: ResponseStub())

    result = runtime.check_for_updates()

    assert result == {
        "available": False,
        "current_version": "v2026.1.9.12_53",
        "latest_version": "v2026.1.9.12_53",
        "release_url": "https://github.com/techmore/TM-NmapUI/releases/tag/v2026.1.9.12_53",
    }


def test_perform_app_update_emits_manual_install_messages(monkeypatch):
    monkeypatch.setenv("NMAPUI_USERNAME", "scanner")
    monkeypatch.setenv("NMAPUI_PASSWORD", "secret-pass")
    monkeypatch.setenv("NMAPUI_TRUST_LOCAL_UI", "false")

    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins="*", test_mode=True)
    opened_urls = []

    class IdleStateStub:
        def set_update_available(self, available, update_info=None):
            return None

        def cancel_countdown(self):
            return None

        def start_countdown(self):
            return None

    register_update_handlers(
        socketio,
        {
            "check_for_updates": lambda: {
                "available": True,
                "latest_version": "v2026.1.9.12_53",
                "asset_name": "NmapUI.dmg",
                "download_url": "https://example.com/NmapUI.dmg",
                "release_url": "https://github.com/techmore/TM-NmapUI/releases/tag/v2026.1.9.12_53",
            },
            "idle_state_manager": IdleStateStub(),
            "logger": app.logger,
        },
    )

    import nmapui.handlers.updates as updates_module

    monkeypatch.setattr(
        updates_module.subprocess,
        "run",
        lambda cmd, check=False: opened_urls.append(cmd[1]),
    )

    token_client = app.test_client()
    import base64
    token = base64.b64encode(b"scanner:secret-pass").decode()
    client = socketio.test_client(app, flask_test_client=token_client, headers={"Authorization": f"Basic {token}"})
    client.emit("perform_app_update")
    received = client.get_received()

    assert opened_urls == ["https://example.com/NmapUI.dmg"]
    assert any(
        event["name"] == "update_status"
        and event["args"] == [{"message": "Opening installer download for NmapUI.dmg..."}]
        for event in received
    )
    assert any(
        event["name"] == "update_complete"
        and event["args"] == [{
            "message": "Installer page opened. Finish the update manually and relaunch NmapUI.",
            "manual_install": True,
            "download_url": "https://example.com/NmapUI.dmg",
        }]
        for event in received
    )
