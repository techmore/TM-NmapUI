"""The browser UI is the olive theme; the elementary layer is native-shell only."""

from pathlib import Path

from flask import Flask

from nmapui.handlers.routes import (
    ELEMENTARY_SHELL_COOKIE,
    elementary_shell_requested,
)

ROOT = Path(__file__).resolve().parents[1]
ELEMENTARY_LINK = "/static/css/elementary.css"


def _render_index(**context):
    app = Flask(__name__, template_folder=str(ROOT / "templates"))
    with app.test_request_context("/"):
        from flask import render_template

        return render_template("index.html", management_history_url="", **context)


def test_browser_index_never_loads_the_elementary_layer():
    html = _render_index(elementary_shell=False)
    assert ELEMENTARY_LINK not in html
    assert "elementary-palette.css" not in html
    assert "/static/css/tailwind.css" in html


def test_native_shell_index_loads_the_elementary_layer():
    html = _render_index(elementary_shell=True)
    assert ELEMENTARY_LINK in html
    assert "elementary-palette.css" in html


def test_elementary_shell_opt_in_by_user_agent_or_cookie_only():
    app = Flask(__name__)
    browser_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    with app.test_request_context("/", headers={"User-Agent": browser_ua}):
        from flask import request

        assert elementary_shell_requested(request) is False
    with app.test_request_context("/", headers={"User-Agent": browser_ua + " NmapUI-elementary/1.0"}):
        from flask import request

        assert elementary_shell_requested(request) is True
    with app.test_request_context("/", headers={"Cookie": f"{ELEMENTARY_SHELL_COOKIE}=elementary"}):
        from flask import request

        assert elementary_shell_requested(request) is True


def test_olive_palette_is_the_tailwind_theme():
    config = (ROOT / "scripts" / "ui-assets" / "tailwind.config.cjs").read_text(encoding="utf-8")
    assert "600: 'oklch(42% 0.055 110)'" in config
    css = (ROOT / "static" / "css" / "tailwind.css").read_text(encoding="utf-8")
    assert ".bg-olive-600" in css


def test_login_page_uses_the_olive_palette():
    login = (ROOT / "templates" / "login.html").read_text(encoding="utf-8")
    assert "background: oklch(42% 0.055 110)" in login
    assert "#2563eb" not in login
    assert "color-scheme: dark" not in login
