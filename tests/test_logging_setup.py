"""Importing app modules must not install root log handlers.

customer_fingerprint used to call logging.basicConfig() at import, which
added a second console handler, so every server log line printed twice.
"""
import importlib
import logging
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_customer_fingerprint_import_adds_no_root_handlers():
    code = (
        "import logging, sys; sys.path.insert(0, %r); "
        "import customer_fingerprint; "
        "print(len(logging.getLogger().handlers))" % str(ROOT)
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT)
    assert result.stdout.strip().splitlines()[-1] == "0"


def test_configure_root_logging_adds_one_console_handler(tmp_path, monkeypatch):
    from nmapui import app_runtime

    root = logging.getLogger()
    saved = list(root.handlers), getattr(root, "_nmapui_configured", None)
    try:
        root.handlers = []
        if hasattr(root, "_nmapui_configured"):
            delattr(root, "_nmapui_configured")
        monkeypatch.setenv("NMAPUI_LOG_DIR", str(tmp_path))
        importlib.import_module("customer_fingerprint")
        app_runtime.configure_root_logging(base_dir=tmp_path)
        consoles = [h for h in root.handlers if type(h) is logging.StreamHandler]
        assert len(consoles) == 1
    finally:
        for handler in root.handlers:
            if handler not in saved[0]:
                handler.close()
        root.handlers = saved[0]
        if saved[1] is None and hasattr(root, "_nmapui_configured"):
            delattr(root, "_nmapui_configured")
        elif saved[1] is not None:
            root._nmapui_configured = saved[1]
