import importlib.util
from pathlib import Path

import pytest


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "packaging" / "validate_service_env.py"
SPEC = importlib.util.spec_from_file_location("nmapui_service_env", VALIDATOR_PATH)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def _validate(path):
    VALIDATOR.validate_service_env(
        path,
        expected_data="/var/lib/nmapui",
        expected_log="/var/log/nmapui",
        expected_browser="/opt/nmapui/playwright-browsers",
    )


def test_service_env_accepts_literal_paths_and_special_password(tmp_path):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        "NMAPUI_PORT=9000\n"
        "NMAPUI_ALLOWED_ORIGINS=https://scanner.example\n"
        "NMAPUI_MAX_CONCURRENT_JOBS=3\n"
        "NMAPUI_RUNTIME_LOGS_KEEP_LATEST=7500\n"
        "NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST=1500\n"
        "NMAPUI_FINISHED_JOBS_KEEP_LATEST=2500\n"
        "NMAPUI_PASSWORD=literal=a$b # retained\n",
        encoding="utf-8",
    )

    _validate(credentials)


def test_service_env_preserves_mac_paths_with_spaces(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/Library/Application Support/NmapUI/data\n"
        "NMAPUI_LOG_DIR=/Library/Logs/NmapUI\n"
        "PLAYWRIGHT_BROWSERS_PATH=/usr/local/share/nmapui/playwright-browsers\n"
        "NMAPUI_PASSWORD=literal $(touch nowhere) a=b\n",
        encoding="utf-8",
    )

    VALIDATOR.validate_service_env(
        credentials,
        expected_data="/Library/Application Support/NmapUI/data",
        expected_log="/Library/Logs/NmapUI",
        expected_browser="/usr/local/share/nmapui/playwright-browsers",
    )


@pytest.mark.parametrize(
    "name",
    [
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT",
        "NMAPUI_ENABLE_UPDATE_CHECK",
        "NMAPUI_ENABLE_VULNERS",
        "NMAPUI_COOKIE_SECURE",
    ],
)
def test_service_env_accepts_and_validates_egress_switches(tmp_path, name):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        f"{name}=false\n",
        encoding="utf-8",
    )
    _validate(credentials)

    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        f"{name}=maybe\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=name):
        _validate(credentials)


@pytest.mark.parametrize(
    "replacement",
    [
        "NMAPUI_DATA_DIR=/tmp/other",
        "NMAPUI_DATA_DIR='/var/lib/nmapui'",
        "NMAPUI_DATA_DIR=/var/lib/nmapui\nNMAPUI_DATA_DIR=/tmp/other",
    ],
)
def test_service_env_rejects_misplaced_or_duplicate_data_dir(tmp_path, replacement):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        replacement + "\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        _validate(credentials)


@pytest.mark.parametrize("port", ["0", "65536", "09000", "not-a-port"])
def test_service_env_rejects_ports_the_service_cannot_bind(tmp_path, port):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        f"NMAPUI_PORT={port}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="NMAPUI_PORT"):
        _validate(credentials)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("NMAPUI_MAX_CONCURRENT_JOBS", "0"),
        ("NMAPUI_RUNTIME_LOGS_KEEP_LATEST", "-1"),
        ("NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST", "1.5"),
        ("NMAPUI_FINISHED_JOBS_KEEP_LATEST", "2147483648"),
    ],
)
def test_service_env_rejects_invalid_operational_limits(tmp_path, setting, value):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        f"{setting}={value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=setting):
        _validate(credentials)


def test_service_env_rejects_duplicate_password_and_indented_comment(tmp_path):
    credentials = tmp_path / "nmapui.env"
    base = (
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
    )
    credentials.write_text(base + "NMAPUI_PASSWORD=first\nNMAPUI_PASSWORD=second\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        _validate(credentials)

    credentials.write_text(base + "  # ambiguous comment\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid service setting"):
        _validate(credentials)


@pytest.mark.parametrize(
    "setting",
    [
        "PATH=/tmp/override",
        "LD_PRELOAD=/tmp/override.so",
        "PYTHONPATH=/tmp/override",
    ],
)
def test_service_env_rejects_process_injection_settings(tmp_path, setting):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text(
        "NMAPUI_DATA_DIR=/var/lib/nmapui\n"
        "NMAPUI_LOG_DIR=/var/log/nmapui\n"
        "PLAYWRIGHT_BROWSERS_PATH=/opt/nmapui/playwright-browsers\n"
        f"{setting}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported service setting"):
        _validate(credentials)
