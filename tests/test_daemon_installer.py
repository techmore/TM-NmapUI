"""Execute generated daemon artifacts without installing a system service."""

import json
import os
from pathlib import Path
import plistlib
import pwd
import subprocess
import sys

import pytest


INSTALLER = Path(__file__).resolve().parents[1] / "packaging/macos/install-daemon.sh"


def installer_call(script, env):
    return subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n' + script],
        env={**os.environ, "INSTALLER": str(INSTALLER), **env},
        text=True, capture_output=True, timeout=10, check=True,
    )


@pytest.fixture
def generated_launcher(tmp_path):
    root = tmp_path / "Nmap UI & literal $(touch INJECTED)"
    root.mkdir()
    app = root / "app.py"
    app.write_text(
        "import json, os\n"
        "print(json.dumps({k: v for k, v in os.environ.items() if k.startswith('NMAPUI_')}))\n"
    )
    credentials = root / "credentials.env"
    wrapper = root / "run.sh"
    env = {
        "TEST_ROOT": str(root), "TEST_APP": str(app),
        "TEST_CREDENTIALS": str(credentials), "TEST_WRAPPER": str(wrapper),
        "TEST_PYTHON": sys.executable,
    }
    installer_call(
        'ROOT_DIR="$TEST_ROOT"; APP_PATH="$TEST_APP"; PYTHON_BIN="$TEST_PYTHON"\n'
        'CREDENTIALS_FILE="$TEST_CREDENTIALS"\n'
        'build_wrapper "$TEST_WRAPPER"', env,
    )
    return root, credentials, wrapper, env


def test_generated_launcher_preserves_literal_credentials_and_paths(generated_launcher):
    root, credentials, wrapper, _ = generated_launcher
    password = "literal $(touch INJECTED) `touch INJECTED` a=b # end"
    credentials.write_text(
        f"NMAPUI_DATA_DIR={root}/Application Support/data\n"
        f"NMAPUI_LOG_DIR={root}/Application Support/logs\n"
        "NMAPUI_USERNAME=admin\n"
        f"NMAPUI_PASSWORD={password}"  # Last line need not end in a newline.
    )
    result = subprocess.run([str(wrapper)], cwd=root, check=True, capture_output=True, text=True, timeout=10)
    values = json.loads(result.stdout)
    assert values["NMAPUI_DATA_DIR"] == str(root / "Application Support/data")
    assert values["NMAPUI_PASSWORD"] == password
    assert not (root / "INJECTED").exists()


def test_generated_launcher_requires_credentials(generated_launcher):
    _, _, wrapper, _ = generated_launcher
    result = subprocess.run([str(wrapper)], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "not readable" in result.stderr


def test_generated_launcher_rejects_unknown_environment_keys(generated_launcher):
    _, credentials, wrapper, _ = generated_launcher
    credentials.write_text("PATH=/untrusted\n")
    result = subprocess.run([str(wrapper)], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "Unsupported setting" in result.stderr


def test_generated_plist_preserves_paths_and_supervision(generated_launcher):
    root, _, _, env = generated_launcher
    target = root / "daemon.plist"
    installer_call(
        'ROOT_DIR="$TEST_ROOT"; PYTHON_BIN="$TEST_PYTHON"\n'
        'WRAPPER_PATH="$TEST_WRAPPER"; LOG_DIR="$TEST_ROOT/logs"\n'
        'RUN_USER="scanner"\n'
        'build_plist "$TEST_ROOT/daemon.plist"', env,
    )
    with target.open("rb") as stream:
        plist = plistlib.load(stream)
    assert plist["WorkingDirectory"] == str(root)
    assert plist["ProgramArguments"] == [env["TEST_WRAPPER"]]
    assert plist["UserName"] == "scanner"
    assert plist["RunAtLoad"] and plist["KeepAlive"]
    assert plist["ThrottleInterval"] >= 10


def test_service_permissions_are_private_and_do_not_follow_symlinks(tmp_path):
    data = tmp_path / "Application Support"
    (data / "data").mkdir(parents=True)
    logs = tmp_path / "logs"
    logs.mkdir()
    credentials = data / "credentials.env"
    credentials.write_text("NMAPUI_USERNAME=admin\n")
    credentials.chmod(0o644)  # Reinstall repairs permissions on an existing file.
    outside = tmp_path / "untouched"
    outside.write_text("outside runtime")
    outside.chmod(0o644)
    (data / "data/link").symlink_to(outside)
    installer_call(
        'DATA_DIR="$TEST_DATA"; LOG_DIR="$TEST_LOGS"\n'
        'CREDENTIALS_FILE="$DATA_DIR/credentials.env"; RUN_USER="$TEST_USER"\n'
        'set_runtime_permissions',
        {"TEST_DATA": str(data), "TEST_LOGS": str(logs), "TEST_USER": pwd.getpwuid(os.getuid()).pw_name},
    )
    assert logs.stat().st_mode & 0o777 == 0o700
    assert credentials.stat().st_mode & 0o777 == 0o600
    assert outside.stat().st_mode & 0o777 == 0o644


def test_sudoers_grants_only_the_validating_helper(tmp_path):
    """sudoers must never grant nmap or arp-scan directly."""
    target = tmp_path / "nmapui.sudoers"
    installer_call(
        'HELPER_PATH="/usr/local/libexec/nmapui-privileged-scanner"\n'
        'RUN_USER="scanner"\n'
        'build_sudoers "$TEST_TARGET"',
        {"TEST_TARGET": str(target)},
    )
    content = target.read_text()
    assert "scanner ALL=(root) NOPASSWD: /usr/local/libexec/nmapui-privileged-scanner" in content
    assert "bin/nmap" not in content
    assert "bin/arp-scan" not in content


def test_sudoers_is_valid_and_uses_an_absolute_helper_path(tmp_path):
    target = tmp_path / "nmapui.sudoers"
    installer_call(
        'HELPER_PATH="/usr/local/libexec/nmapui-privileged-scanner"\n'
        'RUN_USER="scanner"\n'
        'build_sudoers "$TEST_TARGET"\n'
        'validate_sudoers "$TEST_TARGET"',
        {"TEST_TARGET": str(target)},
    )
    assert target.read_text().splitlines()[-1].startswith("scanner ALL=(root) NOPASSWD: /")


def test_default_install_refuses_to_run_the_backend_as_root(tmp_path):
    """Least privilege is the default; --allow-root must be explicit."""
    installer = Path(__file__).resolve().parents[1] / "packaging/macos/install-daemon.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$INSTALLER"\nMODE="install"\nRUN_USER=""\nALLOW_ROOT=0\n'
            "unset SUDO_USER\nresolve_run_user",
        ],
        env={**os.environ, "INSTALLER": str(installer)},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "refusing to run the web backend as root" in result.stderr


def test_allow_root_is_accepted_when_explicit():
    installer = Path(__file__).resolve().parents[1] / "packaging/macos/install-daemon.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$INSTALLER"\nMODE="install"\nRUN_USER=""\nALLOW_ROOT=1\n'
            "resolve_run_user\nprintf '%s' \"$RUN_USER\"",
        ],
        env={**os.environ, "INSTALLER": str(installer)},
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert result.stdout == "root"


def test_wrapper_accepts_the_privileged_asset_setting(tmp_path):
    wrapper = tmp_path / "run.sh"
    credentials = tmp_path / "credentials.env"
    installer_call(
        'ROOT_DIR="/tmp"; APP_PATH="/tmp/app.py"; PYTHON_BIN="/usr/bin/true"\n'
        'CREDENTIALS_FILE="$TEST_CREDENTIALS"\n'
        'build_wrapper "$TEST_WRAPPER"',
        {"TEST_CREDENTIALS": str(credentials), "TEST_WRAPPER": str(wrapper)},
    )
    credentials.write_text("NMAPUI_PRIVILEGED_ASSETS=/usr/local/share/nmapui\n")
    result = subprocess.run(
        ["bash", "-n", str(wrapper)], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0
    assert "NMAPUI_PRIVILEGED_ASSETS" in wrapper.read_text()
