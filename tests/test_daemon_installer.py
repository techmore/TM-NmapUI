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
        'build_wrapper "$TEST_WRAPPER" direct', env,
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


def test_generated_launcher_uses_assets_from_current_release(generated_launcher):
    root, credentials, wrapper, _ = generated_launcher
    (root / "privileged-assets").mkdir()
    credentials.write_text("NMAPUI_PRIVILEGED_ASSETS=/usr/local/share/nmapui\n")

    result = subprocess.run([str(wrapper)], cwd=root, check=True, capture_output=True, text=True, timeout=10)

    assert json.loads(result.stdout)["NMAPUI_PRIVILEGED_ASSETS"] == str(root / "privileged-assets")


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


def test_privacy_defaults_disable_optional_egress_but_preserve_explicit_opt_in(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("NMAPUI_ENABLE_UPDATE_CHECK=true\n")
    installer_call(
        'CREDENTIALS_FILE="$TEST_CREDENTIALS"; ensure_privacy_safe_egress_defaults',
        {"TEST_CREDENTIALS": str(credentials)},
    )

    values = dict(
        line.split("=", 1) for line in credentials.read_text().splitlines()
    )
    assert values == {
        "NMAPUI_ENABLE_UPDATE_CHECK": "true",
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false",
        "NMAPUI_ENABLE_VULNERS": "false",
    }


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
    assert "/opt/homebrew/bin" not in plist["EnvironmentVariables"]["PATH"]


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


def test_default_install_runs_the_backend_as_root():
    """Root is the platform default: no sudoers dependency, no extra decision."""
    installer = Path(__file__).resolve().parents[1] / "packaging/macos/install-daemon.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$INSTALLER"\nMODE="install"\nRUN_USER=""\n'
            "unset SUDO_USER\nresolve_run_user\nprintf '%s' \"$RUN_USER\"",
        ],
        env={**os.environ, "INSTALLER": str(installer)},
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert result.stdout == "root"


def test_user_flag_opts_into_the_least_privilege_path():
    installer = Path(__file__).resolve().parents[1] / "packaging/macos/install-daemon.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$INSTALLER"\nMODE="install"\nRUN_USER="scanner"\n'
            "resolve_run_user\nprintf '%s' \"$RUN_USER\"",
        ],
        env={**os.environ, "INSTALLER": str(installer)},
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert result.stdout == "scanner"


def test_root_mode_needs_no_sudoers_grant(tmp_path):
    target = tmp_path / "nmapui.sudoers"
    installer_call(
        'HELPER_PATH="/usr/local/libexec/nmapui-privileged-scanner"\n'
        'RUN_USER="root"\n'
        'build_sudoers "$TEST_TARGET"\n'
        'validate_sudoers "$TEST_TARGET"',
        {"TEST_TARGET": str(target)},
    )
    content = target.read_text()
    assert "NOPASSWD" not in content
    assert "no sudoers grant is needed" in content


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


def test_generated_launcher_accepts_operational_limit_overrides(generated_launcher):
    root, credentials, wrapper, _ = generated_launcher
    credentials.write_text(
        "NMAPUI_PRIVILEGED_ASSETS=/usr/local/share/nmapui\n"
        "NMAPUI_ALLOWED_ORIGINS=https://scanner.example.com\n"
        "NMAPUI_TRUST_LOCAL_UI=false\n"
        "NMAPUI_COOKIE_SECURE=true\n"
        "NMAPUI_ENABLE_VULNERS=true\n"
        "NMAPUI_MAX_CONCURRENT_JOBS=3\n"
        "NMAPUI_RUNTIME_LOGS_KEEP_LATEST=5000\n"
        "NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST=2000\n"
        "NMAPUI_FINISHED_JOBS_KEEP_LATEST=2000\n"
    )
    result = subprocess.run(
        [str(wrapper)], cwd=root, capture_output=True, text=True, timeout=10, check=True
    )
    values = json.loads(result.stdout)

    assert values["NMAPUI_PRIVILEGED_ASSETS"] == "/usr/local/share/nmapui"
    assert values["NMAPUI_ALLOWED_ORIGINS"] == "https://scanner.example.com"
    assert values["NMAPUI_TRUST_LOCAL_UI"] == "false"
    assert values["NMAPUI_COOKIE_SECURE"] == "true"
    assert values["NMAPUI_ENABLE_VULNERS"] == "true"
    assert values["NMAPUI_MAX_CONCURRENT_JOBS"] == "3"
    assert values["NMAPUI_RUNTIME_LOGS_KEEP_LATEST"] == "5000"
    assert values["NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST"] == "2000"
    assert values["NMAPUI_FINISHED_JOBS_KEEP_LATEST"] == "2000"


def test_service_wrapper_uses_single_worker_production_server(tmp_path):
    wrapper = tmp_path / "run.sh"
    installer_call(
        'NMAP_DATA_DIR="/usr/local/share/nmap"; build_wrapper "$TEST_WRAPPER"',
        {"TEST_WRAPPER": str(wrapper)},
    )
    content = wrapper.read_text()
    assert '"$python_bin" -m gunicorn' in content
    assert '--workers 1 --threads 100' in content
    assert 'nmapui.wsgi:application' in content
    assert 'export NMAPDIR=/usr/local/share/nmap' in content
    assert 'exec "$python_bin" "$app_path"' not in content
    assert 'bind_host="${NMAPUI_HOST:-127.0.0.1}"' in content
    assert 'bind_host="[$bind_host]"' in content


def test_macos_wrapper_brackets_ipv6_gunicorn_bind(tmp_path):
    root = tmp_path / "release"
    root.mkdir()
    fake_python = root / "python"
    fake_python.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n")
    fake_python.chmod(0o755)
    credentials = root / "credentials.env"
    credentials.write_text("NMAPUI_HOST=::1\nNMAPUI_PORT=9000\n")
    wrapper = root / "nmapui-run"
    installer_call(
        'ROOT_DIR="$TEST_ROOT"; APP_PATH="$TEST_APP"; PYTHON_BIN="$TEST_PYTHON"\n'
        'CREDENTIALS_FILE="$TEST_CREDENTIALS"; build_wrapper "$TEST_WRAPPER"',
        {
            "TEST_ROOT": str(root),
            "TEST_APP": str(root / "app.py"),
            "TEST_PYTHON": str(fake_python),
            "TEST_CREDENTIALS": str(credentials),
            "TEST_WRAPPER": str(wrapper),
        },
    )

    result = subprocess.run(
        [str(wrapper)], text=True, capture_output=True, timeout=5, check=True,
    )

    assert "--bind [::1]:9000" in result.stdout


def test_installer_rejects_unmanaged_listener_before_installing(tmp_path):
    credentials = tmp_path / "credentials.env"
    credentials.write_text("NMAPUI_PORT=9000\n")
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'CREDENTIALS_FILE="$TEST_CREDENTIALS"\n'
            'lsof() { return 0; }\n'
            'launchctl() { return 1; }\n'
            'check_port_conflict',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_CREDENTIALS": str(credentials)},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "already occupied by an unmanaged process" in result.stderr


def test_installer_rejects_symlinked_service_state(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "data").symlink_to(tmp_path)
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'DATA_DIR="$TEST_DATA"\n'
            'LOG_DIR="$TEST_LOGS"\n'
            'CREDENTIALS_FILE="$TEST_DATA/credentials.env"\n'
            'check_state_paths',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_DATA": str(data), "TEST_LOGS": str(tmp_path / "logs")},
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert "refusing symlinked service state path" in result.stderr


def test_release_switch_replaces_directory_symlink(tmp_path):
    old_release = tmp_path / "old-release"
    new_release = tmp_path / "new-release"
    old_release.mkdir()
    new_release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(old_release)

    installer_call(
        'INSTALL_ROOT="$TEST_ROOT"; ROOT_DIR="$TEST_ROOT/current"\n'
        'switch_release "$TEST_NEW_RELEASE"',
        {"TEST_ROOT": str(tmp_path), "TEST_NEW_RELEASE": str(new_release)},
    )

    assert current.is_symlink()
    assert current.resolve() == new_release
    assert not list(old_release.iterdir())


def test_release_switch_creates_first_current_link(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    installer_call(
        'INSTALL_ROOT="$TEST_ROOT"; ROOT_DIR="$TEST_ROOT/current"\n'
        'switch_release "$TEST_RELEASE"',
        {"TEST_ROOT": str(tmp_path), "TEST_RELEASE": str(release)},
    )
    assert (tmp_path / "current").is_symlink()
    assert (tmp_path / "current").resolve() == release


def test_mac_installer_rejects_unmanaged_release_path(tmp_path):
    releases = tmp_path / "releases"
    releases.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "release_id").write_text("identity\n")

    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'RELEASES_DIR="$TEST_ROOT/releases"; SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'validate_managed_release "$TEST_ROOT/outside"'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path)},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode != 0
    assert "outside the managed release directory" in result.stderr


def test_mac_installer_rejects_symlinked_installed_artifact(tmp_path):
    for name in ("nmapui-run", "helper", "sudoers", "nmapui.plist"):
        (tmp_path / name).write_text(name)
    (tmp_path / "helper").unlink()
    (tmp_path / "helper").symlink_to(tmp_path / "nmapui-run")

    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; HELPER_PATH="$TEST_ROOT/helper"\n'
         'SUDOERS_PATH="$TEST_ROOT/sudoers"; PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
         'SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'verify_installed_artifacts'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path)},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode != 0
    assert "missing or symlinked" in result.stderr


def test_mac_uninstall_preserves_data_and_release_archives(tmp_path):
    releases = tmp_path / "releases"
    release = releases / "current-release"
    release.mkdir(parents=True)
    (release / "release_id").write_text("identity\n")
    previous_release = releases / "previous-release"
    previous_release.mkdir()
    (previous_release / "release_id").write_text("older-identity\n")
    (tmp_path / "current").symlink_to(release)
    (tmp_path / "previous").symlink_to(previous_release)
    for name in ("nmapui-run", "helper", "sudoers", "nmapui.plist"):
        (tmp_path / name).write_text(name)
    (tmp_path / "nmapui-run").chmod(0o755)
    (tmp_path / "helper").chmod(0o755)
    data = tmp_path / "data"
    data.mkdir()
    (data / "history.json").write_text("history\n")
    launch_log = tmp_path / "launch.log"

    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'RELEASES_DIR="$TEST_ROOT/releases"; ROOT_DIR="$TEST_ROOT/current"\n'
         'PREVIOUS_LINK="$TEST_ROOT/previous"\n'
         'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; HELPER_PATH="$TEST_ROOT/helper"\n'
         'SUDOERS_PATH="$TEST_ROOT/sudoers"; PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
         'SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'require_root() { :; }\n'
         'launchctl() { printf "%s\\n" "$*" >> "$TEST_LOG"; return 0; }\n'
         'uninstall'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_LOG": str(launch_log)},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    for name in ("current", "previous", "nmapui-run", "helper", "sudoers", "nmapui.plist"):
        assert not (tmp_path / name).exists()
    assert release.is_dir()
    assert previous_release.is_dir()
    assert (data / "history.json").read_text() == "history\n"
    assert "bootout system/com.techmore.nmapui" in launch_log.read_text()


def test_mac_uninstall_refuses_unmanaged_plist(tmp_path):
    plist = tmp_path / "nmapui.plist"
    plist.write_text("unmanaged plist\n")
    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'ROOT_DIR="$TEST_ROOT/current"; PREVIOUS_LINK="$TEST_ROOT/previous"\n'
         'PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
         'SUDOERS_PATH="$TEST_ROOT/sudoers"; WRAPPER_PATH="$TEST_ROOT/nmapui-run"\n'
         'HELPER_PATH="$TEST_ROOT/helper"\n'
         'require_root() { :; }\n'
         'launchctl() { echo called >> "$TEST_LOG"; return 0; }\n'
         'uninstall'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_LOG": str(tmp_path / "launch.log")},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode != 0
    assert "without a managed current release" in result.stderr
    assert plist.read_text() == "unmanaged plist\n"
    assert not (tmp_path / "launch.log").exists()


def test_mac_upgrade_rejects_daemon_user_change_before_data_chown(tmp_path):
    plist = tmp_path / "nmapui.plist"
    with plist.open("wb") as stream:
        plistlib.dump({"UserName": "scanner"}, stream)

    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'SOURCE_PYTHON_BIN="$TEST_PYTHON"; PLIST_PATH="$TEST_PLIST"; RUN_USER=root\n'
         'check_existing_run_user'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_PLIST": str(plist),
             "TEST_PYTHON": sys.executable},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode != 0
    assert "changing daemon user from scanner to root" in result.stderr


def test_mac_upgrade_accepts_unchanged_daemon_user(tmp_path):
    plist = tmp_path / "nmapui.plist"
    with plist.open("wb") as stream:
        plistlib.dump({"UserName": "scanner"}, stream)

    installer_call(
        'SOURCE_PYTHON_BIN="$TEST_PYTHON"; PLIST_PATH="$TEST_PLIST"; RUN_USER=scanner\n'
        'check_existing_run_user',
        {"TEST_PLIST": str(plist), "TEST_PYTHON": sys.executable},
    )


def _prepare_mac_release_pair(tmp_path):
    releases = tmp_path / "releases"
    current_release = releases / "current-release"
    previous_release = releases / "previous-release"
    names = ("nmapui-run", "nmapui-privileged-scanner", "nmapui.sudoers", "com.techmore.nmapui.plist")
    for release, label in ((current_release, "current"), (previous_release, "previous")):
        artifacts = release / "service-artifacts"
        artifacts.mkdir(parents=True)
        (release / "release_id").write_text(label)
        for name in names:
            (artifacts / name).write_text(f"{label} {name}\n")
    (tmp_path / "current").symlink_to(current_release)
    (tmp_path / "previous").symlink_to(previous_release)
    installed_names = ("nmapui-run", "helper", "sudoers", "nmapui.plist")
    for installed, archived in zip(installed_names, names):
        (tmp_path / installed).write_text(f"current {archived}\n")
    return current_release, previous_release, names, installed_names


def test_mac_service_artifacts_are_archived_once_per_release(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    names = ("wrapper", "helper", "sudoers", "plist")
    for name in names:
        (tmp_path / name).write_text(f"{name} content\n")
    script = (
        'source "$INSTALLER"\n'
        'install() {\n'
        '  if [[ "$1" == -d ]]; then mkdir -p "$8"; else cp "$7" "$8"; chmod "$2" "$8"; fi\n'
        '}\n'
        'save_release_artifacts "$TEST_RELEASE" "$TEST_ROOT/wrapper" "$TEST_ROOT/helper" '
        '"$TEST_ROOT/sudoers" "$TEST_ROOT/plist"'
    )
    environment = {**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
                   "TEST_RELEASE": str(release)}

    first = subprocess.run(["bash", "-c", script], env=environment, text=True, capture_output=True, timeout=10)
    second = subprocess.run(["bash", "-c", script], env=environment, text=True, capture_output=True, timeout=10)

    assert first.returncode == 0, first.stderr
    artifacts = release / "service-artifacts"
    assert (artifacts / "nmapui-run").read_text() == "wrapper content\n"
    assert (artifacts / "nmapui-privileged-scanner").read_text() == "helper content\n"
    assert (artifacts / "nmapui.sudoers").read_text() == "sudoers content\n"
    assert (artifacts / "com.techmore.nmapui.plist").read_text() == "plist content\n"
    assert artifacts.joinpath("nmapui.sudoers").stat().st_mode & 0o777 == 0o440
    assert second.returncode != 0
    assert "refusing to overwrite" in second.stderr


def _rollback_mac_release(tmp_path, *, fail_first_bootstrap=False):
    return subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'INSTALL_ROOT="$TEST_ROOT"; RELEASES_DIR="$TEST_ROOT/releases"\n'
         'ROOT_DIR="$TEST_ROOT/current"; PREVIOUS_LINK="$TEST_ROOT/previous"\n'
         'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; HELPER_PATH="$TEST_ROOT/helper"\n'
         'SUDOERS_PATH="$TEST_ROOT/sudoers"; PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
         'SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'require_root() { :; }; verify_service_toolchain() { :; }\n'
         'validate_managed_release() { :; }; verify_installed_artifacts() { :; }\n'
         'verify_release_artifacts() { :; }; check_port_conflict() { :; }\n'
         'read_plist_run_user() { echo scanner; }; read_service_port() { echo 9000; }\n'
         'install() { cp "$7" "$8"; chmod "$2" "$8"; }\n'
         'bootstrap_count=0\n'
         'launchctl() {\n'
         '  [[ "$1" == print ]] && return 0\n'
         '  printf "%s\\n" "$*" >> "$TEST_LOG"\n'
         '  if [[ "$1" == bootstrap ]]; then\n'
         '    bootstrap_count=$((bootstrap_count + 1))\n'
         '    if [[ "$TEST_FAIL_BOOTSTRAP" == 1 && "$bootstrap_count" == 1 ]]; then return 1; fi\n'
         '  fi\n'
         '  return 0\n'
         '}\n'
         'rollback_daemon'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_LOG": str(tmp_path / "launch.log"),
             "TEST_FAIL_BOOTSTRAP": "1" if fail_first_bootstrap else "0"},
        text=True, capture_output=True, timeout=10,
    )


def test_mac_manual_rollback_restores_previous_artifacts_and_swaps_links(tmp_path):
    current_release, previous_release, names, installed_names = _prepare_mac_release_pair(tmp_path)

    result = _rollback_mac_release(tmp_path)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "current").resolve() == previous_release
    assert (tmp_path / "previous").resolve() == current_release
    for installed, archived in zip(installed_names, names):
        assert (tmp_path / installed).read_text() == f"previous {archived}\n"
    log = (tmp_path / "launch.log").read_text()
    assert log.index("bootout system/com.techmore.nmapui") < log.index("bootstrap system")


def test_failed_mac_manual_rollback_restores_active_artifacts_and_links(tmp_path):
    current_release, previous_release, names, installed_names = _prepare_mac_release_pair(tmp_path)

    result = _rollback_mac_release(tmp_path, fail_first_bootstrap=True)

    assert result.returncode != 0
    assert (tmp_path / "current").resolve() == current_release
    assert (tmp_path / "previous").resolve() == previous_release
    for installed, archived in zip(installed_names, names):
        assert (tmp_path / installed).read_text() == f"current {archived}\n"
    log = (tmp_path / "launch.log").read_text()
    assert log.count("bootstrap system") == 2
    assert "restoring installed artifacts" in result.stdout


def test_failed_upgrade_restores_launcher_and_previous_release(tmp_path):
    old_release = tmp_path / "old-release"
    new_release = tmp_path / "new-release"
    old_release.mkdir()
    new_release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(old_release)
    wrapper = tmp_path / "nmapui-run"
    wrapper.write_text("old launcher\n")
    wrapper.chmod(0o755)
    plist = tmp_path / "nmapui.plist"
    plist.write_text("old plist\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    launch_log = tmp_path / "launch.log"
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'INSTALL_ROOT="$TEST_ROOT"; ROOT_DIR="$TEST_ROOT/current"\n'
            'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; HELPER_PATH="$TEST_ROOT/helper"\n'
            'SUDOERS_PATH="$TEST_ROOT/sudoers"; PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
            'INSTALL_BACKUP_DIR="$TEST_ROOT/backup"\n'
            'backup_installed_artifacts "$INSTALL_BACKUP_DIR"\n'
            'printf "new launcher\\n" > "$WRAPPER_PATH"\n'
            'printf "new helper\\n" > "$HELPER_PATH"\n'
            'rm "$ROOT_DIR"; ln -s "$TEST_ROOT/new-release" "$ROOT_DIR"\n'
            'INSTALL_MUTATED=1; INSTALL_SWITCHED=1; INSTALL_PREVIOUS_LOADED=1\n'
            'INSTALL_PREVIOUS_RELEASE="$TEST_ROOT/old-release"\n'
            'launchctl() { printf "%s\\n" "$*" >> "$TEST_LOG"; return 0; }\n'
            'rollback_failed_install 1',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path), "TEST_LOG": str(launch_log)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert current.resolve() == old_release
    assert wrapper.read_text() == "old launcher\n"
    assert wrapper.stat().st_mode & 0o777 == 0o755
    assert plist.read_text() == "old plist\n"
    assert not (tmp_path / "helper").exists()
    assert not backup.exists()
    assert "bootstrap system" in launch_log.read_text()


def test_failed_first_install_leaves_no_boot_service(tmp_path):
    new_release = tmp_path / "new-release"
    new_release.mkdir()
    (tmp_path / "current").symlink_to(new_release)
    (tmp_path / "nmapui-run").write_text("new launcher\n")
    (tmp_path / "nmapui.plist").write_text("new plist\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'ROOT_DIR="$TEST_ROOT/current"\n'
            'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; HELPER_PATH="$TEST_ROOT/helper"\n'
            'SUDOERS_PATH="$TEST_ROOT/sudoers"; PLIST_PATH="$TEST_ROOT/nmapui.plist"\n'
            'INSTALL_BACKUP_DIR="$TEST_ROOT/backup"\n'
            'touch "$INSTALL_BACKUP_DIR/0.absent" "$INSTALL_BACKUP_DIR/1.absent"\n'
            'touch "$INSTALL_BACKUP_DIR/2.absent" "$INSTALL_BACKUP_DIR/3.absent"\n'
            'INSTALL_MUTATED=1; INSTALL_SWITCHED=1; INSTALL_PREVIOUS_LOADED=0\n'
            'INSTALL_PREVIOUS_RELEASE=""\n'
            'launchctl() { return 0; }\n'
            'rollback_failed_install 1',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert not (tmp_path / "current").exists()
    assert not (tmp_path / "nmapui-run").exists()
    assert not (tmp_path / "nmapui.plist").exists()
    assert not backup.exists()
