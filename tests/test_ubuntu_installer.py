"""Validate generated Ubuntu service artifacts without installing a unit."""

import os
from pathlib import Path
import subprocess


INSTALLER = Path(__file__).resolve().parents[1] / "packaging" / "ubuntu" / "install-service.sh"


def _installer_call(script, env):
    return subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n' + script],
        env={**os.environ, "INSTALLER": str(INSTALLER), **env},
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )


def test_ubuntu_unit_restarts_one_root_worker_and_contains_children(tmp_path):
    unit = tmp_path / "nmapui.service"
    _installer_call('build_unit "$TEST_UNIT"', {"TEST_UNIT": str(unit)})
    content = unit.read_text()

    assert "User=root" in content
    assert "ExecStart=/usr/local/bin/nmapui-run" in content
    assert "Restart=always" in content
    assert "KillMode=control-group" in content
    assert "ProtectSystem=strict" in content
    assert "ReadWritePaths=/var/lib/nmapui /var/log/nmapui" in content
    assert "EnvironmentFile=/etc/nmapui/nmapui.env" in content
    assert 'Environment="PATH=/usr/sbin:/usr/bin:/sbin:/bin"' in content


def test_privacy_defaults_disable_optional_egress_but_preserve_explicit_opt_in(tmp_path):
    credentials = tmp_path / "nmapui.env"
    credentials.write_text("NMAPUI_ENABLE_VULNERS=true\n")
    _installer_call(
        'CREDENTIALS_FILE="$TEST_CREDENTIALS"; ensure_privacy_safe_egress_defaults',
        {"TEST_CREDENTIALS": str(credentials)},
    )

    values = dict(
        line.split("=", 1) for line in credentials.read_text().splitlines()
    )
    assert values == {
        "NMAPUI_ENABLE_VULNERS": "true",
        "NMAPUI_ENABLE_NETWORK_FINGERPRINT": "false",
        "NMAPUI_ENABLE_UPDATE_CHECK": "false",
    }


def test_ubuntu_wrapper_uses_configured_bind_and_single_worker(tmp_path):
    wrapper = tmp_path / "nmapui-run"
    _installer_call('NMAP_DATA_DIR="/usr/share/nmap"; build_wrapper "$TEST_WRAPPER"', {"TEST_WRAPPER": str(wrapper)})
    content = wrapper.read_text()
    assert content.startswith("#!/bin/bash\n")
    assert 'bind_host="${NMAPUI_HOST:-127.0.0.1}"' in content
    assert 'bind_host="[$bind_host]"' in content
    assert '--bind "$bind_host:$port"' in content
    assert "--workers 1 --threads 100" in content
    assert "nmapui.wsgi:application" in content
    assert "export NMAPDIR=/usr/share/nmap" in content
    assert "export PATH=/usr/sbin:/usr/bin:/sbin:/bin" in content
    assert "export NMAPUI_PRIVILEGED_ASSETS=/opt/nmapui/current/privileged-assets" in content

    invalid = subprocess.run(
        [str(wrapper)],
        env={
            **os.environ,
            "PATH": str(tmp_path / "untrusted-bin"),
            "NMAPUI_PORT": "not-a-port",
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert invalid.returncode != 0
    assert "Invalid NMAPUI_PORT" in invalid.stderr


def test_ubuntu_wrapper_pins_privileged_assets_to_current_release(tmp_path):
    release = tmp_path / "current"
    python_bin = release / ".venv" / "bin" / "python"
    python_bin.parent.mkdir(parents=True)
    python_bin.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$NMAPUI_PRIVILEGED_ASSETS\"\n"
        "printf '%s\\n' \"$*\"\n"
    )
    python_bin.chmod(0o755)
    wrapper = tmp_path / "nmapui-run"
    _installer_call(
        'CURRENT_LINK="$TEST_RELEASE"; build_wrapper "$TEST_WRAPPER"',
        {"TEST_RELEASE": str(release), "TEST_WRAPPER": str(wrapper)},
    )

    result = subprocess.run(
        [str(wrapper)],
        env={
            **os.environ,
            "NMAPUI_PRIVILEGED_ASSETS": "/tmp/untrusted-assets",
            "NMAPUI_HOST": "::1",
        },
        text=True,
        capture_output=True,
        timeout=5,
        check=True,
    )

    assert result.stdout.splitlines()[0] == str(release / "privileged-assets")
    assert "--bind [::1]:9000" in result.stdout


def test_wait_ready_fails_fast_when_systemd_is_restarting_service(tmp_path):
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'SOURCE_PYTHON_BIN=/usr/bin/true; READY_CHECK_PATH=/usr/bin/true\n'
            'read_service_port() { echo 9000; }; read_service_host() { echo 127.0.0.1; }\n'
            'systemctl() { case "$1" in '
            'is-active) return 1 ;; '
            'show) echo auto-restart ;; '
            '*) return 1 ;; esac; }\n'
            'before="$SECONDS"\n'
            'if wait_ready "$TEST_ROOT/release" 180; then exit 1; fi\n'
            '[[ "$((SECONDS - before))" -lt 2 ]]',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr


def test_failed_ubuntu_rollback_restores_current_release(tmp_path):
    releases = tmp_path / "releases"
    releases.mkdir()
    current_release = releases / "current-release"
    previous_release = releases / "previous-release"
    for release, label in ((current_release, "current"), (previous_release, "previous")):
        (release / "service-artifacts").mkdir(parents=True)
        (release / "release_id").write_text(label)
        (release / "service-artifacts" / "nmapui-run").write_text(f"{label} launcher\n")
        (release / "service-artifacts" / "nmapui.service").write_text(f"{label} unit\n")
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    current.symlink_to(current_release)
    previous.symlink_to(previous_release)
    wrapper = tmp_path / "nmapui-run"
    wrapper.write_text("current launcher\n")
    wrapper.chmod(0o755)
    unit = tmp_path / "nmapui.service"
    unit.write_text("current unit\n")
    systemctl_log = tmp_path / "systemctl.log"
    readiness_log = tmp_path / "readiness.log"

    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'INSTALL_ROOT="$TEST_ROOT"\n'
            'RELEASES_DIR="$TEST_ROOT/releases"\n'
            'CURRENT_LINK="$TEST_ROOT/current"\n'
            'PREVIOUS_LINK="$TEST_ROOT/previous"\n'
            'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; UNIT_PATH="$TEST_ROOT/nmapui.service"\n'
            'SOURCE_PYTHON_BIN=/usr/bin/true\n'
            'require_root() { :; }\n'
            'switch_link() { ln -sfn "$2" "$1"; }\n'
            'install() { cp "$7" "$8"; chmod "$2" "$8"; }\n'
            'systemctl() { printf "%s\\n" "$*" >> "$TEST_SYSTEMCTL_LOG"; return 0; }\n'
            'ready_count=0\n'
            'wait_ready() { printf "%s %s\\n" "$1" "${2:-180}" >> "$TEST_READINESS_LOG"; '
            'ready_count=$((ready_count + 1)); (( ready_count > 1 )); }\n'
            'rollback',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_SYSTEMCTL_LOG": str(systemctl_log), "TEST_READINESS_LOG": str(readiness_log)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode != 0
    assert current.resolve() == current_release
    assert previous.resolve() == previous_release
    assert wrapper.read_text() == "current launcher\n"
    assert unit.read_text() == "current unit\n"
    assert "previous release did not become ready" in result.stderr
    assert "restoring previous systemd deployment" in result.stdout
    assert readiness_log.read_text().splitlines() == [f"{previous_release} 180", f"{current_release} 60"]
    assert "daemon-reload" in systemctl_log.read_text()


def test_successful_ubuntu_rollback_restores_release_service_files(tmp_path):
    releases = tmp_path / "releases"
    releases.mkdir()
    current_release = releases / "current-release"
    previous_release = releases / "previous-release"
    for release, label in ((current_release, "current"), (previous_release, "previous")):
        (release / "service-artifacts").mkdir(parents=True)
        (release / "release_id").write_text(label)
        (release / "service-artifacts" / "nmapui-run").write_text(f"{label} launcher\n")
        (release / "service-artifacts" / "nmapui.service").write_text(f"{label} unit\n")
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    current.symlink_to(current_release)
    previous.symlink_to(previous_release)
    wrapper = tmp_path / "nmapui-run"
    wrapper.write_text("current launcher\n")
    unit = tmp_path / "nmapui.service"
    unit.write_text("current unit\n")
    readiness_log = tmp_path / "readiness.log"

    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'INSTALL_ROOT="$TEST_ROOT"; RELEASES_DIR="$TEST_ROOT/releases"\n'
            'CURRENT_LINK="$TEST_ROOT/current"; PREVIOUS_LINK="$TEST_ROOT/previous"\n'
            'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; UNIT_PATH="$TEST_ROOT/nmapui.service"\n'
            'SOURCE_PYTHON_BIN=/usr/bin/true\n'
            'require_root() { :; }\n'
            'switch_link() { ln -sfn "$2" "$1"; }\n'
            'install() { cp "$7" "$8"; chmod "$2" "$8"; }\n'
            'systemctl() { return 0; }\n'
            'wait_ready() { printf "%s\\n" "$1" >> "$TEST_READINESS_LOG"; }\n'
            'rollback',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_READINESS_LOG": str(readiness_log)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert current.resolve() == previous_release
    assert previous.resolve() == current_release
    assert wrapper.read_text() == "previous launcher\n"
    assert unit.read_text() == "previous unit\n"
    assert readiness_log.read_text().splitlines() == [str(previous_release)]


def test_ubuntu_rejects_release_outside_managed_directory(tmp_path):
    (tmp_path / "releases").mkdir()
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


def test_ubuntu_rejects_symlinked_release_service_artifacts(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    artifacts = tmp_path / "elsewhere"
    artifacts.mkdir()
    (release / "service-artifacts").symlink_to(artifacts)
    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'verify_release_service_files "$TEST_RELEASE"'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_RELEASE": str(release)},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode != 0
    assert "missing or symlinked" in result.stderr


def test_ubuntu_uninstall_preserves_data_and_releases(tmp_path):
    releases = tmp_path / "releases"
    current_release = releases / "current-release"
    current_release.mkdir(parents=True)
    (current_release / "release_id").write_text("identity\n")
    (tmp_path / "current").symlink_to(current_release)
    (tmp_path / "nmapui-run").write_text("launcher\n")
    (tmp_path / "nmapui.service").write_text("unit\n")
    data = tmp_path / "data"
    data.mkdir()
    (data / "history.json").write_text("history\n")
    systemctl_log = tmp_path / "systemctl.log"

    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'RELEASES_DIR="$TEST_ROOT/releases"; CURRENT_LINK="$TEST_ROOT/current"\n'
         'PREVIOUS_LINK="$TEST_ROOT/previous"; WRAPPER_PATH="$TEST_ROOT/nmapui-run"\n'
         'UNIT_PATH="$TEST_ROOT/nmapui.service"; SOURCE_PYTHON_BIN=/usr/bin/true\n'
         'require_root() { :; }\n'
         'systemctl() { printf "%s\\n" "$*" >> "$TEST_LOG"; return 0; }\n'
         'uninstall_service'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_LOG": str(systemctl_log)},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "current").exists()
    assert not (tmp_path / "nmapui-run").exists()
    assert not (tmp_path / "nmapui.service").exists()
    assert current_release.is_dir()
    assert (data / "history.json").read_text() == "history\n"
    assert "stop nmapui.service" in systemctl_log.read_text()
    assert "disable nmapui.service" in systemctl_log.read_text()
    assert "daemon-reload" in systemctl_log.read_text()


def test_ubuntu_uninstall_refuses_unmanaged_service_files(tmp_path):
    unit = tmp_path / "nmapui.service"
    unit.write_text("unmanaged unit\n")
    result = subprocess.run(
        ["bash", "-c", 'source "$INSTALLER"\n'
         'CURRENT_LINK="$TEST_ROOT/current"; PREVIOUS_LINK="$TEST_ROOT/previous"\n'
         'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; UNIT_PATH="$TEST_ROOT/nmapui.service"\n'
         'require_root() { :; }\n'
         'systemctl() { echo called >> "$TEST_LOG"; return 0; }\n'
         'uninstall_service'],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path),
             "TEST_LOG": str(tmp_path / "systemctl.log")},
        text=True, capture_output=True, timeout=10,
    )

    assert result.returncode != 0
    assert "without a managed current release" in result.stderr
    assert unit.read_text() == "unmanaged unit\n"
    assert not (tmp_path / "systemctl.log").exists()


def test_failed_ubuntu_upgrade_restores_unit_launcher_and_release(tmp_path):
    old_release = tmp_path / "old-release"
    new_release = tmp_path / "new-release"
    old_release.mkdir()
    new_release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(old_release)
    wrapper = tmp_path / "nmapui-run"
    wrapper.write_text("old launcher\n")
    wrapper.chmod(0o755)
    unit = tmp_path / "nmapui.service"
    unit.write_text("old unit\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    systemctl_log = tmp_path / "systemctl.log"
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'INSTALL_ROOT="$TEST_ROOT"; CURRENT_LINK="$TEST_ROOT/current"\n'
            'WRAPPER_PATH="$TEST_ROOT/nmapui-run"; UNIT_PATH="$TEST_ROOT/nmapui.service"\n'
            'INSTALL_BACKUP_DIR="$TEST_ROOT/backup"\n'
            'backup_service_files "$INSTALL_BACKUP_DIR"\n'
            'printf "new launcher\\n" > "$WRAPPER_PATH"\n'
            'printf "new unit\\n" > "$UNIT_PATH"\n'
            'rm "$CURRENT_LINK"; ln -s "$TEST_ROOT/new-release" "$CURRENT_LINK"\n'
            'INSTALL_MUTATED=1; INSTALL_SWITCHED=1; INSTALL_OLD_ACTIVE=1; INSTALL_OLD_ENABLED=1\n'
            'INSTALL_OLD_RELEASE="$TEST_ROOT/old-release"\n'
            'switch_link() { ln -sfn "$2" "$1"; }\n'
            'systemctl() { printf "%s\\n" "$*" >> "$TEST_LOG"; return 0; }\n'
            'wait_ready() { [[ "$1" == "$TEST_ROOT/old-release" && "$2" == 60 ]]; }\n'
            'rollback_failed_install 1',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path), "TEST_LOG": str(systemctl_log)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert current.resolve() == old_release
    assert wrapper.read_text() == "old launcher\n"
    assert wrapper.stat().st_mode & 0o777 == 0o755
    assert unit.read_text() == "old unit\n"
    assert not backup.exists()
    assert "daemon-reload" in systemctl_log.read_text()
    assert "start nmapui.service" in systemctl_log.read_text()


def test_failed_first_ubuntu_install_removes_boot_service(tmp_path):
    new_release = tmp_path / "new-release"
    new_release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(new_release)
    wrapper = tmp_path / "nmapui-run"
    wrapper.write_text("new launcher\n")
    unit = tmp_path / "nmapui.service"
    unit.write_text("new unit\n")
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "0.absent").touch()
    (backup / "1.absent").touch()
    result = subprocess.run(
        [
            "bash", "-c",
            'source "$INSTALLER"\n'
            'CURRENT_LINK="$TEST_ROOT/current"; WRAPPER_PATH="$TEST_ROOT/nmapui-run"\n'
            'UNIT_PATH="$TEST_ROOT/nmapui.service"; INSTALL_BACKUP_DIR="$TEST_ROOT/backup"\n'
            'INSTALL_MUTATED=1; INSTALL_SWITCHED=1; INSTALL_OLD_ACTIVE=0; INSTALL_OLD_ENABLED=0\n'
            'INSTALL_OLD_RELEASE=""\n'
            'systemctl() { return 0; }\n'
            'rollback_failed_install 1',
        ],
        env={**os.environ, "INSTALLER": str(INSTALLER), "TEST_ROOT": str(tmp_path)},
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 1
    assert not current.exists()
    assert not wrapper.exists()
    assert not unit.exists()
    assert not backup.exists()
