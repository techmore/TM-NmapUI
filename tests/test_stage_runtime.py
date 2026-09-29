import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

STAGER_PATH = Path(__file__).resolve().parents[1] / "packaging" / "stage_runtime.py"
SPEC = importlib.util.spec_from_file_location("nmapui_stage_runtime", STAGER_PATH)
STAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGER)
RUNTIME_DIRS = STAGER.RUNTIME_DIRS
RUNTIME_FILES = STAGER.RUNTIME_FILES
stage_runtime = STAGER.stage_runtime
verify_root_interpreter = STAGER.verify_root_interpreter
verify_root_executable = STAGER.verify_root_executable
verify_root_file = STAGER.verify_root_file
verify_root_nmap_data_dir = STAGER.verify_root_nmap_data_dir


def _source_tree(root: Path) -> Path:
    root.mkdir()
    for name in RUNTIME_FILES:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(name, encoding="utf-8")
    for name in RUNTIME_DIRS:
        (root / name).mkdir()
        (root / name / "asset.txt").write_text(name, encoding="utf-8")
    (root / "nmap-vulners" / "vulners.nse").write_text("nmap-vulners", encoding="utf-8")
    (root / "nmap-vulners" / "vulners_enterprise.nse").write_text(
        "unused enterprise scanner", encoding="utf-8"
    )
    (root / "nmap-vulners" / "example.png").write_bytes(b"unused example asset")
    (root / ".venv" / "bin").mkdir(parents=True)
    (root / ".venv" / "bin" / "python").symlink_to(sys.executable)
    return root


def test_stage_runtime_copies_only_service_files_and_hardens_modes(tmp_path):
    source = _source_tree(tmp_path / "source")
    (source / "static" / "js").mkdir(parents=True)
    (source / "static" / "js" / "report_runtime.js").write_text(
        "spreadsheetSafeText", encoding="utf-8"
    )
    (source / "static" / "css").mkdir(parents=True)
    (source / "static" / "css" / "tailwind.css").write_text(
        "compiled-report-css", encoding="utf-8"
    )
    (source / "data").mkdir()
    (source / "data" / "secret.txt").write_text("private", encoding="utf-8")
    (source / "config" / "customers.yaml").write_text("private", encoding="utf-8")
    (source / "app.py").chmod(0o600)
    destination = tmp_path / "release"

    stage_runtime(source, destination)

    assert (destination / "app.py").read_text() == "app.py"
    assert (destination / "nmapui" / "asset.txt").exists()
    assert (destination / "static" / "js" / "report_runtime.js").read_text() == (
        "spreadsheetSafeText"
    )
    assert (destination / "static" / "css" / "tailwind.css").read_text() == (
        "compiled-report-css"
    )
    assert (destination / "privileged-assets" / "vulners.nse").read_text() == "nmap-vulners"
    assert (destination / "privileged-assets" / "nmap-modern.xsl").read_text() == "nmap-modern.xsl"
    assert (destination / "nmap-vulners" / "LICENSE").is_file()
    assert (destination / "nmap-vulners" / "vulners.nse").read_text() == "nmap-vulners"
    assert not (destination / "nmap-vulners" / "vulners_enterprise.nse").exists()
    assert not (destination / "nmap-vulners" / "example.png").exists()
    assert (destination / ".venv" / "bin" / "python").is_file()
    assert len((destination / "release_id").read_text().strip()) == 32
    assert not (destination / "data").exists()
    assert not (destination / "config" / "customers.yaml").exists()
    assert destination.joinpath("app.py").stat().st_mode & 0o022 == 0
    assert destination.joinpath("app.py").stat().st_mode & 0o044 == 0o044
    assert destination.stat().st_mode & 0o055 == 0o055


def test_stage_runtime_rejects_symlinked_service_code(tmp_path):
    source = _source_tree(tmp_path / "source")
    (source / "app.py").unlink()
    (source / "app.py").symlink_to(tmp_path / "outside.py")

    with pytest.raises(ValueError, match="Service code cannot be a symlink"):
        stage_runtime(source, tmp_path / "release")
    assert not (tmp_path / "release").exists()


def test_stage_runtime_rejects_existing_destination(tmp_path):
    source = _source_tree(tmp_path / "source")
    destination = tmp_path / "release"
    destination.mkdir()

    with pytest.raises(FileExistsError):
        stage_runtime(source, destination)


def test_root_service_rejects_user_owned_interpreter(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("Ownership check requires a non-root test runner")
    interpreter = tmp_path / "python"
    interpreter.write_text("not executable by the service", encoding="utf-8")
    interpreter.chmod(0o755)

    with pytest.raises(ValueError, match="not root-owned"):
        verify_root_interpreter(interpreter)


def test_root_service_rejects_user_owned_scanner_and_symlink(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("Ownership check requires a non-root test runner")
    executable = tmp_path / "nmap"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    link = tmp_path / "nmap-link"
    link.symlink_to(executable)

    with pytest.raises(ValueError, match="not root-owned"):
        verify_root_executable(executable)
    with pytest.raises(ValueError, match="not root-owned"):
        verify_root_executable(link)


def test_root_service_rejects_user_owned_systemd_unit(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("Ownership check requires a non-root test runner")
    unit = tmp_path / "nmapui.service"
    unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not root-owned"):
        verify_root_file(unit)


def test_root_service_accepts_protected_system_executable():
    assert verify_root_executable(Path("/usr/bin/true")).is_file()


def test_macho_dependency_check_rejects_user_owned_library(tmp_path, monkeypatch):
    dependency = tmp_path / "libscanner.dylib"
    dependency.write_text("not a trusted library", encoding="utf-8")
    monkeypatch.setattr(
        STAGER.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"/usr/bin/true:\n\t{dependency} (compatibility version 1.0.0)\n",
        ),
    )

    with pytest.raises(ValueError, match="not root-owned"):
        STAGER._verify_macho_dependencies(Path("/usr/bin/true"), seen=set())


def test_root_service_rejects_user_owned_nmap_scripts(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("Ownership check requires a non-root test runner")
    data = tmp_path / "share" / "nmap"
    (data / "scripts").mkdir(parents=True)
    (data / "nselib").mkdir()
    (data / "nmap-services").write_text("services", encoding="utf-8")
    (data / "nmap-os-db").write_text("os", encoding="utf-8")

    with pytest.raises(ValueError, match="not root-owned"):
        verify_root_nmap_data_dir(data)
