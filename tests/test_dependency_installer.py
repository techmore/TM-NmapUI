"""Exercise dependency setup without touching Homebrew, Python environments or services."""

import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_supported_installer_never_installs_unused_go_stack(tmp_path):
    project = tmp_path / "checkout with spaces"
    project.mkdir()
    shutil.copy2(ROOT / "install.sh", project / "install.sh")
    (project / "requirements.txt").write_text("fixture==1\n")
    stub_dir = tmp_path / "tools"
    stub_dir.mkdir()
    log = tmp_path / "calls"

    def stub(name, body):
        path = stub_dir / name
        path.write_text('#!/bin/bash\nset -eu\n' + body)
        path.chmod(0o755)

    stub("brew", 'printf "brew %s\\n" "$*" >> "$INSTALL_TEST_LOG"\n'
         'if [[ "${1:-}" == list ]]; then exit 1; fi\n')
    stub("python3", 'printf "python3 %s\\n" "$*" >> "$INSTALL_TEST_LOG"\n'
         '[[ "$1 $2" == "-m venv" ]]\n'
         'mkdir -p "$3/bin"\n'
         'printf ":\\n" > "$3/bin/activate"\n')
    stub("python", 'printf "python %s\\n" "$*" >> "$INSTALL_TEST_LOG"\n')
    for name in ("nmap", "xsltproc"):
        stub(name, 'echo "fixture version"\n')
    for name in ("go", "gowitness", "curl", "sudo"):
        stub(name, f'echo "Unexpected dependency or service action: {name}" >&2\nexit 97\n')

    result = subprocess.run(
        ["/bin/bash", str(project / "install.sh"), "--no-daemon"],
        env={**os.environ, "PATH": f"{stub_dir}:/usr/bin:/bin", "INSTALL_TEST_LOG": str(log)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text().splitlines()
    assert {line for line in calls if line.startswith("brew install ")} == {
        "brew install nmap", "brew install libxslt", "brew install python",
        "brew install arp-scan", "brew install wkhtmltopdf",
    }
    assert f"python -m pip install -r {project}/requirements.txt" in calls
    assert "python -m playwright install chromium" in calls
    assert "[6/6] Service installation" in result.stdout
