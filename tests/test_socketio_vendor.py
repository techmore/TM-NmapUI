"""Verify the shipped upstream SDK is exactly the reviewed privacy patch."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "packaging/macos/Vendor/SocketIO"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_vendor_patch_and_provenance_are_complete(tmp_path):
    provenance = json.loads((VENDOR / "PROVENANCE.json").read_text())
    assert provenance["upstream"] == "https://github.com/socketio/socket.io-client-swift"
    assert provenance["revision"] == "42da871d9369f290d6ec4930636c40672143905b"
    actual = {str(path.relative_to(VENDOR)) for path in (VENDOR / "Sources").rglob("*") if path.is_file()} | {"Package.swift", "LICENSE"}
    assert actual == set(provenance["files"])
    for name, expected in provenance["files"].items():
        source = VENDOR / name
        assert digest(source) == expected["vendored_sha256"], name
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    subprocess.run(["patch", "--batch", "--reverse", "-p1", "-i", str(VENDOR / "privacy-session.patch")], cwd=tmp_path, check=True)
    for name, expected in provenance["files"].items():
        assert digest(tmp_path / name) == expected["upstream_sha256"], name
    licenses = ROOT / "packaging/macos/Sources/NmapUIApp/Assets/ThirdPartyLicenses"
    assert (licenses / "SocketIO-MIT.txt").read_bytes() == (VENDOR / "LICENSE").read_bytes()
    assert "Apache License" in (licenses / "Starscream-Apache-2.0.txt").read_text()
    resolved = json.loads((ROOT / "packaging/macos/Package.resolved").read_text())
    assert [(pin["identity"], pin["state"]["revision"]) for pin in resolved["pins"]] == [("starscream", "c6bfd1af48efcc9a9ad203665db12375ba6b145a")]
