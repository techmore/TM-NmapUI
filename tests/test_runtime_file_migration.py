from customer_fingerprint import CustomerFingerprinter
import customer_fingerprint
from nmapui import paths


def test_legacy_customer_drive_and_history_files_move_to_runtime_data(tmp_path, monkeypatch):
    source = tmp_path / "checkout"
    data = tmp_path / "service-data"
    (source / "config").mkdir(parents=True)
    (source / "data").mkdir()
    (source / "config" / "customers.yaml").write_text("customers", encoding="utf-8")
    (source / "config" / "google_drive_credentials.json").write_text("drive", encoding="utf-8")
    (source / "data" / "scan_history.json").write_text("history", encoding="utf-8")
    monkeypatch.setattr(paths, "BASE_DIR", source)
    monkeypatch.setattr(paths, "CUSTOMER_CONFIG_FILE", data / "customers.yaml")
    monkeypatch.setattr(paths, "GOOGLE_DRIVE_CREDENTIALS_FILE", data / "google_drive_credentials.json")
    monkeypatch.setattr(paths, "SCAN_HISTORY_FILE", data / "scan_history.json")

    paths.migrate_legacy_runtime_files()

    assert (data / "customers.yaml").read_text() == "customers"
    assert (data / "google_drive_credentials.json").read_text() == "drive"
    assert (data / "scan_history.json").read_text() == "history"
    assert all(path.stat().st_mode & 0o077 == 0 for path in data.iterdir())

    (data / "customers.yaml").write_text("newer", encoding="utf-8")
    paths.migrate_legacy_runtime_files()
    assert (data / "customers.yaml").read_text() == "newer"


def test_relative_customer_history_stays_in_runtime_data(tmp_path, monkeypatch):
    monkeypatch.setattr(customer_fingerprint, "DATA_DIR", tmp_path)
    fingerprinter = CustomerFingerprinter.__new__(CustomerFingerprinter)
    fingerprinter.config = {"indexing": {"storage_path": "data/scan_history.json"}}

    assert fingerprinter._scan_history_path() == tmp_path / "scan_history.json"
