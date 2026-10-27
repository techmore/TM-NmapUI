import json

import pytest

from persistence import iter_scan_metadata_documents, save_json_document
from nmapui import private_storage
from nmapui.state import get_report_counts


def test_atomic_state_write_preserves_previous_document_on_sync_failure(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    save_json_document(path, {"enabled": False})

    def fail_sync(_file_descriptor):
        raise OSError("sync failed")

    monkeypatch.setattr(private_storage.os, "fsync", fail_sync)
    with pytest.raises(OSError, match="sync failed"):
        save_json_document(path, {"enabled": True})

    assert json.loads(path.read_text()) == {"enabled": False}
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".settings.json.*.tmp"))


def test_iter_scan_metadata_documents_skips_invalid_entries_and_normalizes(tmp_path):
    scans_dir = tmp_path / "scans"
    valid_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    invalid_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    valid_dir.mkdir(parents=True)
    invalid_dir.mkdir(parents=True)

    (valid_dir / "metadata.json").write_text('{"customer_name":"Acme","timestamp":"2026-03-13T01:00:00"}')
    (invalid_dir / "metadata.json").write_text("{not-json")

    logger_calls = []

    documents = list(
        iter_scan_metadata_documents(
            scans_dir,
            lambda path, default: __import__("json").loads(path.read_text()),
            lambda value: value,
            logger=type(
                "LoggerStub",
                (),
                {"error": lambda self, message, path, exc: logger_calls.append((message, path.name, type(exc).__name__))},
            )(),
        )
    )

    assert len(documents) == 1
    assert documents[0][0] == valid_dir / "metadata.json"
    assert documents[0][1]["customer_name"] == "Acme"
    assert logger_calls == [("Error reading metadata at %s: %s", "metadata.json", "JSONDecodeError")]


def test_get_report_counts_ignores_invalid_metadata_files(tmp_path):
    scans_dir = tmp_path / "scans"
    good_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    bad_dir = scans_dir / "Broken" / "2026-03-13" / "scan_020000_target"
    good_dir.mkdir(parents=True)
    bad_dir.mkdir(parents=True)

    (good_dir / "metadata.json").write_text(
        '{"customer_name":"Acme (0.82)","timestamp":"2026-03-13T01:00:00"}'
    )
    (bad_dir / "metadata.json").write_text("{not-json")

    counts = get_report_counts(
        scans_dir,
        lambda value: value,
        lambda path, default: __import__("json").loads(path.read_text()),
    )

    assert counts["Acme"] == 1
    assert counts["total"] == 1
    assert counts["last_scans"]["Acme"] == "2026-03-13T01:00:00"


def test_iter_scan_metadata_documents_builds_index_file_on_first_read(tmp_path):
    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True)
    (scan_dir / "metadata.json").write_text(
        '{"customer_name":"Acme","timestamp":"2026-03-13T01:00:00"}'
    )

    documents = list(
        iter_scan_metadata_documents(
            scans_dir,
            lambda path, default: json.loads(path.read_text()),
            lambda value: value,
        )
    )

    index_path = scans_dir / ".scan_metadata_index.json"
    index = json.loads(index_path.read_text())

    assert documents[0][0] == scan_dir / "metadata.json"
    assert index["entries"][0]["path"] == "Acme/2026-03-13/scan_010000_target"
    assert index["entries"][0]["metadata"]["customer_name"] == "Acme"


def test_iter_scan_metadata_documents_prefers_existing_index(tmp_path):
    scans_dir = tmp_path / "scans"
    scan_dir = scans_dir / "Acme" / "2026-03-13" / "scan_010000_target"
    scan_dir.mkdir(parents=True)
    (scan_dir / "metadata.json").write_text('{"customer_name":"Wrong"}')
    (scans_dir / ".scan_metadata_index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "path": "Acme/2026-03-13/scan_010000_target",
                        "metadata": {
                            "customer_name": "Indexed Acme",
                            "timestamp": "2026-03-13T01:00:00",
                        },
                        "has_html": False,
                        "has_pdf": False,
                        "has_xml": False,
                    }
                ],
            }
        )
    )

    def load_document(path, default):
        if path.name == "metadata.json":
            raise AssertionError("metadata file should not be read when index exists")
        return json.loads(path.read_text())

    documents = list(
        iter_scan_metadata_documents(
            scans_dir,
            load_document,
            lambda value: value,
        )
    )

    assert documents == [
        (
            scan_dir / "metadata.json",
            {
                "schema_version": 1,
                "customer_name": "Indexed Acme",
                "customer_id": "",
                "target": "",
                "timestamp": "2026-03-13T01:00:00",
                "date": "",
                "time": "",
                "scan_start_time": None,
                "scan_end_time": None,
                "duration_seconds": None,
                "duration_formatted": None,
                "network_key": {},
                "customer_info": {},
                "files": {},
                "status": "",
                "failure_stage": "",
                "failure_error": "",
                "completed_successfully": None,
                "diff_summary": None,
                "diff_summary_computed": False,
            },
        )
    ]
