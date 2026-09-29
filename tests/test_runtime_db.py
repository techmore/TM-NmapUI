from contextlib import contextmanager
from pathlib import Path
import sqlite3
import threading

import pytest

from nmapui import runtime_db

from nmapui.runtime_db import (
    RUNTIME_DB_SCHEMA_VERSION,
    SCHEMA_STATEMENTS,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_JOURNAL_MODE,
    create_runtime_state_store,
)
from nmapui.maintenance import run_daily_runtime_maintenance


def test_runtime_state_store_initializes_schema_and_round_trips_snapshots(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_runtime_snapshot(
        "network_topology",
        {"target": "192.168.1.0/24", "total_hops": 4},
    )

    assert store.get_runtime_snapshot("network_topology") == {
        "target": "192.168.1.0/24",
        "total_hops": 4,
    }


def test_runtime_state_store_sets_schema_version_on_initialize(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    assert store.get_schema_version() == RUNTIME_DB_SCHEMA_VERSION


def test_runtime_state_store_upgrades_legacy_schema_version_zero(tmp_path: Path):
    db_path = tmp_path / "runtime.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE runtime_snapshots (
                key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO runtime_snapshots(key, payload_json, updated_at)
            VALUES (?, ?, ?)
            """,
            ("network_key", '{"public_ip": "203.0.113.10"}', "2026-03-15T00:00:00Z"),
        )
        conn.execute("PRAGMA user_version=0")
        conn.commit()
    finally:
        conn.close()

    store = create_runtime_state_store(db_path)

    assert store.get_schema_version() == RUNTIME_DB_SCHEMA_VERSION
    assert store.get_runtime_snapshot("network_key") == {"public_ip": "203.0.113.10"}


def test_existing_v1_database_gets_rollback_compatible_read_indexes(tmp_path: Path):
    db_path = tmp_path / "runtime.sqlite3"
    with sqlite3.connect(db_path) as conn:
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.execute("PRAGMA user_version=1")
        conn.execute(
            """
            INSERT INTO report_artifacts(scan_path, customer_id, payload_json, generated_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("old/scan", "cust-1", "{}", "2026-03-14T00:00:00+00:00", "2026-03-14T00:00:00+00:00"),
        )

    store = create_runtime_state_store(db_path)

    assert store.get_schema_version() == 1
    assert store.get_report_artifact("old/scan") is not None
    with store.connect() as conn:
        plans = {
            "reports_all": conn.execute(
                "EXPLAIN QUERY PLAN SELECT scan_path FROM report_artifacts ORDER BY generated_at DESC LIMIT 500"
            ).fetchall(),
            "reports_customer": conn.execute(
                "EXPLAIN QUERY PLAN SELECT scan_path FROM report_artifacts "
                "WHERE customer_id = ? ORDER BY generated_at DESC LIMIT 500",
                ("cust-1",),
            ).fetchall(),
            "jobs_recent": conn.execute(
                "EXPLAIN QUERY PLAN SELECT job_id FROM jobs "
                "WHERE status IN (?, ?) ORDER BY updated_at DESC, job_id DESC LIMIT 50",
                ("running", "cancelling"),
            ).fetchall(),
        }
    details = {name: " ".join(row[3] for row in rows) for name, rows in plans.items()}
    assert "idx_report_artifacts_generated" in details["reports_all"]
    assert "idx_report_artifacts_customer_generated" in details["reports_customer"]
    assert "idx_jobs_updated_id" in details["jobs_recent"]
    assert all("USE TEMP B-TREE" not in detail for detail in details.values())


def test_runtime_state_store_rejects_newer_unknown_schema_version(tmp_path: Path):
    db_path = tmp_path / "runtime.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"PRAGMA user_version={RUNTIME_DB_SCHEMA_VERSION + 1}")
        conn.commit()
    finally:
        conn.close()

    try:
        create_runtime_state_store(db_path)
    except RuntimeError as exc:
        assert "newer than this application supports" in str(exc)
    else:  # pragma: no cover - defensive failure path only
        raise AssertionError("Expected runtime store initialization to reject newer schema")


def test_runtime_state_store_tracks_jobs_reports_and_logs(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_job(
        job_id="job-1",
        owner_sid="sid-1",
        job_type="report",
        status="running",
        payload={"target": "192.168.1.0/24"},
    )
    store.upsert_report_artifact(
        scan_path="Acme/2026-03-14/scan_120000_192.168.1.0_24",
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )
    log_id = store.append_log(
        category="runtime",
        level="INFO",
        message="Hydrated network topology",
        payload={"target": "192.168.1.0/24"},
    )
    event_id = store.append_job_event(
        job_id="job-1",
        owner_sid="sid-1",
        job_type="report",
        event_name="scan_feedback",
        payload={"message": "Generating report"},
    )

    job = store.get_job("job-1")
    active_jobs = store.list_jobs(statuses=("running",), limit=10)
    events = store.list_job_events(job_id="job-1", limit=10)
    reports = store.list_report_artifacts(customer_id="cust-1")
    report = store.get_report_artifact("Acme/2026-03-14/scan_120000_192.168.1.0_24")
    logs = store.get_recent_logs(category="runtime", limit=10)

    assert job is not None
    assert job["job_type"] == "report"
    assert job["payload"]["target"] == "192.168.1.0/24"
    assert active_jobs[0]["job_id"] == "job-1"
    assert events[0]["id"] == event_id
    assert events[0]["event_name"] == "scan_feedback"
    assert events[0]["payload"]["message"] == "Generating report"
    assert report["scan_path"] == "Acme/2026-03-14/scan_120000_192.168.1.0_24"
    assert reports[0]["pdf_path"] == "scan_report.pdf"
    assert reports[0]["payload"]["status"] == "completed"
    assert logs[0]["id"] == log_id
    assert logs[0]["message"] == "Hydrated network topology"


def test_job_cursor_visits_equal_timestamp_rows_once(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    for index in range(5):
        store.upsert_job(
            job_id=f"job-{index}", owner_sid="sid", job_type="scan",
            status="running", payload={},
        )
    with store.connect() as conn:
        conn.execute("UPDATE jobs SET updated_at = '2026-09-26T00:00:00+00:00'")

    visited = []
    before = None
    while True:
        page = store.list_jobs(statuses=("running",), limit=2, before=before)
        if not page:
            break
        visited.extend(job["job_id"] for job in page)
        before = (page[-1]["updated_at"], page[-1]["job_id"])

    assert visited == ["job-4", "job-3", "job-2", "job-1", "job-0"]


def test_report_lists_omit_large_asset_snapshots_unless_requested(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    store.upsert_report_artifact(
        scan_path="Acme/scan-1",
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={
            "status": "completed",
            "asset_snapshot": [{"ip": "192.168.1.10"}],
        },
    )

    lightweight = store.list_report_artifacts()
    detailed = store.list_report_artifacts(include_asset_snapshot=True)

    assert "asset_snapshot" not in lightweight[0]["payload"]
    assert detailed[0]["payload"]["asset_snapshot"] == [{"ip": "192.168.1.10"}]


def test_finished_job_retention_keeps_active_jobs_and_removes_their_old_events(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    for job_id, status in (("old", "completed"), ("new", "failed"), ("active", "running")):
        store.upsert_job(
            job_id=job_id,
            owner_sid=job_id,
            job_type="report",
            status=status,
            payload={},
        )
        store.append_job_event(
            job_id=job_id,
            owner_sid=job_id,
            job_type="report",
            event_name="scan_feedback",
        )

    result = store.prune_finished_jobs(keep_latest=1)

    assert result == {"deleted_jobs": 1, "deleted_job_events": 1}
    assert store.get_job("old") is None
    assert store.list_job_events(job_id="old") == []
    assert store.get_job("new") is not None
    assert store.get_job("active") is not None


def test_automatic_retention_runs_once_per_day_and_skips_compaction(
    tmp_path: Path, monkeypatch
):
    from datetime import datetime, timezone
    import logging

    # Assert the test exercises production defaults even if the developer shell
    # has custom appliance settings exported.
    for setting in (
        "NMAPUI_RUNTIME_LOGS_KEEP_LATEST",
        "NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST",
        "NMAPUI_FINISHED_JOBS_KEEP_LATEST",
    ):
        monkeypatch.delenv(setting, raising=False)

    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    for index in range(3):
        store.append_log(category="runtime", level="INFO", message=str(index))
    first = run_daily_runtime_maintenance(
        runtime_store=store,
        logger=logging.getLogger(__name__),
        now=datetime(2026, 9, 25, 12, tzinfo=timezone.utc),
    )
    second = run_daily_runtime_maintenance(
        runtime_store=store,
        logger=logging.getLogger(__name__),
        now=datetime(2026, 9, 25, 15, tzinfo=timezone.utc),
    )

    assert first["run_date"] == "2026-09-25"
    assert first["deleted_jobs"] == 0
    assert second is None
    assert store.count_runtime_logs() == 3


def test_automatic_retention_records_status_without_deleting_saved_reports(
    tmp_path: Path, monkeypatch
):
    from datetime import datetime, timezone
    import logging

    monkeypatch.setenv("NMAPUI_RUNTIME_LOGS_KEEP_LATEST", "1")
    scans_root = tmp_path / "scans"
    report_dir = scans_root / "Example Customer" / "2026-09-27" / "scan_120000"
    report_dir.mkdir(parents=True)
    report_files = {
        "scan_web.html": "<html>saved report</html>",
        "scan_report.pdf": "%PDF-1.4\n",
        "scan.xml": "<nmaprun></nmaprun>",
    }
    for name, contents in report_files.items():
        (report_dir / name).write_text(contents, encoding="utf-8")

    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    scan_path = str(report_dir.relative_to(scans_root))
    store.upsert_report_artifact(
        scan_path=scan_path,
        customer_id="customer-1",
        target="192.0.2.0/24",
        html_path=str(report_dir / "scan_web.html"),
        pdf_path=str(report_dir / "scan_report.pdf"),
        xml_path=str(report_dir / "scan.xml"),
        payload={"status": "completed"},
    )
    for index in range(3):
        store.append_log(category="runtime", level="INFO", message=f"log-{index}")

    status = run_daily_runtime_maintenance(
        runtime_store=store,
        logger=logging.getLogger(__name__),
        now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc),
    )

    assert status["deleted_runtime_logs"] == 2
    assert store.get_runtime_snapshot("automatic_retention_status") == status
    assert store.get_report_artifact(scan_path) is not None
    assert {path.name: path.read_text(encoding="utf-8") for path in report_dir.iterdir()} == report_files


def test_daily_runtime_maintenance_uses_configured_retention_limits(monkeypatch, caplog):
    from datetime import datetime, timezone
    import logging

    class CapturingStore:
        def __init__(self):
            self.calls = {}
            self.snapshot = {}

        def get_runtime_snapshot(self, _key):
            return self.snapshot

        def apply_retention_policies(self, **kwargs):
            self.calls["retention"] = kwargs
            return {
                "deleted_runtime_logs": 0,
                "deleted_customer_scan_history": 0,
                "runtime_logs_keep_latest": kwargs["runtime_logs_keep_latest"],
                "customer_history_keep_latest": kwargs["customer_history_keep_latest"],
            }

        def prune_finished_jobs(self, **kwargs):
            self.calls["jobs"] = kwargs
            return {"deleted_jobs": 0, "deleted_job_events": 0}

        def upsert_runtime_snapshot(self, _key, value):
            self.snapshot = value

    monkeypatch.setenv("NMAPUI_RUNTIME_LOGS_KEEP_LATEST", "750")
    monkeypatch.setenv("NMAPUI_CUSTOMER_HISTORY_KEEP_LATEST", "125")
    monkeypatch.setenv("NMAPUI_FINISHED_JOBS_KEEP_LATEST", "400")
    store = CapturingStore()

    result = run_daily_runtime_maintenance(
        runtime_store=store,
        logger=logging.getLogger(__name__),
        now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc),
    )

    assert store.calls["retention"] == {
        "runtime_logs_keep_latest": 750,
        "customer_history_keep_latest": 125,
        "compact": False,
    }
    assert store.calls["jobs"] == {"keep_latest": 400}
    assert result["finished_jobs_keep_latest"] == 400


def test_daily_runtime_maintenance_falls_back_on_invalid_retention_limit(
    monkeypatch, caplog
):
    from datetime import datetime, timezone
    import logging

    class CapturingStore:
        def __init__(self):
            self.calls = {}

        def get_runtime_snapshot(self, _key):
            return {}

        def apply_retention_policies(self, **kwargs):
            self.calls["retention"] = kwargs
            return {
                "deleted_runtime_logs": 0,
                "deleted_customer_scan_history": 0,
                "runtime_logs_keep_latest": kwargs["runtime_logs_keep_latest"],
                "customer_history_keep_latest": kwargs["customer_history_keep_latest"],
            }

        def prune_finished_jobs(self, **kwargs):
            self.calls["jobs"] = kwargs
            return {"deleted_jobs": 0, "deleted_job_events": 0}

        def upsert_runtime_snapshot(self, _key, _value):
            pass

    monkeypatch.setenv("NMAPUI_RUNTIME_LOGS_KEEP_LATEST", "0")
    store = CapturingStore()

    run_daily_runtime_maintenance(
        runtime_store=store,
        logger=logging.getLogger(__name__),
        now=datetime(2026, 9, 27, 12, tzinfo=timezone.utc),
    )

    assert store.calls["retention"]["runtime_logs_keep_latest"] == 5000
    assert "Ignoring invalid NMAPUI_RUNTIME_LOGS_KEEP_LATEST" in caplog.text


def test_runtime_state_store_deletes_report_artifacts(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    scan_path = "Acme/2026-03-14/scan_120000_192.168.1.0_24"
    store.upsert_report_artifact(
        scan_path=scan_path,
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )

    assert store.get_report_artifact(scan_path) is not None

    store.delete_report_artifact(scan_path)

    assert store.get_report_artifact(scan_path) is None


def test_runtime_state_store_tracks_customer_scan_history(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    entry_id = store.append_customer_scan_history(
        customer_id="cust-1",
        payload={
            "timestamp": "2026-03-14T12:00:00",
            "customer_id": "cust-1",
            "customer_name": "Acme",
            "confidence_score": 1.0,
        },
    )

    history = store.list_customer_scan_history(customer_id="cust-1", limit=10)

    assert history[0]["id"] == entry_id
    assert history[0]["customer_id"] == "cust-1"
    assert history[0]["payload"]["customer_name"] == "Acme"


def test_runtime_state_store_counts_persisted_rows(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    store.upsert_report_artifact(
        scan_path="Acme/2026-03-14/scan_120000_192.168.1.0_24",
        customer_id="cust-1",
        target="192.168.1.0/24",
        html_path="scan_web.html",
        pdf_path="scan_report.pdf",
        xml_path="scan.xml",
        payload={"status": "completed"},
    )
    store.append_customer_scan_history(
        customer_id="cust-1",
        payload={"timestamp": "2026-03-14T12:00:00", "customer_id": "cust-1"},
    )
    store.append_log(
        category="runtime",
        level="INFO",
        message="Hydrated runtime state",
        payload={},
    )

    assert store.count_report_artifacts() == 1
    assert store.count_customer_scan_history() == 1
    assert store.count_runtime_logs() == 1


def test_runtime_state_store_prunes_runtime_logs_and_customer_history(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    for index in range(6):
        store.append_log(
            category="runtime",
            level="INFO",
            message=f"log-{index}",
            payload={"index": index},
        )
        store.append_customer_scan_history(
            customer_id="cust-1",
            payload={"timestamp": f"2026-03-14T12:00:0{index}", "index": index},
        )

    deleted_logs = store.prune_runtime_logs(keep_latest=3)
    deleted_history = store.prune_customer_scan_history(keep_latest=2)

    assert deleted_logs == 3
    assert deleted_history == 4
    assert store.count_runtime_logs() == 3
    assert store.count_customer_scan_history() == 2


def test_runtime_state_store_applies_retention_policies_and_compacts(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    for index in range(4):
        store.append_log(
            category="runtime",
            level="INFO",
            message=f"log-{index}",
            payload={"index": index},
        )
        store.append_customer_scan_history(
            customer_id="cust-1",
            payload={"timestamp": f"2026-03-14T12:00:0{index}", "index": index},
        )

    result = store.apply_retention_policies(
        runtime_logs_keep_latest=2,
        customer_history_keep_latest=1,
        compact=True,
    )

    assert result["deleted_runtime_logs"] == 2
    assert result["deleted_customer_scan_history"] == 3
    assert result["runtime_logs_keep_latest"] == 2
    assert result["customer_history_keep_latest"] == 1
    assert result["before_bytes"] >= result["after_bytes"] >= 0
    assert store.count_runtime_logs() == 2
    assert store.count_customer_scan_history() == 1


def test_runtime_state_store_exports_consistent_snapshot(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    store.upsert_runtime_snapshot("network_key", {"public_ip": "203.0.113.10"})

    export_path = store.export_snapshot()

    try:
        exported_store = create_runtime_state_store(export_path)
        assert exported_store.get_runtime_snapshot("network_key") == {
            "public_ip": "203.0.113.10"
        }
    finally:
        export_path.unlink(missing_ok=True)


def test_runtime_snapshot_export_removes_partial_file_on_failure(tmp_path: Path, monkeypatch):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    original_named_temp_file = runtime_db.tempfile.NamedTemporaryFile

    def named_temp_file_in_test_dir(**kwargs):
        return original_named_temp_file(dir=tmp_path, **kwargs)

    def fail_configuration(_connection):
        raise RuntimeError("injected export failure")

    monkeypatch.setattr(runtime_db.tempfile, "NamedTemporaryFile", named_temp_file_in_test_dir)
    monkeypatch.setattr(store, "_configure_connection", fail_configuration)

    with pytest.raises(RuntimeError, match="injected export failure"):
        store.export_snapshot()

    assert not list(tmp_path.glob("nmapui-runtime-export-*"))


def test_runtime_state_store_configures_sqlite_for_concurrent_usage(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")

    pragmas = store.get_connection_pragmas()

    assert pragmas["journal_mode"] == SQLITE_JOURNAL_MODE
    assert pragmas["busy_timeout"] == SQLITE_BUSY_TIMEOUT_MS
    assert pragmas["foreign_keys"] == 1
    assert pragmas["synchronous"] in (1, "1", "normal")


def test_runtime_state_store_retries_transient_locked_writes(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    original_connect = store.connect
    attempts = {"count": 0}

    @contextmanager
    def flaky_connect():
        with original_connect() as conn:
            if attempts["count"] == 0:
                attempts["count"] += 1
                raise sqlite3.OperationalError("database is locked")
            attempts["count"] += 1
            yield conn

    store.connect = flaky_connect

    store.upsert_runtime_snapshot(
        "network_topology",
        {"target": "192.168.1.0/24", "total_hops": 4},
    )

    assert attempts["count"] >= 2
    assert store.get_runtime_snapshot("network_topology") == {
        "target": "192.168.1.0/24",
        "total_hops": 4,
    }


def test_runtime_state_store_handles_concurrent_log_writers(tmp_path: Path):
    store = create_runtime_state_store(tmp_path / "runtime.sqlite3")
    errors = []

    def writer(writer_id: int):
        try:
            for entry_id in range(25):
                store.append_log(
                    category="runtime",
                    level="INFO",
                    message=f"writer-{writer_id}-entry-{entry_id}",
                    payload={"writer": writer_id, "entry": entry_id},
                )
        except Exception as exc:  # pragma: no cover - failure path only
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    logs = store.get_recent_logs(category="runtime", limit=200)
    assert len(logs) == 100
