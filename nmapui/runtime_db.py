from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
import sqlite3
from pathlib import Path
import tempfile
import time
from typing import Any, Iterator

SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_JOURNAL_MODE = "wal"
SQLITE_SYNCHRONOUS = "normal"
SQLITE_WRITE_RETRY_ATTEMPTS = 3
SQLITE_WRITE_RETRY_DELAY_SECONDS = 0.05
RUNTIME_DB_SCHEMA_VERSION = 1
DEFAULT_RUNTIME_LOG_RETENTION = 5000
DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION = 2000
DEFAULT_FINISHED_JOB_RETENTION = 2000


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(payload: Any) -> str:
    return json.dumps(payload if payload is not None else {}, sort_keys=True)


def _json_loads(payload: str | None) -> Any:
    if not payload:
        return {}
    return json.loads(payload)


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS runtime_snapshots (
        key TEXT PRIMARY KEY,
        payload_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        owner_sid TEXT,
        job_type TEXT NOT NULL,
        status TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_jobs_type_status
    ON jobs(job_type, status)
    """,
    """
    CREATE TABLE IF NOT EXISTS job_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL,
        owner_sid TEXT,
        job_type TEXT NOT NULL,
        event_name TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_job_events_job_created
    ON job_events(job_id, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS report_artifacts (
        scan_path TEXT PRIMARY KEY,
        customer_id TEXT,
        target TEXT,
        html_path TEXT,
        pdf_path TEXT,
        xml_path TEXT,
        payload_json TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_report_artifacts_customer_target
    ON report_artifacts(customer_id, target)
    """,
    """
    CREATE TABLE IF NOT EXISTS runtime_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_runtime_logs_category_created
    ON runtime_logs(category, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS customer_scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id TEXT,
        timestamp TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_customer_scan_history_customer_timestamp
    ON customer_scan_history(customer_id, timestamp DESC)
    """,
)

SCHEMA_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: SCHEMA_STATEMENTS,
}

# Additive indexes remain compatible with version-1 readers, including the
# preserved rollback release. Create them for existing v1 databases too; a
# schema-version bump would make older code reject an otherwise readable DB.
READ_INDEX_STATEMENTS = (
    """
    CREATE INDEX IF NOT EXISTS idx_report_artifacts_generated
    ON report_artifacts(generated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_report_artifacts_customer_generated
    ON report_artifacts(customer_id, generated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_jobs_updated_id
    ON jobs(updated_at DESC, job_id DESC)
    """,
)


class RuntimeStateStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _configure_connection(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA journal_mode={SQLITE_JOURNAL_MODE}")
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute(f"PRAGMA synchronous={SQLITE_SYNCHRONOUS}")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000)
        try:
            self._configure_connection(conn)
            yield conn
            conn.commit()
        finally:
            conn.close()

    def get_connection_pragmas(self) -> dict[str, Any]:
        with self.connect() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
            foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        return {
            "journal_mode": journal_mode,
            "busy_timeout": int(busy_timeout),
            "synchronous": synchronous,
            "foreign_keys": int(foreign_keys),
        }

    def _get_schema_version(self, conn: sqlite3.Connection) -> int:
        return int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)

    def _set_schema_version(self, conn: sqlite3.Connection, version: int) -> None:
        conn.execute(f"PRAGMA user_version={int(version)}")

    def get_schema_version(self) -> int:
        with self.connect() as conn:
            return self._get_schema_version(conn)

    def _apply_schema_statements(
        self,
        conn: sqlite3.Connection,
        statements: tuple[str, ...],
    ) -> None:
        for statement in statements:
            conn.execute(statement)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        current_version = self._get_schema_version(conn)
        if current_version > RUNTIME_DB_SCHEMA_VERSION:
            raise RuntimeError(
                "Runtime DB schema version is newer than this application "
                f"supports: {current_version} > {RUNTIME_DB_SCHEMA_VERSION}"
            )
        for version in range(current_version + 1, RUNTIME_DB_SCHEMA_VERSION + 1):
            statements = SCHEMA_MIGRATIONS.get(version)
            if statements is None:
                raise RuntimeError(f"Missing runtime DB migration for version {version}")
            self._apply_schema_statements(conn, statements)
            self._set_schema_version(conn, version)

    def export_snapshot(self) -> Path:
        with tempfile.NamedTemporaryFile(
            prefix="nmapui-runtime-export-",
            suffix=".sqlite3",
            delete=False,
        ) as temp_file:
            export_path = Path(temp_file.name)

        try:
            with closing(sqlite3.connect(
                self.db_path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000
            )) as source_conn:
                with closing(sqlite3.connect(export_path)) as destination_conn:
                    self._configure_connection(source_conn)
                    source_conn.backup(destination_conn)
                    destination_conn.commit()
            return export_path
        except Exception:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{export_path}{suffix}").unlink(missing_ok=True)
            raise

    def get_database_file_size(self) -> int:
        try:
            return int(self.db_path.stat().st_size)
        except OSError:
            return 0

    def _run_write(self, operation):
        last_error = None
        for attempt in range(SQLITE_WRITE_RETRY_ATTEMPTS):
            try:
                with self.connect() as conn:
                    return operation(conn)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                last_error = exc
                if attempt == SQLITE_WRITE_RETRY_ATTEMPTS - 1:
                    raise
                time.sleep(SQLITE_WRITE_RETRY_DELAY_SECONDS * (attempt + 1))
        if last_error is not None:
            raise last_error

    def initialize(self) -> None:
        def operation(conn):
            self._migrate(conn)
            self._apply_schema_statements(conn, READ_INDEX_STATEMENTS)
        self._run_write(operation)

    def upsert_runtime_snapshot(self, key: str, payload: dict[str, Any]) -> None:
        now = utcnow_iso()
        def operation(conn):
            conn.execute(
                """
                INSERT INTO runtime_snapshots(key, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (key, _json_dumps(payload), now),
            )
        self._run_write(operation)

    def get_runtime_snapshot(self, key: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM runtime_snapshots WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return _json_loads(row["payload_json"])

    def upsert_job(
        self,
        *,
        job_id: str,
        owner_sid: str | None,
        job_type: str,
        status: str,
        payload: dict[str, Any],
    ) -> None:
        now = utcnow_iso()
        def operation(conn):
            conn.execute(
                """
                INSERT INTO jobs(job_id, owner_sid, job_type, status, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    owner_sid=excluded.owner_sid,
                    job_type=excluded.job_type,
                    status=excluded.status,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (job_id, owner_sid, job_type, status, _json_dumps(payload), now, now),
            )
        self._run_write(operation)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT job_id, owner_sid, job_type, status, payload_json, created_at, updated_at
                FROM jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "job_id": row["job_id"],
            "owner_sid": row["owner_sid"],
            "job_type": row["job_type"],
            "status": row["status"],
            "payload": _json_loads(row["payload_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_jobs(
        self,
        *,
        statuses: list[str] | tuple[str, ...] | None = None,
        job_type: str | None = None,
        limit: int = 50,
        before: tuple[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT job_id, owner_sid, job_type, status, payload_json, created_at, updated_at
            FROM jobs
        """
        conditions = []
        params: list[Any] = []
        if statuses:
            conditions.append(f"status IN ({','.join('?' for _ in statuses)})")
            params.extend(statuses)
        if job_type:
            conditions.append("job_type = ?")
            params.append(job_type)
        if before is not None:
            conditions.append("(updated_at < ? OR (updated_at = ? AND job_id < ?))")
            params.extend((before[0], before[0], before[1]))
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY updated_at DESC, job_id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "job_id": row["job_id"],
                "owner_sid": row["owner_sid"],
                "job_type": row["job_type"],
                "status": row["status"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def upsert_report_artifact(
        self,
        *,
        scan_path: str,
        customer_id: str,
        target: str,
        html_path: str | None,
        pdf_path: str | None,
        xml_path: str | None,
        payload: dict[str, Any],
    ) -> None:
        now = utcnow_iso()
        def operation(conn):
            conn.execute(
                """
                INSERT INTO report_artifacts(
                    scan_path, customer_id, target, html_path, pdf_path, xml_path,
                    payload_json, generated_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_path) DO UPDATE SET
                    customer_id=excluded.customer_id,
                    target=excluded.target,
                    html_path=excluded.html_path,
                    pdf_path=excluded.pdf_path,
                    xml_path=excluded.xml_path,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    scan_path,
                    customer_id,
                    target,
                    html_path,
                    pdf_path,
                    xml_path,
                    _json_dumps(payload),
                    now,
                    now,
                ),
            )
        self._run_write(operation)

    def list_report_artifacts(
        self,
        *,
        customer_id: str | None = None,
        limit: int = 500,
        offset: int = 0,
        include_asset_snapshot: bool = False,
    ) -> list[dict[str, Any]]:
        payload_expression = (
            "payload_json"
            if include_asset_snapshot
            else "json_remove(payload_json, '$.asset_snapshot')"
        )
        query = """
            SELECT scan_path, customer_id, target, html_path, pdf_path, xml_path,
                   {payload_expression} AS payload_json, generated_at, updated_at
            FROM report_artifacts
        """.format(payload_expression=payload_expression)
        params: list[Any] = []
        if customer_id:
            query += " WHERE customer_id = ?"
            params.append(customer_id)
        query += " ORDER BY generated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "scan_path": row["scan_path"],
                "customer_id": row["customer_id"],
                "target": row["target"],
                "html_path": row["html_path"],
                "pdf_path": row["pdf_path"],
                "xml_path": row["xml_path"],
                "payload": _json_loads(row["payload_json"]),
                "generated_at": row["generated_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def get_report_artifact(self, scan_path: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT scan_path, customer_id, target, html_path, pdf_path, xml_path, payload_json, generated_at, updated_at
                FROM report_artifacts
                WHERE scan_path = ?
                """,
                (scan_path,),
            ).fetchone()
        if row is None:
            return None
        return {
            "scan_path": row["scan_path"],
            "customer_id": row["customer_id"],
            "target": row["target"],
            "html_path": row["html_path"],
            "pdf_path": row["pdf_path"],
            "xml_path": row["xml_path"],
            "payload": _json_loads(row["payload_json"]),
            "generated_at": row["generated_at"],
            "updated_at": row["updated_at"],
        }

    def delete_report_artifact(self, scan_path: str) -> None:
        def operation(conn):
            conn.execute(
                "DELETE FROM report_artifacts WHERE scan_path = ?",
                (scan_path,),
            )
        self._run_write(operation)

    def append_log(
        self,
        *,
        category: str,
        level: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> int:
        now = utcnow_iso()
        def operation(conn):
            cursor = conn.execute(
                """
                INSERT INTO runtime_logs(category, level, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (category, level, message, _json_dumps(payload), now),
            )
            return int(cursor.lastrowid)
        return self._run_write(operation)

    def append_job_event(
        self,
        *,
        job_id: str,
        owner_sid: str | None,
        job_type: str,
        event_name: str,
        payload: Any = None,
        max_events: int = 200,
    ) -> int:
        now = utcnow_iso()
        def operation(conn):
            cursor = conn.execute(
                """
                INSERT INTO job_events(job_id, owner_sid, job_type, event_name, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job_id, owner_sid, job_type, event_name, _json_dumps(payload), now),
            )
            conn.execute(
                """
                DELETE FROM job_events
                WHERE job_id = ?
                  AND id NOT IN (
                    SELECT id FROM job_events
                    WHERE job_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                  )
                """,
                (job_id, job_id, max_events),
            )
            return int(cursor.lastrowid)
        return self._run_write(operation)

    def list_job_events(
        self,
        *,
        job_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, job_id, owner_sid, job_type, event_name, payload_json, created_at
                FROM job_events
                WHERE job_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (job_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "job_id": row["job_id"],
                "owner_sid": row["owner_sid"],
                "job_type": row["job_type"],
                "event_name": row["event_name"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in reversed(rows)
        ]

    def get_recent_logs(
        self,
        *,
        category: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, category, level, message, payload_json, created_at
            FROM runtime_logs
        """
        params: tuple[Any, ...] = ()
        if category:
            query += " WHERE category = ?"
            params = (category,)
        query += " ORDER BY id DESC LIMIT ?"
        params += (limit,)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "category": row["category"],
                "level": row["level"],
                "message": row["message"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def append_customer_scan_history(
        self,
        *,
        customer_id: str | None,
        payload: dict[str, Any],
    ) -> int:
        now = utcnow_iso()
        timestamp = str(payload.get("timestamp", "") or now)
        def operation(conn):
            cursor = conn.execute(
                """
                INSERT INTO customer_scan_history(customer_id, timestamp, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (customer_id, timestamp, _json_dumps(payload), now),
            )
            return int(cursor.lastrowid)
        return self._run_write(operation)

    def list_customer_scan_history(
        self,
        *,
        customer_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, customer_id, timestamp, payload_json, created_at
            FROM customer_scan_history
        """
        params: list[Any] = []
        if customer_id:
            query += " WHERE customer_id = ?"
            params.append(customer_id)
        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            {
                "id": row["id"],
                "customer_id": row["customer_id"],
                "timestamp": row["timestamp"],
                "payload": _json_loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def count_report_artifacts(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM report_artifacts"
            ).fetchone()
        return int(row["count"] or 0)

    def count_customer_scan_history(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM customer_scan_history"
            ).fetchone()
        return int(row["count"] or 0)

    def count_runtime_logs(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM runtime_logs"
            ).fetchone()
        return int(row["count"] or 0)

    def prune_runtime_logs(
        self,
        *,
        keep_latest: int = DEFAULT_RUNTIME_LOG_RETENTION,
    ) -> int:
        keep_latest = max(0, int(keep_latest))

        def operation(conn):
            before = int(
                conn.execute("SELECT COUNT(*) AS count FROM runtime_logs").fetchone()[0]
                or 0
            )
            if keep_latest == 0:
                conn.execute("DELETE FROM runtime_logs")
            else:
                conn.execute(
                    """
                    DELETE FROM runtime_logs
                    WHERE id NOT IN (
                        SELECT id FROM runtime_logs
                        ORDER BY id DESC
                        LIMIT ?
                    )
                    """,
                    (keep_latest,),
                )
            after = int(
                conn.execute("SELECT COUNT(*) AS count FROM runtime_logs").fetchone()[0]
                or 0
            )
            return max(0, before - after)

        return int(self._run_write(operation) or 0)

    def prune_customer_scan_history(
        self,
        *,
        keep_latest: int = DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION,
    ) -> int:
        keep_latest = max(0, int(keep_latest))

        def operation(conn):
            before = int(
                conn.execute(
                    "SELECT COUNT(*) AS count FROM customer_scan_history"
                ).fetchone()[0]
                or 0
            )
            if keep_latest == 0:
                conn.execute("DELETE FROM customer_scan_history")
            else:
                conn.execute(
                    """
                    DELETE FROM customer_scan_history
                    WHERE id NOT IN (
                        SELECT id FROM customer_scan_history
                        ORDER BY timestamp DESC, id DESC
                        LIMIT ?
                    )
                    """,
                    (keep_latest,),
                )
            after = int(
                conn.execute(
                    "SELECT COUNT(*) AS count FROM customer_scan_history"
                ).fetchone()[0]
                or 0
            )
            return max(0, before - after)

        return int(self._run_write(operation) or 0)

    def prune_finished_jobs(
        self,
        *,
        keep_latest: int = DEFAULT_FINISHED_JOB_RETENTION,
    ) -> dict[str, int]:
        """Keep recent finished jobs and remove events tied to older ones."""
        keep_latest = max(0, int(keep_latest))

        def operation(conn):
            before_jobs = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            before_events = conn.execute("SELECT COUNT(*) FROM job_events").fetchone()[0]
            conn.execute(
                """
                DELETE FROM job_events
                WHERE job_id IN (
                    SELECT job_id FROM jobs
                    WHERE status NOT IN ('running', 'cancelling')
                    ORDER BY updated_at DESC, job_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (keep_latest,),
            )
            conn.execute(
                """
                DELETE FROM jobs
                WHERE job_id IN (
                    SELECT job_id FROM jobs
                    WHERE status NOT IN ('running', 'cancelling')
                    ORDER BY updated_at DESC, job_id DESC
                    LIMIT -1 OFFSET ?
                )
                """,
                (keep_latest,),
            )
            return {
                "deleted_jobs": before_jobs - conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                "deleted_job_events": before_events - conn.execute("SELECT COUNT(*) FROM job_events").fetchone()[0],
            }

        return self._run_write(operation)

    def compact_database(self) -> dict[str, int]:
        before_bytes = self.get_database_file_size()
        conn = sqlite3.connect(
            self.db_path,
            timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
        try:
            self._configure_connection(conn)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")
        finally:
            conn.close()
        after_bytes = self.get_database_file_size()
        return {
            "before_bytes": before_bytes,
            "after_bytes": after_bytes,
        }

    def apply_retention_policies(
        self,
        *,
        runtime_logs_keep_latest: int = DEFAULT_RUNTIME_LOG_RETENTION,
        customer_history_keep_latest: int = DEFAULT_CUSTOMER_SCAN_HISTORY_RETENTION,
        compact: bool = True,
    ) -> dict[str, Any]:
        deleted_runtime_logs = self.prune_runtime_logs(
            keep_latest=runtime_logs_keep_latest
        )
        deleted_customer_scan_history = self.prune_customer_scan_history(
            keep_latest=customer_history_keep_latest
        )
        compact_result = (
            self.compact_database()
            if compact
            else {
                "before_bytes": self.get_database_file_size(),
                "after_bytes": self.get_database_file_size(),
            }
        )
        return {
            "deleted_runtime_logs": deleted_runtime_logs,
            "deleted_customer_scan_history": deleted_customer_scan_history,
            "runtime_logs_keep_latest": max(0, int(runtime_logs_keep_latest)),
            "customer_history_keep_latest": max(0, int(customer_history_keep_latest)),
            **compact_result,
        }


def create_runtime_state_store(db_path: Path) -> RuntimeStateStore:
    store = RuntimeStateStore(db_path)
    store.initialize()
    return store
