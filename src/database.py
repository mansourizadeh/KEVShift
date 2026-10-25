"""SQLite schema and storage.

History is preserved: every import and every KEV snapshot is added as new rows and is
never overwritten. All writes that touch several tables run inside one transaction,
so they either fully succeed or leave the database unchanged.

Functions receive the connection as a parameter (no global state), and every SQL
statement is parameterized (values are passed separately, never pasted into the text).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from .models import FindingRow, ImportResult, KevEntry, KevSnapshot, ScanRunInfo, SnapshotInfo

SCHEMA_VERSION = 1

SCHEMA = """
-- One row per imported CSV file. file_sha256 is UNIQUE so the same file cannot be
-- imported twice by accident. comparable_group is the label that says which scans
-- may be compared with each other (for example "internal-weekly").
CREATE TABLE IF NOT EXISTS scan_runs (
    id               INTEGER PRIMARY KEY,
    source_filename  TEXT    NOT NULL,
    file_sha256      TEXT    NOT NULL UNIQUE,
    stored_path      TEXT    NOT NULL,
    scan_date        TEXT    NOT NULL,
    comparable_group TEXT,
    imported_at      TEXT    NOT NULL,
    rows_total       INTEGER NOT NULL,
    rows_accepted    INTEGER NOT NULL,
    rows_rejected    INTEGER NOT NULL,
    rows_duplicate   INTEGER NOT NULL
);

-- One row per accepted finding. Deleting a scan run would delete its findings,
-- but KEVShift never deletes history.
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY,
    scan_run_id    INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset_name     TEXT    NOT NULL,
    cve_id         TEXT    NOT NULL,
    scan_date      TEXT    NOT NULL,
    finding_status TEXT    NOT NULL,
    source_row     INTEGER NOT NULL,
    UNIQUE (scan_run_id, asset_name, cve_id)
);

-- One row per distinct KEV catalog content. content_sha256 is UNIQUE, so an unchanged
-- feed does not create a duplicate snapshot.
CREATE TABLE IF NOT EXISTS kev_snapshots (
    id             INTEGER PRIMARY KEY,
    catalog_version TEXT   NOT NULL,
    date_released  TEXT    NOT NULL,
    retrieved_at   TEXT    NOT NULL,
    source_url     TEXT    NOT NULL,
    entry_count    INTEGER NOT NULL,
    stored_path    TEXT    NOT NULL,
    content_sha256 TEXT    NOT NULL UNIQUE
);

-- The vulnerabilities listed in each snapshot.
CREATE TABLE IF NOT EXISTS kev_entries (
    snapshot_id          INTEGER NOT NULL REFERENCES kev_snapshots(id) ON DELETE CASCADE,
    cve_id               TEXT    NOT NULL,
    vendor_project       TEXT    NOT NULL,
    product              TEXT    NOT NULL,
    vulnerability_name   TEXT    NOT NULL,
    date_added           TEXT    NOT NULL,
    short_description    TEXT    NOT NULL,
    required_action      TEXT    NOT NULL,
    due_date             TEXT    NOT NULL,
    known_ransomware_use TEXT    NOT NULL,
    PRIMARY KEY (snapshot_id, cve_id)
);

-- One row per successful KEV check (even when the catalog had not changed).
CREATE TABLE IF NOT EXISTS kev_checks (
    id          INTEGER PRIMARY KEY,
    snapshot_id INTEGER NOT NULL REFERENCES kev_snapshots(id) ON DELETE CASCADE,
    checked_at  TEXT    NOT NULL,
    source_url  TEXT    NOT NULL
);

-- Audit log shown in the History page (imports, new snapshots, failed refreshes).
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    occurred_at TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    scan_run_id INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    snapshot_id INTEGER REFERENCES kev_snapshots(id) ON DELETE SET NULL,
    message     TEXT    NOT NULL
);

-- Optional EPSS cache (supplementary information only).
CREATE TABLE IF NOT EXISTS epss_cache (
    cve_id     TEXT PRIMARY KEY,
    epss       REAL NOT NULL,
    percentile REAL NOT NULL,
    score_date TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve   ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_runs_group     ON scan_runs(comparable_group, scan_date);
CREATE INDEX IF NOT EXISTS idx_entries_cve    ON kev_entries(cve_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_time ON kev_snapshots(retrieved_at);
CREATE INDEX IF NOT EXISTS idx_checks_time    ON kev_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_events_time    ON events(occurred_at);
"""


class DuplicateImportError(Exception):
    """The same file content was already imported."""

    def __init__(self, scan_run_id: int):
        super().__init__(f"This exact file was already imported (scan run #{scan_run_id}).")
        self.scan_run_id = scan_run_id


# ------------------------------------------------------------------------ helpers
def utc_timestamp(moment: Optional[datetime] = None) -> str:
    """Format a moment as UTC text that sorts correctly, e.g. 2025-10-15T08:00:00Z."""
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: Union[str, Path]) -> sqlite3.Connection:
    """Open (and create if needed) the database file with foreign keys switched on."""
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes (safe to call every time the app starts)."""
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
    conn.commit()


def add_event(
    conn: sqlite3.Connection,
    event_type: str,
    message: str,
    *,
    occurred_at: Optional[str] = None,
    scan_run_id: Optional[int] = None,
    snapshot_id: Optional[int] = None,
) -> None:
    """Append an audit event. The caller is responsible for the surrounding transaction."""
    conn.execute(
        "INSERT INTO events (occurred_at, event_type, scan_run_id, snapshot_id, message) "
        "VALUES (?, ?, ?, ?, ?)",
        (occurred_at or utc_timestamp(), event_type, scan_run_id, snapshot_id, message),
    )


def record_event(conn: sqlite3.Connection, event_type: str, message: str, **kwargs) -> None:
    """Append an audit event in its own transaction."""
    with conn:
        add_event(conn, event_type, message, **kwargs)


# ------------------------------------------------------------------------- scans
def _scan_run_from_row(row: sqlite3.Row) -> ScanRunInfo:
    return ScanRunInfo(
        id=row["id"],
        source_filename=row["source_filename"],
        scan_date=row["scan_date"],
        comparable_group=row["comparable_group"],
        imported_at=row["imported_at"],
        rows_total=row["rows_total"],
        rows_accepted=row["rows_accepted"],
        rows_rejected=row["rows_rejected"],
        rows_duplicate=row["rows_duplicate"],
        file_sha256=row["file_sha256"],
        stored_path=row["stored_path"],
    )


def find_scan_run_by_sha(conn: sqlite3.Connection, file_sha256: str) -> Optional[int]:
    row = conn.execute("SELECT id FROM scan_runs WHERE file_sha256 = ?", (file_sha256,)).fetchone()
    return row["id"] if row else None


def store_scan_run(
    conn: sqlite3.Connection,
    result: ImportResult,
    *,
    source_filename: str,
    file_sha256: str,
    stored_path: str,
    comparable_group: Optional[str],
    imported_at: str,
) -> int:
    """Store one validated import (scan run plus its findings) in a single transaction."""
    if not result.accepted or result.scan_date is None:
        raise ValueError("There are no accepted rows to store.")
    existing = find_scan_run_by_sha(conn, file_sha256)
    if existing is not None:
        raise DuplicateImportError(existing)

    group = (comparable_group or "").strip() or None
    with conn:  # commit on success, roll back on any error
        cursor = conn.execute(
            "INSERT INTO scan_runs (source_filename, file_sha256, stored_path, scan_date, "
            "comparable_group, imported_at, rows_total, rows_accepted, rows_rejected, rows_duplicate) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                source_filename,
                file_sha256,
                stored_path,
                result.scan_date,
                group,
                imported_at,
                result.total_rows,
                result.accepted_count,
                result.rejected_count,
                result.duplicate_count,
            ),
        )
        run_id = cursor.lastrowid
        conn.executemany(
            "INSERT INTO findings (scan_run_id, asset_name, cve_id, scan_date, finding_status, source_row) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (run_id, f.asset_name, f.cve_id, f.scan_date, f.finding_status, f.source_row)
                for f in result.accepted
            ],
        )
        add_event(
            conn,
            "scan_imported",
            f"Imported {source_filename}: {result.accepted_count} accepted, "
            f"{result.rejected_count} rejected, {result.duplicate_count} duplicate "
            f"(scan date {result.scan_date}, group {group or 'none'}).",
            occurred_at=imported_at,
            scan_run_id=run_id,
        )
    return run_id


def list_scan_runs(conn: sqlite3.Connection) -> list:
    """All scan runs, oldest scan first."""
    rows = conn.execute("SELECT * FROM scan_runs ORDER BY scan_date, id").fetchall()
    return [_scan_run_from_row(row) for row in rows]


def get_findings(conn: sqlite3.Connection, scan_run_id: int) -> list:
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_run_id = ? ORDER BY asset_name, cve_id", (scan_run_id,)
    ).fetchall()
    return [
        FindingRow(
            asset_name=r["asset_name"],
            cve_id=r["cve_id"],
            scan_date=r["scan_date"],
            finding_status=r["finding_status"],
            source_row=r["source_row"],
            scan_run_id=r["scan_run_id"],
        )
        for r in rows
    ]


# --------------------------------------------------------------------- KEV data
def _snapshot_from_row(row: sqlite3.Row) -> SnapshotInfo:
    return SnapshotInfo(
        id=row["id"],
        catalog_version=row["catalog_version"],
        date_released=row["date_released"],
        retrieved_at=row["retrieved_at"],
        source_url=row["source_url"],
        entry_count=row["entry_count"],
        stored_path=row["stored_path"],
        content_sha256=row["content_sha256"],
    )


def find_snapshot_by_sha(conn: sqlite3.Connection, content_sha256: str) -> Optional[int]:
    row = conn.execute(
        "SELECT id FROM kev_snapshots WHERE content_sha256 = ?", (content_sha256,)
    ).fetchone()
    return row["id"] if row else None


def store_kev_snapshot(
    conn: sqlite3.Connection,
    snapshot: KevSnapshot,
    *,
    source_url: str,
    retrieved_at: str,
    stored_path: str,
    content_sha256: str,
) -> tuple:
    """Record a successful KEV check. Returns (snapshot_id, created).

    If a snapshot with identical content already exists, no new snapshot is created;
    only the check itself is recorded.
    """
    with conn:
        existing = find_snapshot_by_sha(conn, content_sha256)
        if existing is not None:
            snapshot_id, created = existing, False
            add_event(
                conn,
                "kev_checked_unchanged",
                f"KEV checked; catalog unchanged (version {snapshot.catalog_version}).",
                occurred_at=retrieved_at,
                snapshot_id=snapshot_id,
            )
        else:
            cursor = conn.execute(
                "INSERT INTO kev_snapshots (catalog_version, date_released, retrieved_at, source_url, "
                "entry_count, stored_path, content_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.catalog_version,
                    snapshot.date_released,
                    retrieved_at,
                    source_url,
                    len(snapshot.entries),
                    stored_path,
                    content_sha256,
                ),
            )
            snapshot_id, created = cursor.lastrowid, True
            conn.executemany(
                "INSERT INTO kev_entries (snapshot_id, cve_id, vendor_project, product, vulnerability_name, "
                "date_added, short_description, required_action, due_date, known_ransomware_use) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        snapshot_id,
                        e.cve_id,
                        e.vendor_project,
                        e.product,
                        e.vulnerability_name,
                        e.date_added,
                        e.short_description,
                        e.required_action,
                        e.due_date,
                        e.known_ransomware_use,
                    )
                    for e in snapshot.entries
                ],
            )
            add_event(
                conn,
                "kev_snapshot_added",
                f"New KEV snapshot stored: version {snapshot.catalog_version}, "
                f"{len(snapshot.entries)} entries.",
                occurred_at=retrieved_at,
                snapshot_id=snapshot_id,
            )
        conn.execute(
            "INSERT INTO kev_checks (snapshot_id, checked_at, source_url) VALUES (?, ?, ?)",
            (snapshot_id, retrieved_at, source_url),
        )
    return snapshot_id, created


def list_snapshots(conn: sqlite3.Connection) -> list:
    """All stored snapshots, oldest first."""
    rows = conn.execute("SELECT * FROM kev_snapshots ORDER BY retrieved_at, id").fetchall()
    return [_snapshot_from_row(row) for row in rows]


def get_snapshot(conn: sqlite3.Connection, snapshot_id: int) -> Optional[SnapshotInfo]:
    row = conn.execute("SELECT * FROM kev_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    return _snapshot_from_row(row) if row else None


def latest_snapshot(conn: sqlite3.Connection) -> Optional[SnapshotInfo]:
    row = conn.execute(
        "SELECT * FROM kev_snapshots ORDER BY retrieved_at DESC, id DESC LIMIT 1"
    ).fetchone()
    return _snapshot_from_row(row) if row else None


def get_kev_index(conn: sqlite3.Connection, snapshot_id: int) -> dict:
    """The entries of one snapshot as {cve_id: KevEntry} for exact lookups."""
    rows = conn.execute("SELECT * FROM kev_entries WHERE snapshot_id = ?", (snapshot_id,)).fetchall()
    return {
        r["cve_id"]: KevEntry(
            cve_id=r["cve_id"],
            vendor_project=r["vendor_project"],
            product=r["product"],
            vulnerability_name=r["vulnerability_name"],
            date_added=r["date_added"],
            short_description=r["short_description"],
            required_action=r["required_action"],
            due_date=r["due_date"],
            known_ransomware_use=r["known_ransomware_use"],
        )
        for r in rows
    }


def last_successful_check(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM kev_checks ORDER BY checked_at DESC, id DESC LIMIT 1").fetchone()


def list_checks(conn: sqlite3.Connection) -> list:
    return conn.execute("SELECT * FROM kev_checks ORDER BY checked_at, id").fetchall()


def list_events(conn: sqlite3.Connection, limit: int = 200) -> list:
    """Most recent events first."""
    return conn.execute(
        "SELECT * FROM events ORDER BY occurred_at DESC, id DESC LIMIT ?", (int(limit),)
    ).fetchall()
