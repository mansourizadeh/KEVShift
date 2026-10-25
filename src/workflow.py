"""Glue between storage and the pure rules.

The dashboard, the demo and the tests all call these two functions, so they behave
identically everywhere.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional, Union

from . import csv_importer, database
from .change_detector import analyze
from .models import ChangeResult, ImportResult, ScanRunInfo, SnapshotInfo


@dataclass
class ImportOutcome:
    """Result of validating and (when possible) saving an uploaded scan."""

    result: ImportResult
    scan_run_id: Optional[int]
    message: str


def import_scan(
    conn: sqlite3.Connection,
    data_dir: Union[str, Path],
    data: bytes,
    filename: str,
    comparable_group: Optional[str],
    imported_at: str,
    *,
    today: Optional[date] = None,
) -> ImportOutcome:
    """Validate an uploaded CSV, keep the original file and store the accepted rows.

    Raises csv_importer.CsvFormatError (unusable file) or database.DuplicateImportError
    (same file already imported).
    """
    result = csv_importer.parse_csv_bytes(data, today=today)
    if not result.accepted:
        return ImportOutcome(result, None, "No valid rows were found, so nothing was saved.")

    sha256 = csv_importer.sha256_hex(data)
    existing = database.find_scan_run_by_sha(conn, sha256)
    if existing is not None:
        raise database.DuplicateImportError(existing)

    uploads = Path(data_dir) / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    stored = uploads / f"scan_{sha256[:16]}.csv"
    if not stored.exists():
        stored.write_bytes(data)

    # Keep only the file name, whichever kind of path separator the browser or OS used.
    safe_name = re.split(r"[\\/]", filename or "")[-1][:200] or "upload.csv"
    run_id = database.store_scan_run(
        conn,
        result,
        source_filename=safe_name,
        file_sha256=sha256,
        stored_path=str(stored),
        comparable_group=comparable_group,
        imported_at=imported_at,
    )
    return ImportOutcome(
        result,
        run_id,
        f"Saved scan run #{run_id}: {result.accepted_count} accepted, "
        f"{result.rejected_count} rejected, {result.duplicate_count} duplicate.",
    )


@dataclass
class AnalysisBundle:
    """Everything the Findings page needs."""

    results: list = field(default_factory=list)
    current_snapshot: Optional[SnapshotInfo] = None
    previous_snapshot: Optional[SnapshotInfo] = None
    runs: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def run_analysis(conn: sqlite3.Connection, selected_snapshot_id: Optional[int] = None) -> AnalysisBundle:
    """Read stored data and run the change detector against the chosen snapshot.

    The default is the newest snapshot; its predecessor is the snapshot stored just before it.
    """
    snapshots = database.list_snapshots(conn)
    runs = database.list_scan_runs(conn)
    bundle = AnalysisBundle(runs=runs)

    if not snapshots:
        bundle.notes.append("No KEV snapshot is stored yet. Refresh the KEV catalog first.")
        return bundle
    if not runs:
        bundle.notes.append("No scan has been imported yet.")

    ids = [s.id for s in snapshots]
    if selected_snapshot_id is None or selected_snapshot_id not in ids:
        selected_snapshot_id = ids[-1]
    position = ids.index(selected_snapshot_id)
    current = snapshots[position]
    previous = snapshots[position - 1] if position > 0 else None

    bundle.current_snapshot = current
    bundle.previous_snapshot = previous

    findings_by_run = {run.id: database.get_findings(conn, run.id) for run in runs}
    bundle.results = analyze(
        runs,
        findings_by_run,
        current,
        database.get_kev_index(conn, current.id),
        previous,
        database.get_kev_index(conn, previous.id) if previous else None,
    )
    return bundle
