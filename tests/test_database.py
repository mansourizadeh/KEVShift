"""Phase 3 tests: SQLite schema, history and transactions."""

import sqlite3
from datetime import date

import pytest

from src import csv_importer, database, kev_client
from src.models import FindingRow, ImportResult

TODAY = date(2026, 1, 1)


def _result(make_csv, rows):
    return csv_importer.parse_csv_bytes(make_csv(rows), today=TODAY)


def _store(conn, result, sha, group="weekly", when="2025-10-01T12:00:00Z"):
    return database.store_scan_run(
        conn, result, source_filename="x.csv", file_sha256=sha, stored_path="p", comparable_group=group, imported_at=when
    )


def test_schema_creates_every_documented_table(conn):
    names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scan_runs", "findings", "kev_snapshots", "kev_entries", "kev_checks", "events", "epss_cache"} <= names
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_scan_run_and_findings_round_trip(conn, make_csv):
    result = _result(make_csv, [("web-01", "CVE-2099-0001", "2025-10-01", "open"), ("db-01", "CVE-2099-0002", "2025-10-01", "mitigated")])
    run_id = _store(conn, result, "a" * 64)
    findings = database.get_findings(conn, run_id)
    assert [(f.asset_name, f.cve_id, f.finding_status) for f in findings] == [
        ("db-01", "CVE-2099-0002", "mitigated"), ("web-01", "CVE-2099-0001", "open")]
    run = database.list_scan_runs(conn)[0]
    assert (run.rows_accepted, run.comparable_group, run.scan_date) == (2, "weekly", "2025-10-01")


def test_history_is_preserved_across_imports(conn, make_csv):
    _store(conn, _result(make_csv, [("a", "CVE-2099-0001", "2025-10-01", "open")]), "1" * 64, when="2025-10-01T00:00:00Z")
    _store(conn, _result(make_csv, [("a", "CVE-2099-0001", "2025-10-08", "open")]), "2" * 64, when="2025-10-08T00:00:00Z")
    assert [r.scan_date for r in database.list_scan_runs(conn)] == ["2025-10-01", "2025-10-08"]
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2


def test_same_file_cannot_be_imported_twice(conn, make_csv):
    result = _result(make_csv, [("a", "CVE-2099-0001", "2025-10-01", "open")])
    _store(conn, result, "f" * 64)
    with pytest.raises(database.DuplicateImportError):
        _store(conn, result, "f" * 64)
    assert len(database.list_scan_runs(conn)) == 1


def test_failed_import_is_rolled_back_completely(conn):
    broken = ImportResult(total_rows=2, scan_date="2025-10-01")
    broken.accepted = [
        FindingRow("web-01", "CVE-2099-0001", "2025-10-01", "open", 2),
        FindingRow("web-01", "CVE-2099-0001", "2025-10-01", "open", 3),  # violates UNIQUE
    ]
    with pytest.raises(sqlite3.IntegrityError):
        _store(conn, broken, "b" * 64)
    assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_foreign_keys_are_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO findings (scan_run_id, asset_name, cve_id, scan_date, finding_status, source_row) "
                     "VALUES (999, 'a', 'CVE-2099-0001', '2025-10-01', 'open', 2)")


def test_data_persists_across_application_restarts(tmp_path, make_csv, make_kev_json):
    db_path = tmp_path / "data" / "kevshift.db"
    first = database.connect(db_path)
    database.init_schema(first)
    _store(first, _result(make_csv, [("web-01", "CVE-2099-0001", "2025-10-01", "open")]), "c" * 64)
    kev_client.store_snapshot_bytes(first, make_kev_json(), tmp_path / "data", source_url="t", retrieved_at="2025-10-01T08:00:00Z")
    first.close()  # the "application" stops

    second = database.connect(db_path)  # the "application" starts again
    database.init_schema(second)  # re-running init must not erase anything
    assert len(database.list_scan_runs(second)) == 1
    assert len(database.get_findings(second, 1)) == 1
    snapshot = database.latest_snapshot(second)
    assert snapshot.catalog_version == "v1" and "CVE-2099-0001" in database.get_kev_index(second, snapshot.id)
    second.close()


def test_unchanged_kev_content_creates_one_snapshot_but_two_checks(conn, data_dir, make_kev_json):
    raw = make_kev_json()
    _, created_first = kev_client.store_snapshot_bytes(conn, raw, data_dir, source_url="u", retrieved_at="2025-10-01T08:00:00Z")
    _, created_second = kev_client.store_snapshot_bytes(conn, raw, data_dir, source_url="u", retrieved_at="2025-10-02T08:00:00Z")
    assert (created_first, created_second) == (True, False)
    assert len(database.list_snapshots(conn)) == 1
    assert len(database.list_checks(conn)) == 2


def test_sql_injection_text_is_stored_as_plain_data(conn, make_csv):
    result = _result(make_csv, [("x'); DROP TABLE findings;--", "CVE-2099-0001", "2025-10-01", "open")])
    run_id = _store(conn, result, "d" * 64)
    assert database.get_findings(conn, run_id)[0].asset_name == "x'); DROP TABLE findings;--"
