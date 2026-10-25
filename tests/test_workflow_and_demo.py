"""Phase 7 tests: workflow glue, reproducibility and the demonstration scenario."""

from datetime import date

import pytest

from src import change_detector as cd
from src import csv_importer, database, demo, workflow

TODAY = date(2026, 1, 1)


def test_import_scan_keeps_the_original_file_and_rejects_reimport(conn, data_dir, make_csv):
    data = make_csv([("web-01", "CVE-2099-0001", "2025-10-01", "open"), ("web-01", "BAD", "2025-10-01", "open")])
    outcome = workflow.import_scan(conn, data_dir, data, "C:\\fakepath\\scan.csv", "weekly", "2025-10-01T12:00:00Z", today=TODAY)
    assert outcome.scan_run_id == 1 and outcome.result.rejected_count == 1
    stored = list((data_dir / "uploads").glob("*.csv"))
    assert len(stored) == 1 and stored[0].read_bytes() == data  # audit copy of the original
    assert database.list_scan_runs(conn)[0].source_filename == "scan.csv"
    with pytest.raises(database.DuplicateImportError):
        workflow.import_scan(conn, data_dir, data, "scan.csv", "weekly", "2025-10-02T12:00:00Z", today=TODAY)


def test_import_with_no_valid_rows_saves_nothing(conn, data_dir, make_csv):
    outcome = workflow.import_scan(conn, data_dir, make_csv([("a", "BAD", "2025-10-01", "open")]), "x.csv", None, "t", today=TODAY)
    assert outcome.scan_run_id is None and database.list_scan_runs(conn) == []


def test_analysis_without_snapshot_or_scan_gives_helpful_notes(conn):
    assert "No KEV snapshot" in workflow.run_analysis(conn).notes[0]


def test_reproducible_output_from_stored_snapshots_after_restart(tmp_path, sample_dir):
    data_dir = tmp_path / "data"
    db_path = data_dir / "kevshift.db"

    conn = database.connect(db_path)
    database.init_schema(conn)
    demo.apply_step(conn, data_dir, sample_dir, 3)
    first = workflow.run_analysis(conn).results
    conn.close()

    conn = database.connect(db_path)  # restart
    database.init_schema(conn)
    second = workflow.run_analysis(conn).results
    # Even the earlier snapshot pair can be re-analysed and gives the same answer every time.
    ids = [s.id for s in database.list_snapshots(conn)]
    again = [workflow.run_analysis(conn, ids[-1]).results for _ in range(2)]
    conn.close()

    assert first == second == again[0] == again[1] and len(first) == 5


def test_demo_steps_are_idempotent(conn, data_dir, sample_dir):
    demo.apply_step(conn, data_dir, sample_dir, 3)
    messages = demo.apply_step(conn, data_dir, sample_dir, 3)
    assert any("already" in m for m in messages)
    assert len(database.list_snapshots(conn)) == 2 and len(database.list_scan_runs(conn)) == 2


@pytest.fixture
def reports(tmp_path, sample_dir):
    return demo.run_demo(tmp_path / "demo_cli", sample_dir, tmp_path / "out")


def _row(report, cve, asset=None):
    return [r for r in report.results if r.cve_id == cve and (asset is None or r.asset_name == asset)]


def test_acceptance_catalog_change_without_new_scan(reports):
    step1, step2, _ = reports
    before = _row(step1, "CVE-2099-0001", "web-server-01")[0]
    after = _row(step2, "CVE-2099-0001", "web-server-01")[0]
    assert before.change_category == cd.CAT_NO_MATCH  # 1 October: not in the stored KEV snapshot
    assert after.change_category == cd.CAT_NEWLY_ADDED  # 15 October snapshot now lists it
    assert before.scan_date == after.scan_date == "2025-10-01"  # same scan, no new import
    assert after.kev_date_added == "2025-10-14"
    assert "verify" in after.recommended_action.lower()
    # The only mention of an attack is the explicit disclaimer; no claim that the asset was attacked.
    assert "does not show that web-server-01 was attacked" in after.explanation
    assert after.explanation.count("attacked") == 1


def test_acceptance_no_scan_was_imported_between_the_catalog_checks(tmp_path, sample_dir):
    conn = database.connect(":memory:")
    database.init_schema(conn)
    demo.apply_step(conn, tmp_path, sample_dir, 1)
    runs_before = len(database.list_scan_runs(conn))
    demo._apply_one(conn, tmp_path, sample_dir, demo.STEPS[1])
    assert len(database.list_scan_runs(conn)) == runs_before == 1
    assert len(database.list_snapshots(conn)) == 2
    conn.close()


def test_acceptance_not_observed_in_latest_scan(reports):
    step2, step3 = reports[1], reports[2]
    assert not any(r.change_category == cd.CAT_NOT_OBSERVED for r in step2.results)
    missing = _row(step3, "CVE-2099-0003", "db-server-02")[0]
    assert missing.change_category == cd.CAT_NOT_OBSERVED == "Not observed in latest scan"
    assert "fixed" not in missing.explanation.lower()


def test_acceptance_substring_cve_in_catalog_is_not_matched(reports):
    for report in reports:
        assert not any(r.cve_id == "CVE-2099-00011" for r in report.results)
        assert all(r.kev_match_status == "Not listed in KEV" for r in _row(report, "CVE-2099-0001")
                   if report.step.number == 1)


def test_demo_reports_are_written_as_csv_and_text(reports, tmp_path):
    out = tmp_path / "out"
    assert {p.name for p in out.iterdir()} == {f"demo_step{n}_report.{ext}" for n in (1, 2, 3) for ext in ("csv", "txt")}


def test_demo_refuses_to_delete_non_demo_folders(tmp_path):
    with pytest.raises(ValueError):
        demo.reset_demo_dir(tmp_path)
