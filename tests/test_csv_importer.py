"""Phase 2 tests: CSV import and CVE validation."""

from datetime import date

import pytest

from src import csv_importer
from src.csv_importer import CsvFormatError, parse_csv_bytes
from src.validators import normalize_cve_id

TODAY = date(2026, 1, 1)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("CVE-2024-12345", "CVE-2024-12345"),
        ("  cve-2024-12345  ", "CVE-2024-12345"),
        ("Cve-1999-0001", "CVE-1999-0001"),
        ("CVE-2021-1234567", "CVE-2021-1234567"),
        ("\tCVE-2099-0001\n", "CVE-2099-0001"),
    ],
)
def test_valid_cve_ids_are_normalized(raw, expected):
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "CVE-24-12345", "CVE-2024-123", "CVE-2024-12345 extra", "2024-12345", "CVE-2024-12A45",
     "CVE-1998-1234", "XCVE-2024-12345", "CVE-2024-١٢٣٤٥", None],
)
def test_invalid_cve_ids_are_rejected(raw):
    assert normalize_cve_id(raw) is None


def test_invalid_cve_row_is_rejected_without_crashing(make_csv):
    data = make_csv([("web-01", "NOT-A-CVE", "2025-10-01", "open"), ("web-01", "cve-2099-0001", "2025-10-01", "open")])
    result = parse_csv_bytes(data, today=TODAY)
    assert result.accepted_count == 1 and result.accepted[0].cve_id == "CVE-2099-0001"
    assert result.rejected_count == 1
    assert "not a valid CVE identifier" in result.rejected[0].reasons[0]
    assert result.rejected[0].row_number == 2


def test_missing_columns_raise_a_clear_error():
    with pytest.raises(CsvFormatError) as error:
        parse_csv_bytes(b"asset_name,cve_id\nweb-01,CVE-2099-0001\n", today=TODAY)
    assert "scan_date" in str(error.value) and "finding_status" in str(error.value)


@pytest.mark.parametrize("bad_date", ["01/10/2025", "2025-13-01", "2025-02-30", "yesterday", "2025-1-5", "2999-01-01"])
def test_invalid_scan_dates_are_rejected(make_csv, bad_date):
    result = parse_csv_bytes(make_csv([("web-01", "CVE-2099-0001", bad_date, "open")]), today=TODAY)
    assert result.accepted_count == 0 and result.rejected_count == 1
    assert "scan_date" in result.rejected[0].reasons[0]


def test_missing_required_fields_list_every_problem(make_csv):
    result = parse_csv_bytes(make_csv([("", "", "", "")]) + b"x,CVE-2099-0001,2025-10-01,open\n", today=TODAY)
    assert result.rejected_count == 1  # the all-empty row
    assert result.accepted_count == 1
    rows = parse_csv_bytes(make_csv([("", "CVE-2099-0001", "", "open")]), today=TODAY).rejected
    assert len(rows[0].reasons) == 2  # asset_name and scan_date both reported


def test_duplicate_rows_are_counted_and_not_silently_lost(make_csv):
    data = make_csv([
        ("web-01", "CVE-2099-0001", "2025-10-01", "open"),
        ("WEB-01", "cve-2099-0001", "2025-10-01", "mitigated"),
        ("web-02", "CVE-2099-0001", "2025-10-01", "open"),
    ])
    result = parse_csv_bytes(data, today=TODAY)
    assert (result.total_rows, result.accepted_count, result.duplicate_count, result.rejected_count) == (3, 2, 1, 0)
    duplicate = result.duplicates[0]
    assert duplicate.first_row_number == 2 and duplicate.status_differs


def test_status_is_normalized_and_validated(make_csv):
    result = parse_csv_bytes(make_csv([
        ("a", "CVE-2099-0001", "2025-10-01", "Open"),
        ("b", "CVE-2099-0001", "2025-10-01", "False Positive"),
        ("c", "CVE-2099-0001", "2025-10-01", "fixed"),
    ]), today=TODAY)
    assert [r.finding_status for r in result.accepted] == ["open", "false_positive"]
    assert "not allowed" in result.rejected[0].reasons[0]


def test_unusable_files_raise_format_errors():
    for data in (b"", b"   \n", b"\x00\x01\x02binary", "asset_name\xff".encode("latin-1"), b"asset_name,cve_id,scan_date,finding_status\n"):
        with pytest.raises(CsvFormatError):
            parse_csv_bytes(data, today=TODAY)


def test_excel_bom_and_uppercase_headers_are_accepted():
    data = "﻿Asset_Name,CVE_ID,Scan_Date,Finding_Status\nweb-01,CVE-2099-0001,2025-10-01,open\n".encode("utf-8")
    assert parse_csv_bytes(data, today=TODAY).accepted_count == 1


def test_scan_date_is_latest_accepted_date(make_csv):
    result = parse_csv_bytes(make_csv([("a", "CVE-2099-0001", "2025-10-01", "open"), ("b", "CVE-2099-0002", "2025-10-03", "open")]), today=TODAY)
    assert result.scan_date == "2025-10-03"


def test_csv_content_is_never_executed(make_csv):
    result = parse_csv_bytes(make_csv([("=cmd|' /C calc'!A0", "CVE-2099-0001", "2025-10-01", "open")]), today=TODAY)
    assert result.accepted[0].asset_name.startswith("=")  # kept as plain text, never evaluated


def test_sample_files_behave_as_documented(sample_dir):
    good = parse_csv_bytes((sample_dir / "sample_scan_previous.csv").read_bytes(), today=TODAY)
    assert (good.accepted_count, good.rejected_count, good.duplicate_count) == (5, 0, 0)
    bad = parse_csv_bytes((sample_dir / "sample_scan_invalid.csv").read_bytes(), today=TODAY)
    assert (bad.accepted_count, bad.rejected_count, bad.duplicate_count) == (2, 4, 1)


def test_allowed_statuses_are_documented():
    assert set(csv_importer.ALLOWED_STATUSES) == {"open", "in_progress", "mitigated", "accepted_risk", "false_positive"}
