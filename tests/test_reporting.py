"""Phase 6 tests: reporting and CSV export."""

import io
from datetime import date

import pandas as pd

from src import change_detector as cd
from src import csv_importer, reporting
from src.models import ChangeResult

TODAY = date(2026, 1, 1)


def result(asset="web-01", cve="CVE-2099-0001", category=cd.CAT_NEWLY_ADDED, status="open", explanation="why"):
    return ChangeResult(asset, cve, "2025-10-01", status, "weekly", "Listed in KEV", "2025-10-14", "name",
                        "A", "B", "Newly added since the previous snapshot", category, explanation, "verify")


def sample_table():
    return reporting.results_to_dataframe([
        result("web-01", "CVE-2099-0001", cd.CAT_NEWLY_ADDED),
        result("db-02", "CVE-2099-0002", cd.CAT_LISTED, "mitigated"),
        result("db-02", "CVE-2099-0003", cd.CAT_NO_MATCH),
    ])


def test_table_has_every_required_column():
    required = {"Asset", "CVE", "Latest relevant scan date", "Finding status", "KEV match", "KEV date added",
                "Previous catalog snapshot", "Current catalog snapshot", "Change category",
                "Why it was flagged", "Recommended verification"}
    assert required <= set(sample_table().columns)


def test_empty_results_give_an_empty_table_with_columns():
    table = reporting.results_to_dataframe([])
    assert table.empty and "Asset" in table.columns
    assert reporting.category_counts(table)[cd.CAT_NEWLY_ADDED] == 0


def test_filters_combine_and_empty_selection_means_all():
    table = sample_table()
    assert len(reporting.filter_results(table)) == 3
    assert list(reporting.filter_results(table, assets=["db-02"])["CVE"]) == ["CVE-2099-0002", "CVE-2099-0003"]
    assert list(reporting.filter_results(table, cve_text="0003")["CVE"]) == ["CVE-2099-0003"]
    assert len(reporting.filter_results(table, assets=["db-02"], statuses=["mitigated"])) == 1
    assert len(reporting.filter_results(table, categories=[cd.CAT_NEWLY_ADDED])) == 1


def test_csv_report_round_trips_and_contains_explanations():
    data = reporting.dataframe_to_csv_bytes(sample_table())
    assert data.startswith(b"\xef\xbb\xbf")  # BOM so Excel on Windows reads UTF-8
    back = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
    assert len(back) == 3 and back.loc[0, "Why it was flagged"] == "why"


def test_csv_export_neutralizes_spreadsheet_formulas():
    table = reporting.results_to_dataframe([result(asset="=HYPERLINK(\"http://evil\")", explanation="+cmd")])
    text = reporting.dataframe_to_csv_bytes(table).decode("utf-8-sig")
    assert "'=HYPERLINK" in text and "'+cmd" in text
    assert reporting.neutralize_formulas("normal text") == "normal text"


def test_validation_report_lists_rejected_and_duplicate_rows(sample_dir):
    imported = csv_importer.parse_csv_bytes((sample_dir / "sample_scan_invalid.csv").read_bytes(), today=TODAY)
    report = reporting.validation_report_dataframe(imported)
    assert list(report["outcome"]).count("rejected") == 4 and list(report["outcome"]).count("duplicate") == 1
    assert list(report["row"]) == sorted(report["row"])
    assert report["message"].str.len().min() > 10  # every row has an actionable message
    assert reporting.dataframe_to_csv_bytes(report)  # downloadable


def test_import_summary_counts():
    imported = csv_importer.parse_csv_bytes(b"asset_name,cve_id,scan_date,finding_status\na,CVE-2099-0001,2025-10-01,open\n", today=TODAY)
    assert reporting.import_summary(imported) == {"Rows read": 1, "Accepted": 1, "Rejected": 0, "Duplicates ignored": 0}


def test_text_report_mentions_every_row():
    text = reporting.format_text_report("Title", [result(), result(cve="CVE-2099-0002", category=cd.CAT_LISTED)])
    assert "CVE-2099-0001" in text and "CVE-2099-0002" in text and "Summary:" in text
