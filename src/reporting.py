"""Report building and CSV export.

Turns change-detection results into the findings table shown in the dashboard,
into downloadable CSV files, and into plain-text reports for the demo.
"""

from __future__ import annotations

import textwrap
from typing import Iterable, Optional, Sequence

import pandas as pd

from .change_detector import CATEGORY_ORDER
from .models import ChangeResult, ImportResult

FINDING_COLUMNS = {
    "asset_name": "Asset",
    "cve_id": "CVE",
    "scan_date": "Latest relevant scan date",
    "finding_status": "Finding status",
    "kev_match_status": "KEV match",
    "kev_date_added": "KEV date added",
    "previous_snapshot": "Previous catalog snapshot",
    "current_snapshot": "Current catalog snapshot",
    "kev_change": "KEV catalog change",
    "change_category": "Change category",
    "explanation": "Why it was flagged",
    "recommended_action": "Recommended verification",
    "scan_group": "Comparable scan group",
    "compared_to_scan_date": "Compared with later scan dated",
    "kev_vulnerability_name": "KEV vulnerability name",
}

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def results_to_dataframe(results: Iterable[ChangeResult]) -> pd.DataFrame:
    """Convert results into a table with readable column names (empty table if no results)."""
    rows = [{label: getattr(r, field) for field, label in FINDING_COLUMNS.items()} for r in results]
    return pd.DataFrame(rows, columns=list(FINDING_COLUMNS.values()))


def filter_results(
    table: pd.DataFrame,
    *,
    assets: Optional[Sequence[str]] = None,
    cve_text: str = "",
    statuses: Optional[Sequence[str]] = None,
    categories: Optional[Sequence[str]] = None,
) -> pd.DataFrame:
    """Apply the dashboard filters. An empty selection means 'no restriction'."""
    view = table
    if assets:
        view = view[view["Asset"].isin(list(assets))]
    if cve_text.strip():
        view = view[view["CVE"].str.contains(cve_text.strip().upper(), regex=False)]
    if statuses:
        view = view[view["Finding status"].isin(list(statuses))]
    if categories:
        view = view[view["Change category"].isin(list(categories))]
    return view.reset_index(drop=True)


def category_counts(table: pd.DataFrame) -> dict:
    """Number of rows per change category, in display order (zeros included)."""
    counts = table["Change category"].value_counts().to_dict() if not table.empty else {}
    return {name: int(counts.get(name, 0)) for name in CATEGORY_ORDER}


def neutralize_formulas(value):
    """Prefix a quote to text that a spreadsheet could run as a formula (CSV injection)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def dataframe_to_csv_bytes(table: pd.DataFrame) -> bytes:
    """CSV bytes (UTF-8 with BOM so Excel on Windows shows the characters correctly)."""
    safe = table.copy()
    for column in safe.columns:
        safe[column] = safe[column].map(neutralize_formulas)
    return safe.to_csv(index=False).encode("utf-8-sig")


def validation_report_dataframe(result: ImportResult) -> pd.DataFrame:
    """One row per rejected or duplicate input row, with an actionable message."""
    rows = []
    for item in result.rejected:
        rows.append(
            {
                "row": item.row_number,
                "outcome": "rejected",
                "asset_name": item.values.get("asset_name", ""),
                "cve_id": item.values.get("cve_id", ""),
                "scan_date": item.values.get("scan_date", ""),
                "finding_status": item.values.get("finding_status", ""),
                "message": "; ".join(item.reasons),
            }
        )
    for item in result.duplicates:
        note = f"duplicate of row {item.first_row_number} (same asset and CVE); this row was ignored"
        if item.status_differs:
            note += " and its different finding_status was NOT used"
        rows.append(
            {
                "row": item.row_number,
                "outcome": "duplicate",
                "asset_name": item.asset_name,
                "cve_id": item.cve_id,
                "scan_date": item.scan_date,
                "finding_status": item.finding_status,
                "message": note,
            }
        )
    columns = ["row", "outcome", "asset_name", "cve_id", "scan_date", "finding_status", "message"]
    table = pd.DataFrame(rows, columns=columns)
    return table.sort_values("row").reset_index(drop=True) if not table.empty else table


def import_summary(result: ImportResult) -> dict:
    return {
        "Rows read": result.total_rows,
        "Accepted": result.accepted_count,
        "Rejected": result.rejected_count,
        "Duplicates ignored": result.duplicate_count,
    }


def format_text_report(title: str, results: Sequence[ChangeResult], width: int = 100) -> str:
    """Plain-text report used by the command-line demo and the demo script."""
    lines = [title, "=" * len(title)]
    if not results:
        lines.append("(no findings)")
        return "\n".join(lines)
    counts: dict = {}
    for r in results:
        counts[r.change_category] = counts.get(r.change_category, 0) + 1
    lines.append("Summary: " + ", ".join(f"{name}: {counts[name]}" for name in CATEGORY_ORDER if name in counts))
    lines.append("")
    for r in results:
        lines.append(f"[{r.change_category}] {r.asset_name} | {r.cve_id} | scan {r.scan_date} | status {r.finding_status}")
        for chunk in (r.explanation, "Next step: " + r.recommended_action):
            lines.extend(textwrap.wrap(chunk, width=width, initial_indent="    ", subsequent_indent="    "))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
