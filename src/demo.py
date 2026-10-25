"""Synthetic demonstration scenario (all data is invented and labelled synthetic).

Timeline reproduced from the project specification:
  Step 1  1 Oct  KEV snapshot A is stored, then a scan reports CVE-2099-0001 (not in snapshot A).
  Step 2  15 Oct KEV snapshot B is stored and lists CVE-2099-0001. NO new scan was imported.
  Step 3  22 Oct A later scan of the same comparable group no longer contains one finding.

Run it from the command line with:   python -m src.demo
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from . import database, kev_client, reporting, workflow

DEMO_GROUP = "internal-weekly (synthetic)"


@dataclass(frozen=True)
class DemoStep:
    number: int
    title: str
    kev_file: Optional[str]
    kev_retrieved_at: Optional[str]
    scan_file: Optional[str]
    scan_imported_at: Optional[str]


STEPS = (
    DemoStep(
        1,
        "Step 1 - 1 October: KEV snapshot A stored, then scan 1 imported",
        "sample_kev_previous.json",
        "2025-10-01T08:00:00Z",
        "sample_scan_previous.csv",
        "2025-10-01T12:00:00Z",
    ),
    DemoStep(
        2,
        "Step 2 - 15 October: KEV snapshot B stored (no new scan imported)",
        "sample_kev_current.json",
        "2025-10-15T08:00:00Z",
        None,
        None,
    ),
    DemoStep(
        3,
        "Step 3 - 22 October: scan 2 (comparable) imported",
        None,
        None,
        "sample_scan_latest.csv",
        "2025-10-22T12:00:00Z",
    ),
)


@dataclass
class DemoReport:
    step: DemoStep
    results: list
    text: str


def _apply_one(conn: sqlite3.Connection, data_dir: Path, sample_dir: Path, step: DemoStep) -> list:
    messages = []
    if step.kev_file:
        raw = (sample_dir / step.kev_file).read_bytes()
        _, created = kev_client.store_snapshot_bytes(
            conn,
            raw,
            data_dir,
            source_url=f"synthetic-fixture:{step.kev_file}",
            retrieved_at=step.kev_retrieved_at,
        )
        messages.append(f"KEV snapshot {'stored' if created else 'already stored'}: {step.kev_file}")
    if step.scan_file:
        data = (sample_dir / step.scan_file).read_bytes()
        try:
            outcome = workflow.import_scan(
                conn, data_dir, data, step.scan_file, DEMO_GROUP, step.scan_imported_at
            )
            messages.append(f"{step.scan_file}: {outcome.message}")
        except database.DuplicateImportError:
            messages.append(f"{step.scan_file}: already imported")
    return messages


def apply_step(
    conn: sqlite3.Connection, data_dir: Union[str, Path], sample_dir: Union[str, Path], number: int
) -> list:
    """Load demo steps 1..number (safe to repeat; already loaded data is skipped)."""
    messages = []
    for step in STEPS:
        if step.number <= number:
            messages.extend(_apply_one(conn, Path(data_dir), Path(sample_dir), step))
    return messages


def reset_demo_dir(data_dir: Union[str, Path]) -> None:
    """Delete a demo data folder. Refuses to delete anything not named 'demo' or 'demo_cli'."""
    path = Path(data_dir)
    if path.name not in ("demo", "demo_cli"):
        raise ValueError("Refusing to delete a folder that is not a demo folder.")
    if path.exists():
        shutil.rmtree(path)


def run_demo(
    data_dir: Union[str, Path],
    sample_dir: Union[str, Path],
    out_dir: Optional[Union[str, Path]] = None,
) -> list:
    """Run the whole scenario in a fresh database and return one report per step."""
    data_dir, sample_dir = Path(data_dir), Path(sample_dir)
    reset_demo_dir(data_dir)
    conn = database.connect(data_dir / "kevshift.db")
    database.init_schema(conn)
    reports = []
    try:
        for step in STEPS:
            _apply_one(conn, data_dir, sample_dir, step)
            bundle = workflow.run_analysis(conn)
            text = reporting.format_text_report(step.title, bundle.results)
            reports.append(DemoReport(step, bundle.results, text))
            if out_dir is not None:
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                table = reporting.results_to_dataframe(bundle.results)
                (out / f"demo_step{step.number}_report.csv").write_bytes(
                    reporting.dataframe_to_csv_bytes(table)
                )
                (out / f"demo_step{step.number}_report.txt").write_text(text, encoding="utf-8")
    finally:
        conn.close()
    return reports


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    reports = run_demo(root / "data" / "demo_cli", root / "sample_data", root / "data" / "demo_reports")
    for report in reports:
        print(report.text)
    print("CSV and text copies of these reports were saved in data/demo_reports/")


if __name__ == "__main__":
    main()
