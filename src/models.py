"""Plain data containers shared between modules.

They hold data only (no database or network code), which keeps the modules
independent and easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- scans
@dataclass(frozen=True)
class FindingRow:
    """One validated finding: an asset reported with a CVE on a scan date."""

    asset_name: str
    cve_id: str
    scan_date: str  # YYYY-MM-DD
    finding_status: str
    source_row: int = 0  # spreadsheet row in the uploaded file (header is row 1)
    scan_run_id: int = 0  # filled in when read back from the database


@dataclass(frozen=True)
class RejectedRow:
    """A row that failed validation, with every reason it failed."""

    row_number: int
    values: dict
    reasons: tuple


@dataclass(frozen=True)
class DuplicateRow:
    """A row ignored because the same asset and CVE already appeared in the file."""

    row_number: int
    first_row_number: int
    asset_name: str
    cve_id: str
    scan_date: str
    finding_status: str
    status_differs: bool


@dataclass
class ImportResult:
    """Outcome of validating one CSV file."""

    total_rows: int
    accepted: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    duplicates: list = field(default_factory=list)
    scan_date: Optional[str] = None  # latest scan_date among accepted rows

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicates)


@dataclass(frozen=True)
class ScanRunInfo:
    """A stored scan import (one uploaded CSV file)."""

    id: int
    source_filename: str
    scan_date: str
    comparable_group: Optional[str]
    imported_at: str
    rows_total: int
    rows_accepted: int
    rows_rejected: int
    rows_duplicate: int
    file_sha256: str = ""
    stored_path: str = ""


# ----------------------------------------------------------------------------- KEV
@dataclass(frozen=True)
class KevEntry:
    """One vulnerability in a KEV catalog snapshot."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware_use: str = ""


@dataclass(frozen=True)
class KevSnapshot:
    """A parsed and validated KEV catalog."""

    catalog_version: str
    date_released: str
    entries: tuple


@dataclass(frozen=True)
class SnapshotInfo:
    """A KEV snapshot as stored in the database."""

    id: int
    catalog_version: str
    date_released: str
    retrieved_at: str  # UTC, YYYY-MM-DDTHH:MM:SSZ
    source_url: str
    entry_count: int
    stored_path: str
    content_sha256: str


# ------------------------------------------------------------------------- results
@dataclass(frozen=True)
class ChangeResult:
    """One explainable row of the findings table."""

    asset_name: str
    cve_id: str
    scan_date: str
    finding_status: str
    scan_group: str
    kev_match_status: str
    kev_date_added: str
    kev_vulnerability_name: str
    previous_snapshot: str
    current_snapshot: str
    kev_change: str
    change_category: str
    explanation: str
    recommended_action: str
    compared_to_scan_date: str = ""


@dataclass(frozen=True)
class EpssScore:
    """A FIRST EPSS value for one CVE (supplementary information)."""

    cve_id: str
    epss: float
    percentile: float
    score_date: str
    fetched_at: str
    source: str = "cached"  # "live" or "cached"
    stale: bool = False
