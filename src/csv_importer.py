"""CSV import and validation.

Reads a scan CSV with the columns asset_name, cve_id, scan_date and finding_status,
validates every row, detects duplicates and reports exactly what was accepted,
rejected or ignored. Nothing here touches the database or the network.

Input:  the raw bytes of an uploaded CSV file.
Output: an ImportResult (accepted rows, rejected rows with reasons, duplicates).
"""

from __future__ import annotations

import hashlib
import io
from datetime import date
from typing import Optional

import pandas as pd

from .models import DuplicateRow, FindingRow, ImportResult, RejectedRow
from .validators import asset_key, clean_asset_name, normalize_cve_id, parse_iso_date

REQUIRED_COLUMNS = ("asset_name", "cve_id", "scan_date", "finding_status")

ALLOWED_STATUSES = {
    "open": "The scanner reports the vulnerability as present.",
    "in_progress": "The finding is being worked on.",
    "mitigated": "A mitigation is recorded, but the vulnerability may still exist.",
    "accepted_risk": "The organization decided to accept the risk.",
    "false_positive": "The finding was judged to be a scanner mistake.",
}

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ASSET_NAME_LENGTH = 255


class CsvFormatError(ValueError):
    """The file as a whole cannot be used (wrong columns, not text, empty...)."""


def sha256_hex(data: bytes) -> str:
    """Fingerprint of the file content, used to recognize a re-uploaded file."""
    return hashlib.sha256(data).hexdigest()


def decode_csv_bytes(data: bytes) -> str:
    """Decode uploaded bytes as UTF-8 text (an Excel BOM is accepted)."""
    if not data or not data.strip():
        raise CsvFormatError("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise CsvFormatError(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
    if b"\x00" in data:
        raise CsvFormatError("The file looks like a binary file, not a CSV text file.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvFormatError(
            "The file is not UTF-8 text. In Excel use 'Save as > CSV UTF-8 (Comma delimited)'."
        ) from exc


def _read_table(text: str) -> pd.DataFrame:
    """Read the CSV text into a table of strings and check the header."""
    try:
        table = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            skip_blank_lines=False,
        )
    except pd.errors.EmptyDataError as exc:
        raise CsvFormatError("The file has no header row.") from exc
    except pd.errors.ParserError as exc:
        raise CsvFormatError(f"The file could not be read as CSV: {exc}") from exc

    table.columns = [str(name).strip().lower() for name in table.columns]
    missing = [name for name in REQUIRED_COLUMNS if name not in table.columns]
    if missing:
        raise CsvFormatError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Found: {', '.join(table.columns)}. "
            f"Required: {', '.join(REQUIRED_COLUMNS)}."
        )
    if table.empty:
        raise CsvFormatError("The file has a header but no data rows.")
    return table


def _normalize_status(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _validate_row(values: dict, row_number: int, today: date):
    """Validate one row. Returns (FindingRow or None, list of problems)."""
    problems: list[str] = []

    asset = clean_asset_name(values["asset_name"])
    if not asset:
        problems.append("asset_name is missing")
    elif len(asset) > MAX_ASSET_NAME_LENGTH:
        problems.append(f"asset_name is longer than {MAX_ASSET_NAME_LENGTH} characters")

    raw_cve = values["cve_id"].strip()
    cve = normalize_cve_id(raw_cve)
    if not raw_cve:
        problems.append("cve_id is missing")
    elif cve is None:
        problems.append(
            f"cve_id '{raw_cve}' is not a valid CVE identifier "
            "(expected CVE-YYYY-NNNN with at least 4 digits, e.g. CVE-2024-12345)"
        )

    raw_date = values["scan_date"].strip()
    parsed = parse_iso_date(raw_date)
    if not raw_date:
        problems.append("scan_date is missing")
    elif parsed is None:
        problems.append(f"scan_date '{raw_date}' is not a valid date (use YYYY-MM-DD, e.g. 2025-10-01)")
    elif parsed > today:
        problems.append(f"scan_date '{raw_date}' is in the future")

    raw_status = values["finding_status"].strip()
    status = _normalize_status(raw_status)
    if not raw_status:
        problems.append("finding_status is missing")
    elif status not in ALLOWED_STATUSES:
        problems.append(
            f"finding_status '{raw_status}' is not allowed (use one of: {', '.join(ALLOWED_STATUSES)})"
        )

    if problems:
        return None, problems
    return FindingRow(asset, cve, parsed.isoformat(), status, source_row=row_number), []


def parse_csv_bytes(data: bytes, *, today: Optional[date] = None) -> ImportResult:
    """Validate a CSV file and return what was accepted, rejected and ignored.

    Raises CsvFormatError only when the whole file is unusable. Individual bad rows
    never raise: they are collected in ``result.rejected`` with their reasons.
    """
    today = today or date.today()
    table = _read_table(decode_csv_bytes(data))
    records = table.to_dict("records")

    result = ImportResult(total_rows=len(records))
    first_seen: dict = {}

    for position, record in enumerate(records):
        row_number = position + 2  # row 1 is the header, as in a spreadsheet
        values = {name: str(record.get(name, "")) for name in REQUIRED_COLUMNS}

        if all(str(cell).strip() == "" for cell in record.values()):
            result.rejected.append(RejectedRow(row_number, values, ("the row is completely empty",)))
            continue

        finding, problems = _validate_row(values, row_number, today)
        if finding is None:
            result.rejected.append(RejectedRow(row_number, values, tuple(problems)))
            continue

        key = (asset_key(finding.asset_name), finding.cve_id)
        if key in first_seen:
            first = first_seen[key]
            result.duplicates.append(
                DuplicateRow(
                    row_number=row_number,
                    first_row_number=first.source_row,
                    asset_name=finding.asset_name,
                    cve_id=finding.cve_id,
                    scan_date=finding.scan_date,
                    finding_status=finding.finding_status,
                    status_differs=finding.finding_status != first.finding_status,
                )
            )
            continue

        first_seen[key] = finding
        result.accepted.append(finding)

    if result.accepted:
        result.scan_date = max(row.scan_date for row in result.accepted)
    return result
