"""CISA KEV download, validation, snapshot storage and offline fallback.

Safety rules implemented here:
  * every HTTP request has a timeout and its status code is checked;
  * the JSON is validated BEFORE anything is saved;
  * a failed or invalid download never touches stored snapshots;
  * when the network fails, the last valid saved snapshot is reported as cached data,
    and the result says clearly that the refresh did NOT succeed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional, Union

import requests

from . import database
from .models import KevEntry, KevSnapshot, SnapshotInfo
from .validators import normalize_cve_id, parse_iso_date

logger = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
STALE_AFTER_DAYS = 7


class KevError(Exception):
    """Base class for KEV problems."""


class KevDownloadError(KevError):
    """The catalog could not be downloaded."""


class KevFormatError(KevError):
    """The downloaded data is not a valid, complete KEV catalog."""


# ------------------------------------------------------------------------ parsing
def _text(item: dict, key: str) -> str:
    value = item.get(key, "")
    return "" if value is None else str(value)


def parse_kev_json(raw: Union[bytes, str]) -> KevSnapshot:
    """Validate KEV JSON and convert it into a KevSnapshot.

    Raises KevFormatError for malformed, incomplete or inconsistent data.
    """
    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KevFormatError(f"The response is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise KevFormatError("The JSON top level must be an object.")

    version = data.get("catalogVersion")
    released = data.get("dateReleased")
    if not isinstance(version, str) or not version.strip():
        raise KevFormatError("The catalog has no 'catalogVersion'.")
    if not isinstance(released, str) or not released.strip():
        raise KevFormatError("The catalog has no 'dateReleased'.")

    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise KevFormatError("The catalog has no 'vulnerabilities' list or it is empty.")

    declared_count = data.get("count")
    if declared_count is not None and declared_count != len(vulnerabilities):
        raise KevFormatError(
            f"The catalog declares {declared_count} entries but contains {len(vulnerabilities)}; "
            "the response looks incomplete."
        )

    entries: list = []
    seen: set = set()
    for index, item in enumerate(vulnerabilities, start=1):
        if not isinstance(item, dict):
            raise KevFormatError(f"Entry {index} is not an object.")
        cve_id = normalize_cve_id(item.get("cveID"))
        if cve_id is None:
            raise KevFormatError(f"Entry {index} has an invalid cveID: {item.get('cveID')!r}.")
        if cve_id in seen:
            raise KevFormatError(f"{cve_id} appears more than once.")
        seen.add(cve_id)
        added = _text(item, "dateAdded").strip()
        if parse_iso_date(added) is None:
            raise KevFormatError(f"{cve_id} has an invalid dateAdded: {added!r}.")
        entries.append(
            KevEntry(
                cve_id=cve_id,
                vendor_project=_text(item, "vendorProject"),
                product=_text(item, "product"),
                vulnerability_name=_text(item, "vulnerabilityName"),
                date_added=added,
                short_description=_text(item, "shortDescription"),
                required_action=_text(item, "requiredAction"),
                due_date=_text(item, "dueDate"),
                known_ransomware_use=_text(item, "knownRansomwareCampaignUse"),
            )
        )
    return KevSnapshot(version.strip(), released.strip(), tuple(entries))


def match_cve(cve_id: str, index: dict) -> Optional[KevEntry]:
    """Exact lookup by normalized CVE ID (no substring matching)."""
    return index.get(cve_id)


# ------------------------------------------------------------------------ network
def download_kev_json(
    url: str = KEV_FEED_URL,
    *,
    session=None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> bytes:
    """Download the catalog. Raises KevDownloadError on any network or HTTP problem."""
    client = session if session is not None else requests
    try:
        response = client.get(
            url, timeout=timeout, headers={"User-Agent": "KEVShift/1.0 (student project)"}
        )
    except requests.RequestException as exc:
        raise KevDownloadError(f"Network error while contacting CISA: {exc}") from exc
    if response.status_code != 200:
        raise KevDownloadError(f"CISA returned HTTP status {response.status_code}, not 200.")
    content = response.content
    if not content:
        raise KevDownloadError("CISA returned an empty response.")
    if len(content) > MAX_DOWNLOAD_BYTES:
        raise KevDownloadError("The response is unexpectedly large and was rejected.")
    return content


# ------------------------------------------------------------------------ storage
def _save_snapshot_file(raw: bytes, data_dir: Path, retrieved_at: str, sha256: str) -> Path:
    """Write the raw JSON atomically (temp file, then rename)."""
    folder = Path(data_dir) / "kev_snapshots"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = retrieved_at.replace("-", "").replace(":", "")
    target = folder / f"kev_{stamp}_{sha256[:12]}.json"
    temp = target.with_suffix(".tmp")
    temp.write_bytes(raw)
    os.replace(temp, target)
    return target


def store_snapshot_bytes(
    conn: sqlite3.Connection,
    raw: bytes,
    data_dir: Union[str, Path],
    *,
    source_url: str,
    retrieved_at: str,
) -> tuple:
    """Validate raw KEV JSON, save the file and the database rows.

    Returns (snapshot_id, created). Raises KevFormatError before saving anything if the
    data is invalid, so an invalid response can never replace a valid snapshot.
    """
    snapshot = parse_kev_json(raw)
    sha256 = hashlib.sha256(raw).hexdigest()

    existing = database.find_snapshot_by_sha(conn, sha256)
    written: Optional[Path] = None
    if existing is None:
        written = _save_snapshot_file(raw, Path(data_dir), retrieved_at, sha256)
        stored_path = str(written)
    else:
        info = database.get_snapshot(conn, existing)
        stored_path = info.stored_path if info else ""
    try:
        return database.store_kev_snapshot(
            conn,
            snapshot,
            source_url=source_url,
            retrieved_at=retrieved_at,
            stored_path=stored_path,
            content_sha256=sha256,
        )
    except Exception:
        if written is not None:
            written.unlink(missing_ok=True)
        raise


# ------------------------------------------------------------------------ refresh
@dataclass
class RefreshResult:
    """What happened when a refresh was attempted."""

    status: str  # "refreshed" | "unchanged" | "cached" | "unavailable"
    message: str
    snapshot: Optional[SnapshotInfo] = None
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """True only when CISA was reached and a valid catalog was received."""
        return self.status in ("refreshed", "unchanged")

    @property
    def used_cache(self) -> bool:
        return self.status == "cached"


def refresh_kev(
    conn: sqlite3.Connection,
    data_dir: Union[str, Path],
    *,
    fetch: Optional[Callable[[], bytes]] = None,
    now: Optional[datetime] = None,
) -> RefreshResult:
    """Try to download a fresh catalog; fall back to the last valid snapshot on failure."""
    fetch = fetch or download_kev_json
    moment = now or datetime.now(timezone.utc)
    retrieved_at = database.utc_timestamp(moment)

    try:
        raw = fetch()
        snapshot_id, created = store_snapshot_bytes(
            conn, raw, data_dir, source_url=KEV_FEED_URL, retrieved_at=retrieved_at
        )
    except (KevError, sqlite3.Error, OSError) as exc:
        logger.warning("KEV refresh failed: %s", exc)
        try:
            database.record_event(
                conn, "kev_refresh_failed", f"KEV refresh failed: {exc}", occurred_at=retrieved_at
            )
        except sqlite3.Error:
            logger.exception("Could not record the failed refresh event")
        latest = database.latest_snapshot(conn)
        if latest is None:
            return RefreshResult(
                "unavailable",
                "The refresh failed and no saved KEV snapshot exists yet. "
                "Connect to the internet and try again, or load a KEV JSON file manually.",
                None,
                str(exc),
            )
        age = format_age(snapshot_age(latest.retrieved_at, moment))
        return RefreshResult(
            "cached",
            f"The refresh FAILED ({exc}). Showing the last valid saved snapshot "
            f"(version {latest.catalog_version}, retrieved {latest.retrieved_at}, {age} old).",
            latest,
            str(exc),
        )

    info = database.get_snapshot(conn, snapshot_id)
    if created:
        return RefreshResult(
            "refreshed",
            f"Refresh succeeded: new snapshot saved (version {info.catalog_version}, "
            f"{info.entry_count} entries).",
            info,
        )
    return RefreshResult(
        "unchanged",
        f"Refresh succeeded: CISA was reached and the catalog is unchanged "
        f"(version {info.catalog_version}).",
        info,
    )


# --------------------------------------------------------------------- cache age
def snapshot_age(retrieved_at: str, now: Optional[datetime] = None) -> timedelta:
    """How old a snapshot is, from its stored UTC timestamp."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    stored = datetime.strptime(retrieved_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return max(moment - stored, timedelta(0))


def format_age(age: timedelta) -> str:
    """Human-readable age such as '3 days 4 hours' or '12 minutes'."""
    seconds = int(age.total_seconds())
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} day{'s' if days != 1 else ''} {hours} hour{'s' if hours != 1 else ''}"
    if hours:
        return f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''}"
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


@dataclass
class KevStatus:
    """Summary shown in the dashboard's KEV status panel."""

    snapshot: SnapshotInfo
    last_checked_at: str
    age_text: str
    is_stale: bool


def kev_status(conn: sqlite3.Connection, now: Optional[datetime] = None) -> Optional[KevStatus]:
    """Describe the newest stored snapshot, or None if nothing has been stored yet."""
    latest = database.latest_snapshot(conn)
    if latest is None:
        return None
    check = database.last_successful_check(conn)
    last_checked = check["checked_at"] if check else latest.retrieved_at
    age = snapshot_age(last_checked, now)
    return KevStatus(latest, last_checked, format_age(age), age > timedelta(days=STALE_AFTER_DAYS))
