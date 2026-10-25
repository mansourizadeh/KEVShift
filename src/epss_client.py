"""Optional FIRST EPSS integration (supplementary information only).

EPSS estimates the probability that a CVE will be exploited in the wild soon.
KEV records vulnerabilities for which exploitation has actually been documented.
EPSS never replaces KEV change detection; it is shown separately and clearly labelled.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Optional

import requests

from . import database
from .models import EpssScore
from .validators import normalize_cve_id, parse_iso_date

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 50
DEFAULT_TIMEOUT_SECONDS = 20
STALE_AFTER = timedelta(days=2)


class EpssError(Exception):
    """The EPSS service could not be used."""


def parse_epss_response(raw) -> list:
    """Validate an EPSS API response body and return (cve, epss, percentile, date) tuples."""
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        data = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EpssError(f"The EPSS response is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise EpssError("The EPSS response has no 'data' list.")

    rows = []
    for item in data["data"]:
        if not isinstance(item, dict):
            raise EpssError("An EPSS record is not an object.")
        cve = normalize_cve_id(item.get("cve"))
        try:
            epss = float(item.get("epss"))
            percentile = float(item.get("percentile"))
        except (TypeError, ValueError) as exc:
            raise EpssError(f"Invalid EPSS numbers for {item.get('cve')!r}.") from exc
        score_date = str(item.get("date", "")).strip()
        if cve is None or not (0.0 <= epss <= 1.0) or not (0.0 <= percentile <= 1.0):
            raise EpssError(f"Invalid EPSS record for {item.get('cve')!r}.")
        if parse_iso_date(score_date) is None:
            raise EpssError(f"Invalid EPSS date for {cve}: {score_date!r}.")
        rows.append((cve, epss, percentile, score_date))
    return rows


def fetch_epss_scores(cve_ids: Iterable[str], *, session=None, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> list:
    """Request EPSS values from the official API in small batches."""
    valid = sorted({c for c in (normalize_cve_id(x) for x in cve_ids) if c})
    client = session if session is not None else requests
    rows: list = []
    for start in range(0, len(valid), BATCH_SIZE):
        batch = valid[start : start + BATCH_SIZE]
        try:
            response = client.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=timeout)
        except requests.RequestException as exc:
            raise EpssError(f"Network error while contacting FIRST: {exc}") from exc
        if response.status_code != 200:
            raise EpssError(f"FIRST returned HTTP status {response.status_code}, not 200.")
        rows.extend(parse_epss_response(response.content))
    return rows


def _is_stale(fetched_at: str, now: datetime) -> bool:
    fetched = datetime.strptime(fetched_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return now - fetched > STALE_AFTER


def read_cached(conn: sqlite3.Connection, cve_ids: Iterable[str], now: Optional[datetime] = None) -> dict:
    """Cached EPSS values for the given CVEs, each flagged as stale when older than two days."""
    moment = now or datetime.now(timezone.utc)
    wanted = sorted({c for c in (normalize_cve_id(x) for x in cve_ids) if c})
    scores: dict = {}
    for start in range(0, len(wanted), 500):
        batch = wanted[start : start + 500]
        marks = ",".join("?" for _ in batch)
        for row in conn.execute(f"SELECT * FROM epss_cache WHERE cve_id IN ({marks})", batch):
            scores[row["cve_id"]] = EpssScore(
                cve_id=row["cve_id"],
                epss=row["epss"],
                percentile=row["percentile"],
                score_date=row["score_date"],
                fetched_at=row["fetched_at"],
                source="cached",
                stale=_is_stale(row["fetched_at"], moment),
            )
    return scores


@dataclass
class EpssRefresh:
    ok: bool
    message: str
    scores: dict = field(default_factory=dict)


def refresh_epss(
    conn: sqlite3.Connection,
    cve_ids: Iterable[str],
    *,
    fetch: Optional[Callable[[list], list]] = None,
    now: Optional[datetime] = None,
) -> EpssRefresh:
    """Fetch EPSS values and cache them; on failure return the cached values instead."""
    moment = now or datetime.now(timezone.utc)
    wanted = sorted({c for c in (normalize_cve_id(x) for x in cve_ids) if c})
    if not wanted:
        return EpssRefresh(True, "There are no CVEs to look up.", {})
    fetch = fetch or fetch_epss_scores
    stamp = database.utc_timestamp(moment)
    try:
        rows = fetch(wanted)
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO epss_cache (cve_id, epss, percentile, score_date, fetched_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [(cve, epss, pct, day, stamp) for cve, epss, pct, day in rows],
            )
    except (EpssError, sqlite3.Error) as exc:
        logger.warning("EPSS refresh failed: %s", exc)
        cached = read_cached(conn, wanted, moment)
        return EpssRefresh(False, f"EPSS refresh FAILED ({exc}). Showing cached values where available.", cached)

    live = {
        cve: EpssScore(cve, epss, pct, day, stamp, source="live", stale=False) for cve, epss, pct, day in rows
    }
    return EpssRefresh(True, f"EPSS values retrieved live for {len(live)} CVE(s).", live)
