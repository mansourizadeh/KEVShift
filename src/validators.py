"""Small validation helpers shared by the importer, the KEV client and the EPSS client.

Keeping them in one place means a CVE identifier is validated the same way everywhere.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Optional

MIN_CVE_YEAR = 1999

# [0-9] is used instead of \d on purpose: \d also matches non-ASCII digits
# (for example Persian or Arabic-Indic digits), which are not valid in a CVE ID.
_CVE_PATTERN = re.compile(r"CVE-([0-9]{4})-([0-9]{4,})")
_ISO_DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def normalize_cve_id(value: object) -> Optional[str]:
    """Return the CVE ID in canonical form (upper case, no surrounding spaces).

    Returns None when the value is not a valid CVE identifier.

    >>> normalize_cve_id("  cve-2024-12345 ")
    'CVE-2024-12345'
    >>> normalize_cve_id("CVE-2024-12") is None
    True
    """
    if value is None:
        return None
    text = str(value).strip().upper()
    match = _CVE_PATTERN.fullmatch(text)
    if match is None:
        return None
    if int(match.group(1)) < MIN_CVE_YEAR:
        return None
    return text


def parse_iso_date(value: object) -> Optional[date]:
    """Parse a strict YYYY-MM-DD date. Returns None if it is missing or invalid."""
    if value is None:
        return None
    text = str(value).strip()
    if _ISO_DATE_PATTERN.fullmatch(text) is None:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def clean_asset_name(value: object) -> str:
    """Trim an asset name and collapse repeated internal whitespace."""
    return " ".join(str(value).split())


def asset_key(name: str) -> str:
    """Case-insensitive identity of an asset, so 'Web-01' and 'web-01 ' are the same."""
    return clean_asset_name(name).casefold()
