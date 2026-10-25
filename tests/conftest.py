"""Shared fixtures. All data is synthetic; no test needs the internet."""

import json
from pathlib import Path

import pytest

from src import database

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"


@pytest.fixture
def sample_dir():
    return SAMPLE_DIR


@pytest.fixture
def conn():
    """A fresh in-memory database."""
    connection = database.connect(":memory:")
    database.init_schema(connection)
    yield connection
    connection.close()


@pytest.fixture
def data_dir(tmp_path):
    """A temporary folder standing in for the project's data/ folder."""
    return tmp_path / "data"


@pytest.fixture
def make_kev_json():
    """Build KEV JSON bytes. cves maps CVE ID -> dateAdded."""

    def build(version="v1", released="2025-01-01T00:00:00.000Z", cves=None, count=None):
        cves = {"CVE-2099-0001": "2025-01-01"} if cves is None else cves
        vulns = [
            {
                "cveID": cve,
                "vendorProject": "Vendor (synthetic)",
                "product": "Product (synthetic)",
                "vulnerabilityName": f"Synthetic issue {cve}",
                "dateAdded": added,
                "shortDescription": "synthetic",
                "requiredAction": "synthetic",
                "dueDate": "2025-02-01",
                "knownRansomwareCampaignUse": "Unknown",
            }
            for cve, added in cves.items()
        ]
        doc = {
            "catalogVersion": version,
            "dateReleased": released,
            "count": len(vulns) if count is None else count,
            "vulnerabilities": vulns,
        }
        return json.dumps(doc).encode("utf-8")

    return build


@pytest.fixture
def make_csv():
    """Build CSV bytes from (asset, cve, date, status) tuples."""

    def build(rows):
        lines = ["asset_name,cve_id,scan_date,finding_status"]
        lines += [",".join(row) for row in rows]
        return ("\n".join(lines) + "\n").encode("utf-8")

    return build
