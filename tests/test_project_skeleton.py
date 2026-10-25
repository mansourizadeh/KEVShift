"""Phase 1 smoke tests: the project skeleton is complete and importable."""

import importlib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CORE_MODULES = [
    "src.csv_importer",
    "src.database",
    "src.kev_client",
    "src.change_detector",
    "src.reporting",
]


@pytest.mark.parametrize("module_name", CORE_MODULES)
def test_core_module_imports(module_name):
    """Every core module can be imported without errors."""
    assert importlib.import_module(module_name) is not None


def test_expected_folders_exist():
    """Source, tests, sample data and generated-data folders are kept separate."""
    for folder in ["src", "tests", "sample_data", "data", "docs"]:
        assert (PROJECT_ROOT / folder).is_dir(), f"missing folder: {folder}"


def test_requirements_lists_core_dependencies():
    """requirements.txt names every package the project is allowed to use."""
    text = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for package in ["streamlit", "pandas", "requests", "pytest"]:
        assert package in text


def test_kev_feed_url_is_the_official_cisa_feed():
    """The configured data source is the official CISA JSON feed over HTTPS."""
    from src.kev_client import KEV_FEED_URL

    assert KEV_FEED_URL.startswith("https://www.cisa.gov/")
    assert KEV_FEED_URL.endswith("known_exploited_vulnerabilities.json")
