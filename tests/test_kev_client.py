"""Phase 4 tests: KEV parsing, download (mocked), caching and offline behavior."""

import json
from datetime import datetime, timedelta, timezone

import pytest
import requests

from src import database, kev_client
from src.kev_client import KevDownloadError, KevFormatError, parse_kev_json

NOW = datetime(2025, 10, 15, 9, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, status_code=200, content=b"{}"):
        self.status_code, self.content = status_code, content


class FakeSession:
    """Stands in for requests: records the call and returns or raises what we choose."""

    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response, error, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def test_valid_kev_json_is_parsed(make_kev_json):
    snapshot = parse_kev_json(make_kev_json(version="2025.10.15", cves={"CVE-2099-0001": "2025-10-14", "CVE-2099-0002": "2025-09-01"}))
    assert snapshot.catalog_version == "2025.10.15"
    assert [e.cve_id for e in snapshot.entries] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert snapshot.entries[0].date_added == "2025-10-14"


@pytest.mark.parametrize(
    "raw",
    [b"not json at all", b"[]", b"{}", b'{"catalogVersion":"v","dateReleased":"d","vulnerabilities":[]}',
     b'{"catalogVersion":"v","dateReleased":"d","vulnerabilities":[{"cveID":"BAD","dateAdded":"2025-01-01"}]}',
     b'{"catalogVersion":"v","dateReleased":"d","vulnerabilities":[{"cveID":"CVE-2099-0001","dateAdded":"soon"}]}',
     b"\xff\xfe\x00"],
)
def test_malformed_kev_json_is_rejected(raw):
    with pytest.raises(KevFormatError):
        parse_kev_json(raw)


def test_incomplete_response_is_detected_by_count_mismatch(make_kev_json):
    with pytest.raises(KevFormatError, match="incomplete"):
        parse_kev_json(make_kev_json(count=5))


def test_duplicate_cve_in_feed_is_rejected():
    doc = {"catalogVersion": "v", "dateReleased": "d", "vulnerabilities": [
        {"cveID": "CVE-2099-0001", "dateAdded": "2025-01-01"}, {"cveID": "cve-2099-0001", "dateAdded": "2025-01-02"}]}
    with pytest.raises(KevFormatError, match="more than once"):
        parse_kev_json(json.dumps(doc))


def test_cve_matching_is_exact_never_substring(make_kev_json):
    index = {e.cve_id: e for e in parse_kev_json(make_kev_json(cves={"CVE-2099-00011": "2025-01-01"})).entries}
    assert kev_client.match_cve("CVE-2099-0001", index) is None  # substring of the listed ID
    assert kev_client.match_cve("CVE-2099-00011", index) is not None


def test_download_uses_timeout_and_the_official_url():
    session = FakeSession(FakeResponse(200, b'{"x":1}'))
    assert kev_client.download_kev_json(session=session) == b'{"x":1}'
    url, kwargs = session.calls[0]
    assert url == kev_client.KEV_FEED_URL and kwargs["timeout"] == kev_client.DEFAULT_TIMEOUT_SECONDS


@pytest.mark.parametrize("response", [FakeResponse(404), FakeResponse(500), FakeResponse(200, b"")])
def test_bad_http_responses_raise_download_errors(response):
    with pytest.raises(KevDownloadError):
        kev_client.download_kev_json(session=FakeSession(response))


def test_network_failure_raises_download_error():
    with pytest.raises(KevDownloadError, match="Network error"):
        kev_client.download_kev_json(session=FakeSession(error=requests.ConnectionError("no route")))


def test_successful_refresh_saves_snapshot_file_and_database_rows(conn, data_dir, make_kev_json):
    result = kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(), now=NOW)
    assert result.status == "refreshed" and result.is_success and not result.used_cache
    files = list((data_dir / "kev_snapshots").glob("*.json"))
    assert len(files) == 1 and files[0].read_bytes() == make_kev_json()
    assert database.latest_snapshot(conn).retrieved_at == "2025-10-15T09:00:00Z"


def test_unchanged_feed_is_reported_as_unchanged_success(conn, data_dir, make_kev_json):
    kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(), now=NOW)
    result = kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(), now=NOW + timedelta(days=1))
    assert result.status == "unchanged" and result.is_success
    assert len(database.list_snapshots(conn)) == 1


def test_offline_operation_uses_the_valid_cached_snapshot(conn, data_dir, make_kev_json):
    kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(version="saved"), now=NOW)

    def offline():
        raise KevDownloadError("no internet")

    result = kev_client.refresh_kev(conn, data_dir, fetch=offline, now=NOW + timedelta(days=3, hours=2))
    assert result.status == "cached" and result.used_cache and not result.is_success
    assert result.snapshot.catalog_version == "saved"
    assert "FAILED" in result.message and "3 days" in result.message  # shows the cache age


def test_failed_refresh_preserves_the_previous_valid_snapshot(conn, data_dir, make_kev_json):
    kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(version="good", cves={"CVE-2099-0001": "2025-01-01"}), now=NOW)
    before = database.get_kev_index(conn, database.latest_snapshot(conn).id)

    for bad in (b"<html>maintenance</html>", make_kev_json(count=99), b'{"catalogVersion":"v","dateReleased":"d","vulnerabilities":[]}'):
        result = kev_client.refresh_kev(conn, data_dir, fetch=lambda bad=bad: bad, now=NOW + timedelta(hours=1))
        assert not result.is_success and result.used_cache

    snapshots = database.list_snapshots(conn)
    assert len(snapshots) == 1 and snapshots[0].catalog_version == "good"
    assert database.get_kev_index(conn, snapshots[0].id) == before
    assert len(list((data_dir / "kev_snapshots").glob("*"))) == 1  # no junk files saved


def test_failed_refresh_without_any_cache_never_claims_success(conn, data_dir):
    def offline():
        raise KevDownloadError("no internet")

    result = kev_client.refresh_kev(conn, data_dir, fetch=offline, now=NOW)
    assert result.status == "unavailable" and not result.is_success and result.snapshot is None
    assert database.list_snapshots(conn) == []
    assert any(e["event_type"] == "kev_refresh_failed" for e in database.list_events(conn))


def test_cache_age_is_calculated_and_formatted():
    age = kev_client.snapshot_age("2025-10-12T07:00:00Z", NOW)
    assert age == timedelta(days=3, hours=2)
    assert kev_client.format_age(age) == "3 days 2 hours"
    assert kev_client.format_age(timedelta(minutes=12)) == "12 minutes"


def test_status_flags_stale_cache(conn, data_dir, make_kev_json):
    assert kev_client.kev_status(conn, NOW) is None
    kev_client.refresh_kev(conn, data_dir, fetch=lambda: make_kev_json(), now=NOW)
    assert not kev_client.kev_status(conn, NOW + timedelta(days=1)).is_stale
    assert kev_client.kev_status(conn, NOW + timedelta(days=8)).is_stale
