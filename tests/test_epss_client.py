"""Phase 9 tests: optional EPSS integration (mocked; no internet)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src import epss_client
from src.epss_client import EpssError

NOW = datetime(2025, 10, 15, 9, 0, tzinfo=timezone.utc)


def body(*items):
    return json.dumps({"status": "OK", "data": [
        {"cve": c, "epss": e, "percentile": p, "date": "2025-10-14"} for c, e, p in items]}).encode()


class Resp:
    def __init__(self, status_code=200, content=b""):
        self.status_code, self.content = status_code, content


class Session:
    def __init__(self, response):
        self.response, self.calls = response, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def test_response_is_parsed_into_numbers():
    rows = epss_client.parse_epss_response(body(("CVE-2099-0001", "0.01234", "0.5")))
    assert rows == [("CVE-2099-0001", 0.01234, 0.5, "2025-10-14")]


@pytest.mark.parametrize("raw", [b"nope", b"{}", body(("CVE-2099-0001", "1.5", "0.5")), body(("BAD", "0.1", "0.1")),
                                 body(("CVE-2099-0001", "abc", "0.1"))])
def test_invalid_epss_responses_are_rejected(raw):
    with pytest.raises(EpssError):
        epss_client.parse_epss_response(raw)


def test_fetch_sends_only_valid_ids_with_a_timeout():
    session = Session(Resp(200, body(("CVE-2099-0001", "0.1", "0.2"))))
    epss_client.fetch_epss_scores(["cve-2099-0001", "garbage; DROP"], session=session)
    url, kwargs = session.calls[0]
    assert url == epss_client.EPSS_API_URL and kwargs["params"] == {"cve": "CVE-2099-0001"} and kwargs["timeout"]


def test_live_values_are_cached_and_labelled(conn):
    result = epss_client.refresh_epss(conn, ["CVE-2099-0001"], fetch=lambda ids: [("CVE-2099-0001", 0.1, 0.9, "2025-10-14")], now=NOW)
    assert result.ok and result.scores["CVE-2099-0001"].source == "live"
    cached = epss_client.read_cached(conn, ["CVE-2099-0001"], NOW)["CVE-2099-0001"]
    assert cached.source == "cached" and not cached.stale and cached.epss == 0.1


def test_failed_refresh_returns_stale_cached_values_and_does_not_claim_success(conn):
    epss_client.refresh_epss(conn, ["CVE-2099-0001"], fetch=lambda ids: [("CVE-2099-0001", 0.1, 0.9, "2025-10-14")], now=NOW)

    def down(ids):
        raise EpssError("service unavailable")

    result = epss_client.refresh_epss(conn, ["CVE-2099-0001"], fetch=down, now=NOW + timedelta(days=5))
    assert not result.ok and "FAILED" in result.message
    assert result.scores["CVE-2099-0001"].stale and result.scores["CVE-2099-0001"].source == "cached"


def test_failed_refresh_with_empty_cache_is_harmless(conn):
    def down(ids):
        raise EpssError("service unavailable")

    result = epss_client.refresh_epss(conn, ["CVE-2099-0001"], fetch=down, now=NOW)
    assert not result.ok and result.scores == {}
