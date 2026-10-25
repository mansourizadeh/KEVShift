"""Evidence tests with REAL CISA catalog data.

The three files in sample_data/real/ are unmodified copies of real KEV snapshots (see manifest.json).
All CVE IDs, dates and names used in these tests are read from those files at run time; nothing about a
real vulnerability is typed into this test file. The SCAN data is still synthetic (invented asset names):
real CVE IDs in a made-up scan do not mean any real system has those vulnerabilities.
"""

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from src import change_detector as cd
from src import database, kev_client, workflow

REAL_DIR = Path(__file__).resolve().parent.parent / "sample_data" / "real"
DAYS = ("2026-10-01", "2026-10-15", "2026-10-23")
TODAY = date(2026, 12, 31)  # fixed, so the "scan date not in the future" rule is deterministic
RETRIEVED = {d: f"{d}T20:00:00Z" for d in DAYS}
FORBIDDEN = ("fixed", "remediated", "resolved", "patched", "compromised")


def _path(day):
    return REAL_DIR / f"cisa_kev_{day}.json"


@pytest.fixture(scope="module")
def raw():
    for day in DAYS:
        assert _path(day).is_file(), f"real catalog file missing: {_path(day)}"  # never skip silently
    return {day: _path(day).read_bytes() for day in DAYS}


@pytest.fixture(scope="module")
def parsed(raw):
    return {day: kev_client.parse_kev_json(raw[day]) for day in DAYS}


@pytest.fixture(scope="module")
def index(parsed):
    return {day: {e.cve_id: e for e in parsed[day].entries} for day in DAYS}


@pytest.fixture
def csv_for(make_csv):
    def build(rows, scan_date="2026-10-01"):
        return make_csv([(asset, cve, scan_date, status) for asset, cve, status in rows])
    return build


def _store(conn, data_dir, raw, day):
    return kev_client.store_snapshot_bytes(conn, raw[day], data_dir, source_url=f"real-fixture:{day}",
                                           retrieved_at=RETRIEVED[day])


# ----------------------------------------------------------------------------- the files themselves
def test_real_files_match_the_recorded_manifest(raw):
    manifest = json.loads((REAL_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert "REAL" in manifest["description"] and manifest["license"].startswith("CC0")
    assert len(manifest["files"]) == len(DAYS)
    for item in manifest["files"]:
        data = (REAL_DIR / item["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"], f"{item['file']} was modified"
        assert len(data) == item["bytes"]
        assert item["source_repository"] == "https://github.com/cisagov/kev-data" and len(item["source_commit"]) == 40


def test_real_catalogs_parse_with_consistent_metadata(parsed, raw):
    expected_entries = {"2026-10-01": 1731, "2026-10-15": 1746, "2026-10-23": 1756}
    for day in DAYS:
        snapshot = parsed[day]
        declared = json.loads(raw[day])["count"]
        assert len(snapshot.entries) == declared == expected_entries[day]
        assert snapshot.catalog_version == day.replace("-", ".")
        assert snapshot.date_released.startswith(day)
        assert len({e.cve_id for e in snapshot.entries}) == len(snapshot.entries)


def test_every_real_entry_has_a_valid_normalized_id_and_dates(parsed):
    for entry in parsed["2026-10-23"].entries:
        assert entry.cve_id == entry.cve_id.strip().upper() and entry.cve_id.startswith("CVE-")
        assert datetime.strptime(entry.date_added, "%Y-%m-%d")
        assert entry.vulnerability_name and entry.vendor_project and entry.product


def test_real_feed_contains_fields_the_app_does_not_use_and_still_parses(raw):
    fields = {key for item in json.loads(raw["2026-10-23"])["vulnerabilities"] for key in item}
    assert {"cveID", "dateAdded", "vulnerabilityName"} <= fields
    assert fields - {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription",
                     "requiredAction", "dueDate", "knownRansomwareCampaignUse"}  # extras exist (notes, cwes, ...)


def test_real_catalog_changes_are_additions_only_and_consistent_with_date_added(index):
    added, removed = cd.diff_catalogs(index["2026-10-01"], index["2026-10-15"])
    assert (len(added), len(removed)) == (15, 0)
    assert all("2026-10-01" < index["2026-10-15"][c].date_added <= "2026-10-15" or
               index["2026-10-15"][c].date_added <= "2026-10-01" for c in added)
    added2, removed2 = cd.diff_catalogs(index["2026-10-15"], index["2026-10-23"])
    assert (len(added2), len(removed2)) == (10, 0)


# ----------------------------------------------------------------------------- storage with real data
def test_real_snapshot_is_stored_completely_and_the_saved_file_is_byte_identical(conn, data_dir, raw, parsed):
    snapshot_id, created = _store(conn, data_dir, raw, "2026-10-15")
    assert created
    info = database.get_snapshot(conn, snapshot_id)
    assert info.entry_count == 1746 and info.catalog_version == "2026.10.15"
    assert Path(info.stored_path).read_bytes() == raw["2026-10-15"]
    assert hashlib.sha256(raw["2026-10-15"]).hexdigest() == info.content_sha256
    stored = database.get_kev_index(conn, snapshot_id)
    assert stored == {e.cve_id: e for e in parsed["2026-10-15"].entries}  # every field of every entry round-trips


def test_real_non_ascii_text_survives_storage(conn, data_dir, raw, parsed):
    non_ascii = [e for e in parsed["2026-10-23"].entries if not (e.required_action + e.short_description).isascii()]
    assert non_ascii, "expected real entries with typographic characters"
    snapshot_id, _ = _store(conn, data_dir, raw, "2026-10-23")
    stored = database.get_kev_index(conn, snapshot_id)
    for entry in non_ascii[:25]:
        assert stored[entry.cve_id].required_action == entry.required_action
        assert stored[entry.cve_id].short_description == entry.short_description


# ----------------------------------------------------------------------------- exact matching on real IDs
# Two functions do the lookup: kev_client.match_cve and change_detector.match_kev (the one the dashboard
# analysis really uses). Both must be exact, so every matching test runs against both.
MATCHERS = [pytest.param(kev_client.match_cve, id="kev_client.match_cve"),
            pytest.param(cd.match_kev, id="change_detector.match_kev")]


def _prefix_cases(current, limit=40):
    """Real listed IDs whose one-character-shorter prefix is a different, UNLISTED but valid-format ID.

    The prefix keeps at least 4 digits, so it is a well-formed CVE ID that a substring search would hit.
    """
    cases = []
    for cve_id in sorted(current):
        prefix = cve_id[:-1]
        if len(cve_id.split("-")[2]) >= 5 and prefix not in current:
            cases.append((cve_id, prefix))
    return cases[:limit]


def _real_prefix_pairs(current):
    """Pairs (short, long) where BOTH are really listed and 'short' is a strict prefix of 'long'."""
    return [(long_id[:-1], long_id) for long_id in sorted(current) if long_id[:-1] in current]


@pytest.mark.parametrize("match", MATCHERS)
def test_every_real_id_matches_itself_and_nothing_longer_or_shorter(match, index):
    current = index["2026-10-23"]
    for cve_id in current:
        assert match(cve_id, current) is current[cve_id]
        assert match(cve_id + "0", current) is None  # a longer ID must not match
        assert match(cve_id.lower(), current) is None  # matching is on NORMALIZED ids only


@pytest.mark.parametrize("match", MATCHERS)
def test_real_prefix_of_a_listed_id_is_not_matched(match, index):
    current = index["2026-10-23"]
    cases = _prefix_cases(current)
    assert len(cases) == 40, "expected plenty of real IDs to build prefix cases from"
    for cve_id, prefix in cases:
        assert any(prefix in listed for listed in current)  # a substring search WOULD (wrongly) hit
        assert match(prefix, current) is None  # exact matching does not


@pytest.mark.parametrize("match", MATCHERS)
def test_real_catalog_has_listed_ids_that_are_prefixes_of_other_listed_ids_and_each_matches_only_itself(match, index):
    current = index["2026-10-23"]
    pairs = _real_prefix_pairs(current)
    assert pairs, "the real catalog is expected to contain such pairs (e.g. CVE-2022-4135 / CVE-2022-41352)"
    for short_id, long_id in pairs:
        assert short_id in long_id  # the trap: one real ID is literally inside another
        assert match(short_id, current) is current[short_id]
        assert match(long_id, current) is current[long_id]
        assert current[short_id].vulnerability_name != "" and current[short_id] is not current[long_id]


def test_real_prefix_trap_end_to_end_a_short_id_is_not_flagged_because_a_longer_real_id_is_listed(conn, data_dir, raw, index, csv_for):
    """DERIVED fixture: the real 23 Oct catalog with the SHORT id of a real prefix pair removed, in memory only.

    The long ID (which contains the short one as text) stays listed. A scan that reports only the short ID
    must therefore NOT match.
    """
    short_id, long_id = _real_prefix_pairs(index["2026-10-23"])[0]
    document = json.loads(raw["2026-10-23"])
    document["vulnerabilities"] = [v for v in document["vulnerabilities"] if v["cveID"] != short_id]
    document["count"] = len(document["vulnerabilities"])
    derived = json.dumps(document).encode("utf-8")
    remaining = {v["cveID"] for v in document["vulnerabilities"]}
    assert long_id in remaining and short_id not in remaining  # the short ID is gone; the long one (containing it) stays

    kev_client.store_snapshot_bytes(conn, derived, data_dir, source_url="derived-from-real", retrieved_at="2026-10-23T20:00:00Z")
    workflow.import_scan(conn, data_dir, csv_for([("only-short", short_id, "open"), ("has-long", long_id, "open")]),
                         "s.csv", "g", "2026-10-23T22:00:00Z", today=TODAY)
    by_asset = {r.asset_name: r for r in workflow.run_analysis(conn).results}
    assert by_asset["only-short"].change_category == cd.CAT_NO_MATCH and by_asset["only-short"].kev_match_status == "Not listed in KEV"
    assert by_asset["has-long"].kev_match_status == "Listed in KEV"


def test_scan_reporting_a_prefix_of_a_real_listed_id_is_not_flagged_by_the_analysis(conn, data_dir, raw, index, csv_for):
    """End to end: the dashboard's analysis must not flag CVE-2026-11462 because CVE-2026-114625 is listed."""
    cases = _prefix_cases(index["2026-10-23"], limit=5)
    _store(conn, data_dir, raw, "2026-10-15")
    _store(conn, data_dir, raw, "2026-10-23")
    rows = [(f"host-{n}", prefix, "open") for n, (_, prefix) in enumerate(cases)]
    rows.append(("host-real", cases[0][0], "open"))  # the genuinely listed ID, as a control
    workflow.import_scan(conn, data_dir, csv_for(rows), "s.csv", "g", "2026-10-23T22:00:00Z", today=TODAY)
    by_asset = {r.asset_name: r for r in workflow.run_analysis(conn).results}
    for n in range(len(cases)):
        assert by_asset[f"host-{n}"].change_category == cd.CAT_NO_MATCH, cases[n]
    assert by_asset["host-real"].kev_match_status == "Listed in KEV"


# ----------------------------------------------------------------------------- the whole scenario with real catalogs
def _scenario_findings(index):
    added_oct15 = sorted(set(index["2026-10-15"]) - set(index["2026-10-01"]))
    added_oct23 = sorted(set(index["2026-10-23"]) - set(index["2026-10-15"]))
    already = sorted(set(index["2026-10-01"]))[0]
    return {"new_in_oct15": added_oct15[0], "new_in_oct23": added_oct23[0], "already_listed": already,
            "not_listed": "CVE-2099-0001"}


def test_real_catalog_change_is_detected_without_importing_a_new_scan(conn, data_dir, raw, index, csv_for):
    ids = _scenario_findings(index)
    assert ids["new_in_oct15"] not in index["2026-10-01"] and ids["new_in_oct15"] in index["2026-10-15"]

    _store(conn, data_dir, raw, "2026-10-01")  # 1 October: real catalog stored first
    scan = csv_for([("web-server-01", ids["new_in_oct15"], "open"), ("db-server-02", ids["already_listed"], "open"),
                    ("app-server-03", ids["not_listed"], "open")])
    workflow.import_scan(conn, data_dir, scan, "scan.csv", "internal-weekly", "2026-10-01T22:00:00Z", today=TODAY)
    day1 = {r.cve_id: r for r in workflow.run_analysis(conn).results}
    assert day1[ids["new_in_oct15"]].change_category == cd.CAT_NO_MATCH
    assert day1[ids["already_listed"]].change_category == cd.CAT_FIRST_OBSERVED  # no earlier snapshot exists

    _store(conn, data_dir, raw, "2026-10-15")  # 15 October: real catalog stored, NO new scan imported
    assert len(database.list_scan_runs(conn)) == 1
    day15 = {r.cve_id: r for r in workflow.run_analysis(conn).results}
    row = day15[ids["new_in_oct15"]]
    real = index["2026-10-15"][ids["new_in_oct15"]]
    assert row.change_category == cd.CAT_NEWLY_ADDED
    assert row.scan_date == "2026-10-01"  # still the 1 October scan
    assert row.kev_date_added == real.date_added  # straight from the real catalog
    assert row.kev_vulnerability_name == real.vulnerability_name
    assert "2026.10.01" in row.previous_snapshot and "2026.10.15" in row.current_snapshot
    assert "does not show that web-server-01 was attacked" in row.explanation and row.explanation.count("attacked") == 1
    assert "Verify" in row.recommended_action
    assert day15[ids["already_listed"]].change_category == cd.CAT_LISTED
    assert day15[ids["not_listed"]].change_category == cd.CAT_NO_MATCH

    _store(conn, data_dir, raw, "2026-10-23")  # a third real snapshot: the older addition is now a continuing match
    day23 = {r.cve_id: r for r in workflow.run_analysis(conn).results}
    assert day23[ids["new_in_oct15"]].change_category == cd.CAT_LISTED


def test_real_snapshot_pair_flags_a_cve_added_in_the_latest_interval(conn, data_dir, raw, index, csv_for):
    ids = _scenario_findings(index)
    for day in DAYS:
        _store(conn, data_dir, raw, day)
    workflow.import_scan(conn, data_dir, csv_for([("host-a", ids["new_in_oct23"], "open")]), "s.csv", "g",
                         "2026-10-01T22:00:00Z", today=TODAY)
    result = workflow.run_analysis(conn).results[0]
    assert result.change_category == cd.CAT_NEWLY_ADDED
    assert result.kev_date_added == index["2026-10-23"][ids["new_in_oct23"]].date_added


def test_real_data_analysis_is_reproducible_after_restart(tmp_path, raw, index, csv_for):
    ids = _scenario_findings(index)
    data_dir = tmp_path / "data"
    conn = database.connect(data_dir / "kevshift.db")
    database.init_schema(conn)
    for day in DAYS:
        _store(conn, data_dir, raw, day)
    workflow.import_scan(conn, data_dir, csv_for([("h", ids["new_in_oct15"], "open"), ("h", ids["already_listed"], "open")]),
                         "s.csv", "g", "2026-10-01T22:00:00Z", today=TODAY)
    snapshot_ids = [s.id for s in database.list_snapshots(conn)]
    first = [workflow.run_analysis(conn, sid).results for sid in snapshot_ids]
    conn.close()

    conn = database.connect(data_dir / "kevshift.db")  # restart
    database.init_schema(conn)
    second = [workflow.run_analysis(conn, sid).results for sid in snapshot_ids]
    conn.close()
    assert first == second
    assert [r.change_category for r in first[1] if r.cve_id == ids["new_in_oct15"]] == [cd.CAT_NEWLY_ADDED]
    assert [r.change_category for r in first[2] if r.cve_id == ids["new_in_oct15"]] == [cd.CAT_LISTED]


def test_real_not_observed_in_a_later_comparable_scan_makes_no_remediation_claim(conn, data_dir, raw, index, csv_for):
    ids = _scenario_findings(index)
    _store(conn, data_dir, raw, "2026-10-15")
    workflow.import_scan(conn, data_dir, csv_for([("db-server-02", ids["new_in_oct15"], "open"),
                                                  ("web-server-01", ids["already_listed"], "open")], "2026-10-01"),
                         "a.csv", "internal-weekly", "2026-10-01T22:00:00Z", today=TODAY)
    workflow.import_scan(conn, data_dir, csv_for([("web-server-01", ids["already_listed"], "open")], "2026-10-22"),
                         "b.csv", "internal-weekly", "2026-10-22T22:00:00Z", today=TODAY)
    missing = [r for r in workflow.run_analysis(conn).results if r.change_category == cd.CAT_NOT_OBSERVED]
    assert [r.cve_id for r in missing] == [ids["new_in_oct15"]]
    text = (missing[0].explanation + missing[0].recommended_action).lower()
    assert not any(word in text for word in FORBIDDEN)
    assert missing[0].kev_match_status == "Listed in KEV"  # real catalog lists it, so the extra caution appears
    assert "confirm its status" in missing[0].explanation


# ----------------------------------------------------------------------------- offline / failure with real data
def test_offline_refresh_falls_back_to_the_real_cached_snapshot(conn, data_dir, raw):
    now = datetime(2026, 10, 15, 21, 0, tzinfo=timezone.utc)
    assert kev_client.refresh_kev(conn, data_dir, fetch=lambda: raw["2026-10-15"], now=now).status == "refreshed"

    def offline():
        raise kev_client.KevDownloadError("no internet")

    result = kev_client.refresh_kev(conn, data_dir, fetch=offline, now=now + timedelta(days=2))
    assert result.status == "cached" and not result.is_success
    assert result.snapshot.catalog_version == "2026.10.15" and result.snapshot.entry_count == 1746


def test_truncated_real_download_is_rejected_and_the_previous_real_snapshot_survives(conn, data_dir, raw):
    now = datetime(2026, 10, 15, 21, 0, tzinfo=timezone.utc)
    kev_client.refresh_kev(conn, data_dir, fetch=lambda: raw["2026-10-01"], now=now)
    truncated = raw["2026-10-23"][: len(raw["2026-10-23"]) // 2]  # a half-downloaded real file
    result = kev_client.refresh_kev(conn, data_dir, fetch=lambda: truncated, now=now + timedelta(days=1))
    assert not result.is_success and result.used_cache
    assert [s.catalog_version for s in database.list_snapshots(conn)] == ["2026.10.01"]
    assert len(list((data_dir / "kev_snapshots").glob("*.json"))) == 1


def test_real_catalog_with_entries_removed_is_detected_as_incomplete(raw):
    document = json.loads(raw["2026-10-23"])
    document["vulnerabilities"] = document["vulnerabilities"][:-5]  # count still says 1756
    with pytest.raises(kev_client.KevFormatError, match="incomplete"):
        kev_client.parse_kev_json(json.dumps(document))
