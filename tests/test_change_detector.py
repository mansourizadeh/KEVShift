"""Phase 5 tests: change detection rules (pure functions, no database needed)."""

import pytest

from src import change_detector as cd
from src.models import FindingRow, KevEntry, ScanRunInfo, SnapshotInfo

FORBIDDEN_FOR_NOT_OBSERVED = ("fixed", "remediated", "resolved", "patched", "compromised", "attacked")


def run(run_id, scan_date, group="weekly"):
    return ScanRunInfo(run_id, f"scan{run_id}.csv", scan_date, group, "t", 0, 0, 0, 0)


def finding(asset, cve, date, status="open", run_id=0):
    return FindingRow(asset, cve, date, status, 2, run_id)


def snap(snap_id, version, retrieved):
    return SnapshotInfo(snap_id, version, retrieved, f"{retrieved}T00:00:00Z", "u", 0, "", "x")


def kev(*cves, added="2025-10-14"):
    return {c: KevEntry(c, vulnerability_name=f"name {c}", date_added=added) for c in cves}


SNAP_A, SNAP_B = snap(1, "A", "2025-10-01"), snap(2, "B", "2025-10-15")


def categories(results):
    return {(r.asset_name, r.cve_id): r.change_category for r in results}


def test_exact_matching_never_uses_substrings():
    assert cd.match_kev("CVE-2099-0001", kev("CVE-2099-00011")) is None
    results = cd.analyze([run(1, "2025-10-01")], {1: [finding("a", "CVE-2099-0001", "2025-10-01")]},
                         SNAP_B, kev("CVE-2099-00011"), SNAP_A, kev())
    assert results[0].change_category == cd.CAT_NO_MATCH


def test_newly_added_kev_entry_is_detected_between_snapshots():
    results = cd.analyze([run(1, "2025-10-01")], {1: [finding("web-01", "CVE-2099-0001", "2025-10-01")]},
                         SNAP_B, kev("CVE-2099-0001"), SNAP_A, kev())
    row = results[0]
    assert row.change_category == cd.CAT_NEWLY_ADDED
    assert row.kev_date_added == "2025-10-14"
    assert "A (retrieved 2025-10-01)" in row.previous_snapshot and "B (retrieved 2025-10-15)" in row.current_snapshot
    assert "does not show that web-01 was attacked" in row.explanation
    assert "Verify" in row.recommended_action


def test_catalog_change_is_detected_without_any_new_scan():
    runs, findings = [run(1, "2025-10-01")], {1: [finding("web-01", "CVE-2099-0001", "2025-10-01")]}
    before = cd.analyze(runs, findings, SNAP_A, kev(), None, None)
    after = cd.analyze(runs, findings, SNAP_B, kev("CVE-2099-0001"), SNAP_A, kev())  # same scan, newer catalog
    assert before[0].change_category == cd.CAT_NO_MATCH
    assert after[0].change_category == cd.CAT_NEWLY_ADDED
    assert before[0].scan_date == after[0].scan_date == "2025-10-01"


def test_first_observed_match_when_no_earlier_snapshot_exists():
    results = cd.analyze([run(1, "2025-10-01")], {1: [finding("a", "CVE-2099-0001", "2025-10-01")]},
                         SNAP_A, kev("CVE-2099-0001"), None, None)
    row = results[0]
    assert row.change_category == cd.CAT_FIRST_OBSERVED
    assert "newly added" not in row.explanation.lower()
    assert "first observed" in row.explanation


def test_kev_match_in_latest_comparable_scan_is_still_listed():
    results = cd.analyze([run(1, "2025-10-01"), run(2, "2025-10-22")],
                         {1: [finding("a", "CVE-2099-0002", "2025-10-01")], 2: [finding("a", "CVE-2099-0002", "2025-10-22")]},
                         SNAP_B, kev("CVE-2099-0002"), SNAP_A, kev("CVE-2099-0002"))
    assert len(results) == 1  # only the latest scan's finding is reported as current
    assert results[0].change_category == cd.CAT_LISTED and results[0].scan_date == "2025-10-22"
    assert "continuing match" in results[0].explanation


def test_finding_missing_from_later_comparable_scan_is_not_observed():
    results = cd.analyze([run(1, "2025-10-01"), run(2, "2025-10-22")],
                         {1: [finding("a", "CVE-2099-0003", "2025-10-01"), finding("b", "CVE-2099-0004", "2025-10-01")],
                          2: [finding("b", "CVE-2099-0004", "2025-10-22")]},
                         SNAP_B, kev(), SNAP_A, kev())
    cats = categories(results)
    assert cats[("a", "CVE-2099-0003")] == cd.CAT_NOT_OBSERVED
    assert cats[("b", "CVE-2099-0004")] == cd.CAT_NO_MATCH
    row = next(r for r in results if r.change_category == cd.CAT_NOT_OBSERVED)
    assert row.scan_date == "2025-10-01" and row.compared_to_scan_date == "2025-10-22"


def test_not_observed_never_claims_remediation():
    results = cd.analyze([run(1, "2025-10-01"), run(2, "2025-10-22")],
                         {1: [finding("a", "CVE-2099-0003", "2025-10-01")], 2: [finding("z", "CVE-2099-0009", "2025-10-22")]},
                         SNAP_B, kev("CVE-2099-0003"), SNAP_A, kev("CVE-2099-0003"))
    row = next(r for r in results if r.change_category == cd.CAT_NOT_OBSERVED)
    text = (row.explanation + " " + row.recommended_action + " " + row.change_category).lower()
    for word in FORBIDDEN_FOR_NOT_OBSERVED:
        assert word not in text, word
    assert "not evidence" in row.explanation and "coverage" in row.explanation
    assert "not covered" in row.explanation  # asset a has no findings at all in the later scan
    assert "listed in KEV" in row.explanation  # KEV-listed CVE gets an extra caution


def test_scans_are_only_comparable_inside_an_explicit_group():
    runs = [run(1, "2025-10-01", "profile-A"), run(2, "2025-10-22", "profile-B")]
    results = cd.analyze(runs, {1: [finding("a", "CVE-2099-0003", "2025-10-01")], 2: []}, SNAP_B, kev(), SNAP_A, kev())
    assert all(r.change_category != cd.CAT_NOT_OBSERVED for r in results)


def test_unlabelled_scans_are_never_used_for_not_observed():
    runs = [run(1, "2025-10-01", None), run(2, "2025-10-22", None)]
    results = cd.analyze(runs, {1: [finding("a", "CVE-2099-0003", "2025-10-01")], 2: [finding("b", "CVE-2099-0004", "2025-10-22")]},
                         SNAP_B, kev(), SNAP_A, kev())
    assert all(r.change_category != cd.CAT_NOT_OBSERVED for r in results)
    assert {r.asset_name for r in results} == {"a", "b"}


def test_each_unlabelled_scan_is_treated_independently_and_none_disappears():
    """An older unlabelled scan must stay visible, even when a newer unlabelled scan exists."""
    runs = [run(1, "2025-10-01", None), run(2, "2025-10-22", None)]
    findings = {1: [finding("old-host", "CVE-2099-0001", "2025-10-01")],
                2: [finding("new-host", "CVE-2099-0001", "2025-10-22")]}
    results = cd.analyze(runs, findings, SNAP_B, kev("CVE-2099-0001"), SNAP_A, kev())
    by_asset = {r.asset_name: r for r in results}
    assert set(by_asset) == {"old-host", "new-host"}
    assert by_asset["old-host"].scan_date == "2025-10-01" and by_asset["new-host"].scan_date == "2025-10-22"
    assert by_asset["old-host"].change_category == cd.CAT_NEWLY_ADDED  # the catalog change reaches the old scan too
    assert by_asset["old-host"].scan_group != by_asset["new-host"].scan_group  # separate pseudo-groups
    assert "unlabelled" in by_asset["old-host"].scan_group


def test_same_finding_in_two_unlabelled_scans_appears_once_per_scan():
    runs = [run(1, "2025-10-01", None), run(2, "2025-10-22", None)]
    findings = {1: [finding("a", "CVE-2099-0009", "2025-10-01")], 2: [finding("a", "CVE-2099-0009", "2025-10-22")]}
    results = cd.analyze(runs, findings, SNAP_B, kev(), SNAP_A, kev())
    assert sorted(r.scan_date for r in results) == ["2025-10-01", "2025-10-22"]


def test_labelled_group_still_shows_only_its_newest_scan_while_unlabelled_scan_stays():
    runs = [run(1, "2025-10-01", "weekly"), run(2, "2025-10-08", "weekly"), run(3, "2025-10-03", None)]
    findings = {1: [finding("w-old", "CVE-2099-0001", "2025-10-01")],
                2: [finding("w-new", "CVE-2099-0002", "2025-10-08")],
                3: [finding("solo", "CVE-2099-0003", "2025-10-03")]}
    results = cd.analyze(runs, findings, SNAP_B, kev(), SNAP_A, kev())
    current = {r.asset_name for r in results if r.change_category != cd.CAT_NOT_OBSERVED}
    assert current == {"w-new", "solo"}  # w-old is superseded inside its group; solo is independent
    assert {r.asset_name for r in results if r.change_category == cd.CAT_NOT_OBSERVED} == {"w-old"}


def test_unlabelled_scan_never_makes_a_labelled_finding_not_observed():
    runs = [run(1, "2025-10-01", "weekly"), run(2, "2025-10-22", None)]
    findings = {1: [finding("a", "CVE-2099-0003", "2025-10-01")], 2: []}
    results = cd.analyze(runs, findings, SNAP_B, kev(), SNAP_A, kev())
    assert [r.change_category for r in results] == [cd.CAT_NO_MATCH]  # 'a' is its own labelled group's latest scan


def test_scans_on_the_same_date_are_not_treated_as_later():
    runs = [run(1, "2025-10-01"), run(2, "2025-10-01")]
    results = cd.analyze(runs, {1: [finding("a", "CVE-2099-0003", "2025-10-01")], 2: []}, SNAP_B, kev(), SNAP_A, kev())
    assert all(r.change_category != cd.CAT_NOT_OBSERVED for r in results)


def test_asset_names_compare_case_insensitively():
    runs = [run(1, "2025-10-01"), run(2, "2025-10-22")]
    results = cd.analyze(runs, {1: [finding("Web-01", "CVE-2099-0003", "2025-10-01")], 2: [finding("web-01", "CVE-2099-0003", "2025-10-22")]},
                         SNAP_B, kev(), SNAP_A, kev())
    assert [r.change_category for r in results] == [cd.CAT_NO_MATCH]


@pytest.mark.parametrize("status", ["mitigated", "accepted_risk", "false_positive"])
def test_kev_listed_finding_with_non_open_status_needs_manual_review(status):
    results = cd.analyze([run(1, "2025-10-01")], {1: [finding("a", "CVE-2099-0001", "2025-10-01", status)]},
                         SNAP_B, kev("CVE-2099-0001"), SNAP_A, kev())
    assert results[0].change_category == cd.CAT_MANUAL_REVIEW
    assert status in results[0].explanation and "newly added" in results[0].explanation.lower()


def test_catalog_diff_lists_added_and_removed_entries():
    assert cd.diff_catalogs(kev("CVE-2099-0001", "CVE-2099-0002"), kev("CVE-2099-0002", "CVE-2099-0003")) == (
        ["CVE-2099-0003"], ["CVE-2099-0001"])


def test_output_is_deterministic_and_sorted_by_priority():
    runs = [run(1, "2025-10-01")]
    findings = {1: [finding("b", "CVE-2099-0004", "2025-10-01"), finding("a", "CVE-2099-0001", "2025-10-01"),
                    finding("a", "CVE-2099-0002", "2025-10-01")]}
    args = (runs, findings, SNAP_B, kev("CVE-2099-0001", "CVE-2099-0002"), SNAP_A, kev("CVE-2099-0002"))
    first, second = cd.analyze(*args), cd.analyze(*args)
    assert first == second
    assert [r.change_category for r in first] == [cd.CAT_NEWLY_ADDED, cd.CAT_LISTED, cd.CAT_NO_MATCH]


def test_every_category_has_help_text():
    assert set(cd.CATEGORY_HELP) == set(cd.CATEGORY_ORDER)
    assert all(info["meaning"] and info["limitation"] for info in cd.CATEGORY_HELP.values())
