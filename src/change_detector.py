"""Change detection rules.

Pure functions: plain data in, plain data out. No Streamlit, no database, no network.
The same stored inputs always produce the same rows, which is what makes a flag
reproducible.

Categories (each row gets exactly one):
  * Newly added to KEV            - catalog change between two snapshots, finding in latest scan
  * First observed KEV match      - listed in KEV, but no earlier snapshot to compare with
  * Still present and listed in KEV
  * Not observed in latest scan   - never described as fixed
  * Needs manual review           - listed in KEV but the finding's status is not 'open'
  * No KEV match
"""

from __future__ import annotations

from typing import Mapping, Optional, Sequence

from .models import ChangeResult, FindingRow, KevEntry, ScanRunInfo, SnapshotInfo
from .validators import asset_key

CAT_NEWLY_ADDED = "Newly added to KEV"
CAT_FIRST_OBSERVED = "First observed KEV match"
CAT_LISTED = "Still present and listed in KEV"
CAT_NOT_OBSERVED = "Not observed in latest scan"
CAT_MANUAL_REVIEW = "Needs manual review"
CAT_NO_MATCH = "No KEV match"

CATEGORY_ORDER = [
    CAT_NEWLY_ADDED,
    CAT_FIRST_OBSERVED,
    CAT_MANUAL_REVIEW,
    CAT_LISTED,
    CAT_NOT_OBSERVED,
    CAT_NO_MATCH,
]

CATEGORY_HELP = {
    CAT_NEWLY_ADDED: {
        "meaning": "A CVE in the latest comparable scan is in the selected KEV snapshot but was not in the "
        "snapshot before it. This is a catalog change and can appear without any new scan.",
        "limitation": "KEV says exploitation of the CVE has been documented somewhere. It does not say this asset "
        "was attacked or is exploitable.",
    },
    CAT_FIRST_OBSERVED: {
        "meaning": "A CVE in the latest comparable scan is in the selected KEV snapshot, and no earlier "
        "snapshot is stored.",
        "limitation": "Without an earlier snapshot KEVShift cannot tell whether the entry is new.",
    },
    CAT_LISTED: {
        "meaning": "A CVE in the latest comparable scan is in the selected KEV snapshot and was already "
        "listed in the snapshot before it.",
        "limitation": "A KEV listing is not evidence that this specific asset was attacked.",
    },
    CAT_NOT_OBSERVED: {
        "meaning": "An asset/CVE finding from an earlier scan is missing from a later scan that you labelled as "
        "comparable (same comparable group).",
        "limitation": "This is NOT proof of a change on the asset. Coverage, scan configuration, credentials, "
        "timing or renamed assets can all explain it.",
    },
    CAT_MANUAL_REVIEW: {
        "meaning": "The CVE is listed in KEV but the finding's recorded status is mitigated, accepted_risk or "
        "false_positive.",
        "limitation": "KEVShift cannot judge whether the recorded status is still justified; a person must check.",
    },
    CAT_NO_MATCH: {
        "meaning": "A CVE in the latest comparable scan is not in the selected KEV snapshot.",
        "limitation": "Not being in KEV does not mean the vulnerability is harmless.",
    },
}

REVIEW_STATUSES = frozenset({"mitigated", "accepted_risk", "false_positive"})
UNLABELLED_GROUP = "(unlabelled)"


# ------------------------------------------------------------------------ helpers
def snapshot_label(info: Optional[SnapshotInfo]) -> str:
    """Short text identifying a snapshot by version and retrieval date."""
    if info is None:
        return "none stored"
    return f"{info.catalog_version} (retrieved {info.retrieved_at[:10]})"


def match_kev(cve_id: str, kev_index: Mapping[str, KevEntry]) -> Optional[KevEntry]:
    """Exact lookup. 'CVE-2099-0001' never matches 'CVE-2099-00011'."""
    return kev_index.get(cve_id)


def diff_catalogs(
    previous: Mapping[str, KevEntry], current: Mapping[str, KevEntry]
) -> tuple:
    """Return (added_cve_ids, removed_cve_ids) between two snapshots, sorted."""
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    return added, removed


def _run_sort_key(run: ScanRunInfo) -> tuple:
    return (run.scan_date, run.id)


def _group_name(run: ScanRunInfo) -> str:
    return run.comparable_group or UNLABELLED_GROUP


def latest_run_per_group(runs: Sequence[ScanRunInfo]) -> dict:
    """The newest scan of each comparable group. Unlabelled scans share one pseudo-group."""
    latest: dict = {}
    for run in sorted(runs, key=_run_sort_key):
        latest[_group_name(run)] = run
    return latest


# --------------------------------------------------------------------- row builders
def _kev_row(
    finding: FindingRow,
    group: str,
    entry: Optional[KevEntry],
    cur_label: str,
    prev_label: str,
    previous_kev: Optional[Mapping[str, KevEntry]],
) -> ChangeResult:
    asset, cve, when, status = finding.asset_name, finding.cve_id, finding.scan_date, finding.finding_status
    common = dict(
        asset_name=asset,
        cve_id=cve,
        scan_date=when,
        finding_status=status,
        scan_group=group,
        previous_snapshot=prev_label,
        current_snapshot=cur_label,
    )

    if entry is None:
        return ChangeResult(
            **common,
            kev_match_status="Not listed in KEV",
            kev_date_added="",
            kev_vulnerability_name="",
            kev_change="Not applicable",
            change_category=CAT_NO_MATCH,
            explanation=(
                f"{cve} is reported on {asset} in the scan dated {when} (status: {status}) but is not listed "
                f"in KEV snapshot {cur_label}. Absence from KEV does not mean the vulnerability is harmless; "
                "KEV only lists CVEs with documented exploitation."
            ),
            recommended_action="No KEV-driven action. Handle it under your normal vulnerability-management process.",
        )

    first_observed = previous_kev is None
    newly_added = previous_kev is not None and cve not in previous_kev
    if first_observed:
        kev_change = "First observed (no earlier snapshot stored)"
    elif newly_added:
        kev_change = "Newly added since the previous snapshot"
    else:
        kev_change = "Already listed in the previous snapshot"

    listing = f"KEV snapshot {cur_label} lists it (CISA date added: {entry.date_added})"
    disclaimer = f"This does not show that {asset} was attacked or is exploitable."

    if status in REVIEW_STATUSES:
        category = CAT_MANUAL_REVIEW
        if first_observed:
            change_note = "No earlier snapshot is stored, so it is only a first observed match."
        elif newly_added:
            change_note = f"It was newly added to KEV since snapshot {prev_label}."
        else:
            change_note = f"It was already listed in snapshot {prev_label}."
        explanation = (
            f"{cve} on {asset} (scan dated {when}) is listed in KEV, but the finding's recorded status is "
            f"'{status}'. {listing}. {change_note} A KEV-listed CVE with a status other than 'open' is "
            f"uncertain: the status may be outdated. {disclaimer}"
        )
        action = (
            f"Manually verify that the recorded status '{status}' is still justified "
            "(for example that the mitigation is in place or the finding really is a false positive)."
        )
    elif first_observed:
        category = CAT_FIRST_OBSERVED
        explanation = (
            f"{cve} was reported on {asset} in the scan dated {when} (status: {status}). {listing}. "
            f"No earlier KEV snapshot is stored, so KEVShift cannot tell whether the entry is new; this is "
            f"only the first observed match. {disclaimer}"
        )
        action = (
            f"Verify that the finding applies to {asset} and prioritize it for review. "
            "Refresh the catalog later so future changes can be compared."
        )
    elif newly_added:
        category = CAT_NEWLY_ADDED
        explanation = (
            f"{cve} was reported on {asset} in the scan dated {when} (status: {status}). {listing}, but the "
            f"earlier snapshot {prev_label} did not list it. This is a catalog change, not a scan change. "
            f"{disclaimer} It shows that exploitation of this CVE has been documented."
        )
        action = (
            f"Verify that this finding still applies to {asset} (affected version, configuration, exposure), "
            "then prioritize it and record the outcome."
        )
    else:
        category = CAT_LISTED
        explanation = (
            f"{cve} is reported on {asset} in the latest scan dated {when} (status: {status}). {listing}. "
            f"It was already listed in the earlier snapshot {prev_label}, so this is a continuing match, "
            f"not a new catalog change. {disclaimer}"
        )
        action = "Confirm the finding's current status and that a remediation or mitigation decision is tracked."

    return ChangeResult(
        **common,
        kev_match_status="Listed in KEV",
        kev_date_added=entry.date_added,
        kev_vulnerability_name=entry.vulnerability_name,
        kev_change=kev_change,
        change_category=category,
        explanation=explanation,
        recommended_action=action,
    )


def find_not_observed(
    runs: Sequence[ScanRunInfo],
    findings_by_run: Mapping[int, Sequence[FindingRow]],
    current_kev: Mapping[str, KevEntry],
    cur_label: str,
    prev_label: str,
) -> list:
    """Findings seen in an earlier scan of a comparable group but absent from its latest scan.

    Only scans that share an explicit comparable_group are compared, and only against a
    strictly later scan date. The wording never claims the finding was fixed.
    """
    by_group: dict = {}
    for run in sorted(runs, key=_run_sort_key):
        if run.comparable_group:
            by_group.setdefault(run.comparable_group, []).append(run)

    rows: list = []
    for group, group_runs in by_group.items():
        latest = group_runs[-1]
        earlier = [r for r in group_runs[:-1] if r.scan_date < latest.scan_date]
        if not earlier:
            continue

        latest_findings = findings_by_run.get(latest.id, ())
        present = {(asset_key(f.asset_name), f.cve_id) for f in latest_findings}
        assets_in_latest = {asset_key(f.asset_name) for f in latest_findings}

        last_seen: dict = {}
        for run in earlier:  # chronological, so later scans overwrite earlier ones
            for f in findings_by_run.get(run.id, ()):
                last_seen[(asset_key(f.asset_name), f.cve_id)] = f

        for key, finding in last_seen.items():
            if key in present:
                continue
            entry = match_kev(finding.cve_id, current_kev)
            asset_note = ""
            if key[0] not in assets_in_latest:
                asset_note = (
                    f" No finding for {finding.asset_name} appears in the later scan at all, which often "
                    "indicates the asset was not covered by it."
                )
            kev_note = ""
            if entry is not None:
                kev_note = (
                    f" The CVE is listed in KEV snapshot {cur_label} (CISA date added: {entry.date_added}), "
                    "so confirm its status before treating this finding as closed."
                )
            rows.append(
                ChangeResult(
                    asset_name=finding.asset_name,
                    cve_id=finding.cve_id,
                    scan_date=finding.scan_date,
                    finding_status=finding.finding_status,
                    scan_group=group,
                    kev_match_status="Listed in KEV" if entry else "Not listed in KEV",
                    kev_date_added=entry.date_added if entry else "",
                    kev_vulnerability_name=entry.vulnerability_name if entry else "",
                    previous_snapshot=prev_label,
                    current_snapshot=cur_label,
                    kev_change="Not applicable",
                    change_category=CAT_NOT_OBSERVED,
                    explanation=(
                        f"{finding.cve_id} was reported on {finding.asset_name} in the scan dated "
                        f"{finding.scan_date} (status: {finding.finding_status}) but does not appear in the "
                        f"later comparable scan dated {latest.scan_date} (group: {group}). Absence from a scan "
                        "is not evidence of a change on the asset: scan coverage, configuration, credentials, "
                        f"timing or a renamed asset can all explain it.{asset_note}{kev_note}"
                    ),
                    recommended_action=(
                        "Re-run a scan with the same profile and coverage, or check the asset manually, "
                        "before changing the finding's status."
                    ),
                    compared_to_scan_date=latest.scan_date,
                )
            )
    return rows


# --------------------------------------------------------------------------- main
def analyze(
    runs: Sequence[ScanRunInfo],
    findings_by_run: Mapping[int, Sequence[FindingRow]],
    current_snapshot: SnapshotInfo,
    current_kev: Mapping[str, KevEntry],
    previous_snapshot: Optional[SnapshotInfo] = None,
    previous_kev: Optional[Mapping[str, KevEntry]] = None,
) -> list:
    """Produce the explainable findings table for one chosen snapshot.

    ``previous_*`` is the snapshot stored immediately before ``current_*`` (or None).
    """
    cur_label = snapshot_label(current_snapshot)
    prev_label = snapshot_label(previous_snapshot)
    if previous_snapshot is None:
        previous_kev = None

    results: list = []
    for group, run in latest_run_per_group(runs).items():
        for finding in findings_by_run.get(run.id, ()):
            entry = match_kev(finding.cve_id, current_kev)
            results.append(_kev_row(finding, group, entry, cur_label, prev_label, previous_kev))

    results.extend(find_not_observed(runs, findings_by_run, current_kev, cur_label, prev_label))

    order = {name: position for position, name in enumerate(CATEGORY_ORDER)}
    results.sort(key=lambda r: (order[r.change_category], r.asset_name.casefold(), r.cve_id))
    return results
