"""KEVShift dashboard.

Run from the project folder with:  streamlit run app.py

This file only draws pages and calls functions from src/. It contains no business rules.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st

from src import (
    __version__,
    change_detector,
    csv_importer,
    database,
    demo,
    epss_client,
    kev_client,
    reporting,
    workflow,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_DIR = PROJECT_ROOT / "sample_data"
BASE_DATA_DIR = Path(os.environ.get("KEVSHIFT_DATA_DIR", PROJECT_ROOT / "data"))

PAGES = ["Overview", "Import scan CSV", "KEV catalog", "Findings", "History", "Help and limitations"]
MODE_MINE, MODE_DEMO = "My data", "Synthetic demo"


# ---------------------------------------------------------------------------- pages
def page_overview(conn) -> None:
    st.header("Overview")
    runs = database.list_scan_runs(conn)
    snapshots = database.list_snapshots(conn)
    bundle = workflow.run_analysis(conn)
    table = reporting.results_to_dataframe(bundle.results)

    in_latest = int((table["Change category"] != change_detector.CAT_NOT_OBSERVED).sum()) if not table.empty else 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Scan imports", len(runs))
    c2.metric("Findings in latest scans", in_latest)
    c3.metric("KEV snapshots stored", len(snapshots))
    c4.metric("Assets with findings", table["Asset"].nunique() if not table.empty else 0)

    for note in bundle.notes:
        st.info(note)

    if not table.empty:
        st.subheader("Findings by change category")
        counts = reporting.category_counts(table)
        columns = st.columns(len(counts))
        for column, (name, value) in zip(columns, counts.items()):
            column.metric(name, value)

    st.subheader("Scan history")
    if runs:
        st.dataframe(pd.DataFrame([asdict(r) for r in runs]).drop(columns=["file_sha256", "stored_path"]),
                     width="stretch", hide_index=True)
    else:
        st.write("No scans imported yet. Use **Import scan CSV** in the sidebar.")


def page_import(conn, data_dir: Path) -> None:
    st.header("Import scan CSV")
    st.write(
        "Upload a CSV with the columns `asset_name`, `cve_id`, `scan_date` (YYYY-MM-DD) and `finding_status`. "
        "KEVShift never scans anything; it only reads the file you give it."
    )
    st.download_button(
        "Download example CSV (synthetic data)",
        (SAMPLE_DIR / "sample_scan_previous.csv").read_bytes(),
        file_name="example_scan.csv",
        mime="text/csv",
    )
    with st.expander("Accepted finding_status values"):
        st.table({"finding_status": list(csv_importer.ALLOWED_STATUSES),
                  "Meaning": list(csv_importer.ALLOWED_STATUSES.values())})

    uploaded = st.file_uploader("Scan CSV file", type=["csv"])
    group = st.text_input(
        "Comparable scan group (optional but needed for 'not observed' detection)",
        help="Give the same label (for example 'internal-weekly') to scans made with the same scope and "
             "configuration. Only scans with the same label are compared with each other. A scan without a "
             "label is kept on its own: it is always shown, but never used for 'Not observed' results.",
    )
    if uploaded is None:
        st.info("Choose a CSV file to validate it. Nothing is saved until you press the save button.")
        return

    data = uploaded.getvalue()
    try:
        result = csv_importer.parse_csv_bytes(data)
    except csv_importer.CsvFormatError as exc:
        st.error(f"This file cannot be imported: {exc}")
        return

    st.subheader("Validation result")
    columns = st.columns(4)
    for column, (label, value) in zip(columns, reporting.import_summary(result).items()):
        column.metric(label, value)

    report = reporting.validation_report_dataframe(result)
    if not report.empty:
        st.warning("Some rows were rejected or ignored. Nothing was silently discarded; see the details below.")
        st.dataframe(report, width="stretch", hide_index=True)
        st.download_button("Download validation report (CSV)", reporting.dataframe_to_csv_bytes(report),
                           file_name="validation_report.csv", mime="text/csv")

    if not result.accepted:
        st.error("There are no valid rows, so there is nothing to save.")
        return
    if st.button("Save accepted rows to the database", type="primary"):
        try:
            outcome = workflow.import_scan(conn, data_dir, data, uploaded.name, group,
                                           database.utc_timestamp())
            st.success(outcome.message)
        except database.DuplicateImportError as exc:
            st.warning(str(exc))
        except csv_importer.CsvFormatError as exc:
            st.error(str(exc))


def page_kev(conn, data_dir: Path) -> None:
    st.header("KEV catalog")
    st.write(f"Official source: `{kev_client.KEV_FEED_URL}`")

    if st.button("Refresh KEV catalog now", type="primary"):
        with st.spinner("Contacting CISA..."):
            result = kev_client.refresh_kev(conn, data_dir)
        if result.is_success:
            st.success(result.message)
        elif result.used_cache:
            st.warning(result.message)
        else:
            st.error(result.message)

    status = kev_client.kev_status(conn)
    if status is None:
        st.info("No KEV snapshot is stored yet. Press the refresh button, or load a KEV JSON file below.")
    else:
        st.subheader("Status")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Snapshot version", status.snapshot.catalog_version)
        c2.metric("Catalog released", status.snapshot.date_released[:10])
        c3.metric("Entries", status.snapshot.entry_count)
        c4.metric("Age of saved data", status.age_text)
        st.write(f"Last successful check (UTC): **{status.last_checked_at}**. "
                 f"Snapshot retrieved (UTC): **{status.snapshot.retrieved_at}**. "
                 f"Source: `{status.snapshot.source_url}`")
        if status.is_stale:
            st.warning(f"The saved data is more than {kev_client.STALE_AFTER_DAYS} days old. "
                       "Results use this saved copy until a refresh succeeds.")

    with st.expander("Load a KEV JSON file manually (for offline use)"):
        st.caption("The file is validated exactly like a download. It is recorded as an uploaded file, "
                   "and the time it was loaded is stored as its retrieval time.")
        uploaded = st.file_uploader("KEV JSON file", type=["json"], key="kev_upload")
        if uploaded is not None and st.button("Validate and store this KEV file"):
            try:
                _, created = kev_client.store_snapshot_bytes(
                    conn, uploaded.getvalue(), data_dir,
                    source_url=f"uploaded-file:{Path(uploaded.name).name}",
                    retrieved_at=database.utc_timestamp())
                st.success("Snapshot stored." if created else "This exact catalog was already stored.")
            except kev_client.KevError as exc:
                st.error(f"The file was rejected and nothing was saved: {exc}")


def page_findings(conn) -> None:
    st.header("Findings")
    snapshots = database.list_snapshots(conn)
    if not snapshots:
        st.info("Load a KEV snapshot first (KEV catalog page).")
        return

    options = {f"{s.catalog_version} - retrieved {s.retrieved_at}": s.id for s in reversed(snapshots)}
    chosen = st.selectbox("KEV snapshot to compare against", list(options), index=0)
    bundle = workflow.run_analysis(conn, options[chosen])
    for note in bundle.notes:
        st.info(note)
    table = reporting.results_to_dataframe(bundle.results)
    if table.empty:
        st.info("There are no findings to show yet. Import a scan CSV first.")
        return

    st.caption(f"Compared snapshot: {change_detector.snapshot_label(bundle.current_snapshot)}. "
               f"Previous snapshot: {change_detector.snapshot_label(bundle.previous_snapshot)}.")

    f1, f2, f3, f4 = st.columns(4)
    assets = f1.multiselect("Asset", sorted(table["Asset"].unique()))
    cve_text = f2.text_input("CVE contains")
    statuses = f3.multiselect("Finding status", sorted(table["Finding status"].unique()))
    categories = f4.multiselect("Change category", [c for c in change_detector.CATEGORY_ORDER
                                                     if c in set(table["Change category"])])
    view = reporting.filter_results(table, assets=assets, cve_text=cve_text, statuses=statuses,
                                    categories=categories)
    st.write(f"Showing {len(view)} of {len(table)} rows.")
    st.dataframe(view, width="stretch", hide_index=True)
    st.download_button("Download filtered findings (CSV)", reporting.dataframe_to_csv_bytes(view),
                       file_name="kevshift_findings.csv", mime="text/csv")

    with st.expander("What each category means and its limits"):
        for name in change_detector.CATEGORY_ORDER:
            info = change_detector.CATEGORY_HELP[name]
            st.markdown(f"**{name}**  \n{info['meaning']}  \n*Limitation:* {info['limitation']}")

    with st.expander("Supplementary: EPSS (optional, never replaces KEV)"):
        st.caption("EPSS estimates the probability of exploitation in the wild soon. KEV records vulnerabilities "
                   "for which exploitation has been documented. EPSS is shown only as extra context.")
        listed = sorted(set(view.loc[view["KEV match"] == "Listed in KEV", "CVE"]))
        if not listed:
            st.write("No KEV-listed CVEs in the current view.")
        else:
            if st.button("Fetch EPSS values from FIRST"):
                with st.spinner("Contacting api.first.org..."):
                    refreshed = epss_client.refresh_epss(conn, listed)
                (st.success if refreshed.ok else st.warning)(refreshed.message)
            cached = epss_client.read_cached(conn, listed)
            if cached:
                st.dataframe(pd.DataFrame([{
                    "CVE": s.cve_id, "EPSS probability": s.epss, "EPSS percentile": s.percentile,
                    "Score date": s.score_date, "Retrieved (UTC)": s.fetched_at,
                    "Source": "cached copy", "Stale": "yes" if s.stale else "no"} for s in cached.values()]),
                    width="stretch", hide_index=True)
            else:
                st.write("No EPSS values cached yet.")


def page_history(conn) -> None:
    st.header("History")
    st.subheader("Scan runs")
    runs = database.list_scan_runs(conn)
    if runs:
        st.dataframe(pd.DataFrame([asdict(r) for r in runs]).drop(columns=["file_sha256", "stored_path"]),
                     width="stretch", hide_index=True)
    else:
        st.write("No scans imported yet.")

    st.subheader("KEV snapshots and catalog changes")
    snapshots = database.list_snapshots(conn)
    if snapshots:
        rows, previous_index = [], None
        for snap in snapshots:
            index = database.get_kev_index(conn, snap.id)
            added, removed = (change_detector.diff_catalogs(previous_index, index)
                              if previous_index is not None else ([], []))
            rows.append({"Version": snap.catalog_version, "Retrieved (UTC)": snap.retrieved_at,
                         "Entries": snap.entry_count,
                         "Added vs previous": len(added) if previous_index is not None else "first snapshot",
                         "Removed vs previous": len(removed) if previous_index is not None else "first snapshot",
                         "Source": snap.source_url})
            previous_index = index
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

        if len(snapshots) >= 2:
            labels = {f"{s.catalog_version} ({s.retrieved_at[:10]})": s.id for s in snapshots}
            names = list(labels)
            a, b = st.columns(2)
            older = a.selectbox("Older snapshot", names, index=len(names) - 2)
            newer = b.selectbox("Newer snapshot", names, index=len(names) - 1)
            added, removed = change_detector.diff_catalogs(database.get_kev_index(conn, labels[older]),
                                                           database.get_kev_index(conn, labels[newer]))
            st.write(f"**Added to KEV:** {', '.join(added) if added else 'none'}")
            st.write(f"**Removed from KEV:** {', '.join(removed) if removed else 'none'}")
    else:
        st.write("No KEV snapshots stored yet.")

    st.subheader("Event log")
    events = database.list_events(conn)
    if events:
        st.dataframe(pd.DataFrame([dict(e) for e in events]).drop(columns=["id", "scan_run_id", "snapshot_id"]),
                     width="stretch", hide_index=True)
    else:
        st.write("No events yet.")


def page_help() -> None:
    st.header("Help and limitations")
    st.write("KEVShift is **not** a vulnerability scanner. It reads scan results you already have, keeps their "
             "history, and compares the reported CVEs with the CISA KEV catalog.")
    for name in change_detector.CATEGORY_ORDER:
        info = change_detector.CATEGORY_HELP[name]
        st.subheader(name)
        st.write(info["meaning"])
        st.caption(f"Limitation: {info['limitation']}")
    st.subheader("General limits")
    st.markdown(
        "- KEV does not prove an asset was attacked or is exploitable.\n"
        "- Absence from a later scan is not proof of a change on the asset.\n"
        "- Only scans with the same comparable group label are compared with each other.\n"
        "- A scan WITHOUT a label stands alone: its findings are always shown, and it can never produce "
        "'Not observed in latest scan'.\n"
        "- Timestamps are in UTC. Results depend on the saved snapshots, not on today's catalog.\n"
        "- KEVShift gives rule-based categories, not a risk score."
    )


# ---------------------------------------------------------------------------- main
def sidebar_demo_controls(data_dir: Path) -> None:
    st.sidebar.markdown("**Synthetic demo** (invented data)")
    chosen = None
    for step in demo.STEPS:
        if st.sidebar.button(f"Load demo up to step {step.number}", key=f"demo_step_{step.number}"):
            chosen = step.number
    if chosen is not None:
        conn = database.connect(data_dir / "kevshift.db")
        database.init_schema(conn)
        try:
            for message in demo.apply_step(conn, data_dir, SAMPLE_DIR, chosen):
                st.sidebar.write(message)
        finally:
            conn.close()
    if st.sidebar.button("Reset demo data", key="demo_reset"):
        demo.reset_demo_dir(data_dir)
        st.sidebar.success("Demo data deleted.")


def main() -> None:
    st.set_page_config(page_title="KEVShift", layout="wide")
    st.title("KEVShift")
    st.caption(f"Explainable vulnerability change tracking - version {__version__}")

    mode = st.sidebar.radio("Data set", [MODE_MINE, MODE_DEMO], key="mode")
    data_dir = BASE_DATA_DIR if mode == MODE_MINE else BASE_DATA_DIR / "demo"
    page = st.sidebar.radio("Page", PAGES, key="page")
    if mode == MODE_DEMO:
        sidebar_demo_controls(data_dir)
        st.info("You are viewing the SYNTHETIC demo data set. All records are invented.")

    conn = database.connect(data_dir / "kevshift.db")
    database.init_schema(conn)
    try:
        if page == "Overview":
            page_overview(conn)
        elif page == "Import scan CSV":
            page_import(conn, data_dir)
        elif page == "KEV catalog":
            page_kev(conn, data_dir)
        elif page == "Findings":
            page_findings(conn)
        elif page == "History":
            page_history(conn)
        else:
            page_help()
    finally:
        conn.close()


main()
