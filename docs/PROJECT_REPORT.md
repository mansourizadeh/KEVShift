# KEVShift: Explainable Vulnerability Change Tracking
### Bachelor's Final Project Report, Computer Engineering

## 1. Problem statement
Organizations receive vulnerability scan reports repeatedly. The CISA Known Exploited Vulnerabilities (KEV) catalog
changes over time: a CVE that was not listed when a scan ran may be added days later. A normal scan report cannot show
this, because the scan itself did not change. Analysts need to know (a) which previously reported findings now match
KEV, (b) whether that is a *new* catalog change, and (c) what disappeared from later scans, **without** unsupported
claims such as "this asset was attacked" or "this was fixed".

## 2. Objectives
1. Import scan results from a simple CSV with strict, transparent validation.
2. Download, validate and store KEV snapshots so every comparison is reproducible and works offline.
3. Detect catalog changes independently of new scans.
4. Detect findings not observed in a later, explicitly comparable scan, described cautiously.
5. Explain every flag in plain English with a recommended verification action.
6. Provide a local Streamlit dashboard, CSV exports, automated tests and documentation.

Non-goals: scanning, exploitation, authentication, risk scoring, claims about attacks or remediation.

## 3. Methodology
Incremental development in ten phases, each ending with tests (see `docs/STAGES.md`). Rules were written as pure
functions and tested with synthetic fixtures and mocked HTTP, so no test needs the internet. Requirements from the
specification were mapped to automated tests (section 7).

## 4. Architecture
See `docs/ARCHITECTURE.md` (modules, data flow, decisions) and `docs/DATABASE_SCHEMA.md` (tables).
Layers: **input** (csv_importer, kev_client) -> **storage** (database) -> **rules** (change_detector) ->
**presentation** (reporting, app.py), glued by `workflow.py`.

## 5. Implementation summary
* **CSV import:** UTF-8 (BOM tolerated), required columns, per-row validation that reports *all* problems of a row,
  CVE normalization (`fullmatch`, ASCII digits only), strict `YYYY-MM-DD` dates not in the future, controlled status
  vocabulary, duplicate detection by (asset, CVE), original file kept with a SHA-256 fingerprint.
* **KEV client:** timeout, HTTP status check, size limit, JSON structure validation (including declared count versus
  actual count), atomic file write, one database transaction per snapshot, unchanged content does not create a duplicate
  snapshot, offline fallback to the last valid snapshot with clear labelling and age.
* **Database:** SQLite with primary keys, foreign keys, UNIQUE constraints, indexes, transactions and an event log.
* **Change detection:** six categories decided by explicit rules (ARCHITECTURE section 5).
* **Dashboard:** overview, import with validation report, KEV status and refresh, filterable findings with CSV download,
  history with catalog diffs and event log, help page with limitations of each category.
* **EPSS (optional):** validated API client with cache and stale labels; displayed separately from KEV.

## 6. Limitations
* Comparability of scans is declared by the user through a group label; the tool cannot verify scan scope.
* Matching is by CVE ID only; no product or version reasoning.
* Asset identity is the (case-insensitive) name; a renamed asset appears as "not observed" plus a new finding.
* KEV records documented exploitation somewhere; it never proves exploitation of a given asset.
* The snapshot "previous" is the one stored immediately before; checks are only as frequent as the user refreshes.
* Local single-user tool: no authentication or concurrent multi-user access.
* Not implemented, by design: Nessus adapter, CVSS/NVD enrichment (future work).
* The dashboard was verified with Streamlit's headless test runner and an HTTP health check of the running server;
  a human visual review in a browser is still recommended before the defense.

## 7. Evaluation
Run `python -m pytest`. On the development machine (Python 3.13) the result was **128 passed**.

| Spec test area | Where tested |
|---|---|
| CVE normalization / invalid CVE | `test_csv_importer.py` |
| Missing columns, invalid dates, duplicates | `test_csv_importer.py` |
| KEV parsing, malformed JSON | `test_kev_client.py` |
| Exact CVE matching, no substrings | `test_kev_client.py`, `test_change_detector.py`, demo acceptance test |
| Newly added KEV entry | `test_change_detector.py` |
| KEV match in latest comparable scan | `test_change_detector.py` |
| Not observed in later comparable scan; no remediation claim | `test_change_detector.py` |
| Catalog change without a new scan | `test_change_detector.py`, `test_workflow_and_demo.py` |
| Offline operation with cache; failed refresh keeps snapshot | `test_kev_client.py` |
| Persistence across restarts; transactions | `test_database.py` |
| Reproducible output from stored snapshots | `test_workflow_and_demo.py` |
| CSV report generation | `test_reporting.py` |
| Dashboard renders, no false success message | `test_app_smoke.py` |

Demonstration reproduces the required scenario: see `docs/demo_reports/` and `docs/DEMO_SCRIPT.md`.

## 8. Future work
Nessus CSV adapter, CVSS enrichment, scheduled refresh, snapshot-to-snapshot report export, asset aliasing,
multi-user storage.

## 9. Ethics and safety
The application only reads files the user supplies and two public data sources. It performs no scanning or
exploitation and avoids language that asserts attacks or fixes. All demonstration data is synthetic (CVE-2099-xxxx).
