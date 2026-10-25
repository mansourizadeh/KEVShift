# Stage Log: what was done, in order

Use this file to ask follow-up questions later, for example "explain stage 5" or "change the rule in stage 5".
File names are relative to the project folder.

| Stage | What was done | Main files | Verified by |
|---|---|---|---|
| 1. Environment and skeleton | Checked Python, installed Streamlit and pytest, created folders, requirements, .gitignore, pytest.ini, module docstrings, a placeholder app, the first architecture note | `requirements.txt`, `pytest.ini`, `.gitignore`, `src/__init__.py`, `tests/test_project_skeleton.py` | 8 smoke tests |
| 2. CSV import and CVE validation | Validators (CVE, date, asset), data models, importer with row-level reasons, duplicate detection, status vocabulary, file-level errors | `src/validators.py`, `src/models.py`, `src/csv_importer.py` | `tests/test_csv_importer.py` |
| 3. SQLite schema and history | Seven tables, foreign keys, UNIQUE fingerprints, indexes, transactions, event log, query helpers | `src/database.py`, `docs/DATABASE_SCHEMA.md` | `tests/test_database.py` (rollback, restart persistence) |
| 4. KEV client | Download with timeout and status checks, strict JSON validation, atomic file saving, snapshot storage, offline fallback, cache age and staleness | `src/kev_client.py` | `tests/test_kev_client.py` (HTTP mocked) |
| 5. Change detection | Six rule-based categories, catalog diff, "not observed" within comparable groups, explanations and verification actions | `src/change_detector.py`, `src/workflow.py` | `tests/test_change_detector.py` |
| 6. Reporting and dashboard | Findings table, filters, CSV export with formula neutralization, validation report, six-page Streamlit app | `src/reporting.py`, `app.py` | `tests/test_reporting.py`, `tests/test_app_smoke.py` |
| 7. Synthetic demo and acceptance tests | Invented scans and KEV snapshots (CVE-2099-xxxx), step-by-step demo loader, CLI demo, saved before/after reports | `sample_data/*`, `src/demo.py`, `docs/demo_reports/` | `tests/test_workflow_and_demo.py` |
| 8. Full run and checks | Ran the complete suite, fixed 2 failures (Windows-style file path in the filename sanitizer; a demo asset name in a test), started the real Streamlit server and got HTTP 200 on its health check and page | `src/workflow.py`, tests | 128 passed |
| 9. Optional EPSS | Validated API client, cache table, live/cached and stale labels, dashboard expander | `src/epss_client.py` | `tests/test_epss_client.py` |
| 10. Documentation | README with Windows steps and troubleshooting, architecture, schema, module guide, report, demo script, defense questions, glossary, GitHub guide, this log | `README.md`, `docs/*` | Read-through; commands in docs were run |

## Review follow-up (after the first delivery)

| Stage | What was done | Main files | Verified by |
|---|---|---|---|
| 11. Unlabelled scans (review item A) | Each scan without a comparable-group label is now its own independent group (`(unlabelled) scan #<id>`), so an older unlabelled scan no longer disappears from the current findings. Unlabelled scans still never produce "Not observed". Help text updated. | `src/change_detector.py`, `app.py` | 1 old test replaced (it asserted the old, hiding behaviour) and 4 new tests; end-to-end check through real import and database; deliberately restoring the old behaviour makes a test fail |
| 12. Python-version documentation (item B) | README no longer claims a single version. It lists exactly what was run: 3.11.17, 3.12.3 and 3.13.17 on Linux, 154 passed; pandas 2.3.3 and 3.1.0; recommends 3.12 or 3.13; says plainly that 3.14, Windows and 3.10 were not verified by the author. (The first README said 3.13, which matched the runs actually made; a 3.14.3 run was never reported by me.) | `README.md` | The suite was actually run on each interpreter before the table was written |
| 13. Real catalog evidence (priority 3) | Extracted three unmodified real KEV snapshots (1, 15, 23 Oct 2026) from CISA's own GitHub repository (cisa.gov itself was blocked), with manifest and CC0 licence; 22 tests; `tools/verify_real_kev.py`; evidence document and per-snapshot reports | `sample_data/real/*`, `tests/test_real_catalog.py`, `tools/verify_real_kev.py`, `docs/REAL_DATA_EVIDENCE.md`, `docs/real_evidence/` | 154 passed; mutation check: breaking exact matching fails 5 real-data tests |

Test count history: 8 (stage 1) -> 128 (stage 8) -> 132 (stage 11) -> 154 (stage 13).

## Decisions worth remembering
* Only exact CVE-ID matching. The demo catalog contains `CVE-2099-00011` to prove `CVE-2099-0001` is not matched by substring.
* Comparable scans are defined by a user-entered group label. Unlabelled scans stand alone: always shown, each independent, never used for "not observed" (changed in stage 11).
* A KEV-listed finding whose status is mitigated, accepted_risk or false_positive becomes "Needs manual review".
* A failed refresh returns status `cached` or `unavailable` and `is_success` False; the UI shows a warning/error only.
* Unchanged catalog content does not create a new snapshot but is recorded as a successful check.

## Not done on purpose
Nessus adapter and CVSS/NVD enrichment (the specification says not before the core is complete; listed as future work).

## Known gaps to check yourself
* The live cisa.gov download was never run by me (blocked in my environment). Real catalog CONTENT was verified with
  files from CISA's GitHub repository (stage 13). Run `python tools/verify_real_kev.py` once on your own internet
  connection, and press **Refresh KEV catalog now** in the dashboard, to confirm the live endpoint.
* I did not view the dashboard in a real browser; it was checked with Streamlit's headless test runner and an HTTP check.
* Verified Python: 3.11, 3.12, 3.13 (Linux). Not verified: 3.14, Windows. Your machine uses Python 3.14: if an install or
  test fails there, install Python 3.12 or 3.13.
