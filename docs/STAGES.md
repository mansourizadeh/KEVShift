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

## Decisions worth remembering
* Only exact CVE-ID matching. The demo catalog contains `CVE-2099-00011` to prove `CVE-2099-0001` is not matched by substring.
* Comparable scans are defined by a user-entered group label; unlabelled scans are never used for "not observed".
* A KEV-listed finding whose status is mitigated, accepted_risk or false_positive becomes "Needs manual review".
* A failed refresh returns status `cached` or `unavailable` and `is_success` False; the UI shows a warning/error only.
* Unchanged catalog content does not create a new snapshot but is recorded as a successful check.

## Not done on purpose
Nessus adapter and CVSS/NVD enrichment (the specification says not before the core is complete; listed as future work).

## Known gaps to check yourself
* Real CISA download was not run in my environment's tests (mocked). Press **Refresh KEV catalog now** once on your own
  internet connection and confirm it succeeds.
* I did not view the dashboard in a real browser; it was checked with Streamlit's headless test runner and an HTTP check.
* Developed on Python 3.13; your machine has Python 3.14. If an install fails on 3.14, install Python 3.12 or 3.13.
