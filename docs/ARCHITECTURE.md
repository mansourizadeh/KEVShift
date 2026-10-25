# KEVShift Architecture

## 1. The big idea in one example

A scan on **1 October** reports `CVE-2099-0001` on `web-server-01` (synthetic). The KEV snapshot stored at
that time does **not** list it, so nothing is flagged. On **15 October** a newer KEV snapshot is stored and
lists it. Nobody imported a new scan, yet KEVShift can say:

> "The finding reported on 1 October now matches a CVE that was added to KEV between your two catalog
> checks. Verify whether it still applies and prioritize it."

It never says the asset was attacked, never says it is exploitable, and never produces a risk score. KEV says
exploitation of a CVE has been documented somewhere in the world; it says nothing about one specific asset.
To make this possible, KEVShift keeps **history**: scans and snapshots are stored, never overwritten.

## 2. Data flow

```
 scan CSV --> csv_importer --+
 (you upload)  (validate)    |                       +--> reporting --> app.py (Streamlit)
                             v                       |   (tables, CSV)    (pages only)
                         workflow.import_scan   workflow.run_analysis
                             |                       ^
                             v                       |
                          database  <----------------+--> change_detector (pure rules)
                          (SQLite)
                             ^
 CISA JSON feed --> kev_client (download, validate, save snapshot file, offline fallback)
 (or saved file)
```

## 3. Modules

| Module | Problem it solves |
|---|---|
| `validators.py` | One definition of a valid CVE ID, date and asset identity |
| `models.py` | Plain data containers so modules do not depend on each other's internals |
| `csv_importer.py` | Turn an untrusted CSV into clean rows plus an honest report of rejects and duplicates |
| `database.py` | Permanent, historical storage with transactions |
| `kev_client.py` | Download, validate and cache KEV without ever losing a good snapshot |
| `change_detector.py` | The rule-based comparisons and their explanations (pure functions) |
| `workflow.py` | Two entry points used by the app, the demo and the tests: `import_scan`, `run_analysis` |
| `reporting.py` | Findings table, filters, CSV export (with formula neutralization), text reports |
| `epss_client.py` | Optional supplementary EPSS values with caching and stale labels |
| `demo.py` | The synthetic scenario from the specification |
| `app.py` | Streamlit pages; no rules |

## 4. Key design decisions

1. **Logic is separate from the interface.** `change_detector.py` knows nothing about Streamlit or SQLite, so
   pytest can check every rule quickly, and results are reproducible.
2. **Snapshots are immutable.** A snapshot is saved once as a JSON file and as database rows. A flag can be
   reproduced later from saved records only.
3. **Validate before saving.** A downloaded catalog is parsed and checked (valid JSON, version, release date,
   non-empty list, declared count equals actual count, valid CVE IDs and dates) before anything is written.
4. **Failure never destroys data.** A failed refresh writes only an event-log row. The last valid snapshot stays.
5. **Explicit comparability.** "Not observed in latest scan" is only computed between scans that share a
   user-assigned comparable group and have different dates. It is never described as fixed.
6. **Rule-based categories instead of a score.** Each row has one category, an explanation and a verification action.
7. **Exact matching.** CVE IDs are matched with dictionary lookups on normalized IDs, never substrings.
8. **Small dependency set.** Streamlit, pandas, requests, pytest plus the standard library.
9. **Generated files stay out of source control** (`data/` is git-ignored; test fixtures are in `sample_data/` and `tests/`).

## 5. How the change categories are decided

For the chosen snapshot S and its predecessor P (the snapshot stored just before S, or none):

1. Choose the scans shown as "current": the newest scan of each labelled comparable group, plus **every** unlabelled
   scan, each as its own independent group (`(unlabelled) scan #<id>`), so no unlabelled scan is hidden by another.
2. For each finding in those scans:
   * CVE not in S -> **No KEV match**.
   * CVE in S and status is mitigated / accepted_risk / false_positive -> **Needs manual review**.
   * CVE in S and no P -> **First observed KEV match**.
   * CVE in S, not in P -> **Newly added to KEV**.
   * CVE in S and in P -> **Still present and listed in KEV**.
3. Only labelled groups take part here; unlabelled scans never do. For each labelled group with an earlier scan on a strictly earlier date: every asset/CVE pair seen in an earlier
   scan but absent from the group's latest scan -> **Not observed in latest scan**.

## 6. Changes from the suggested structure

* Added `validators.py`, `models.py`, `workflow.py`, `demo.py` (shared code, data containers, glue, demonstration).
* Added `docs/` for the schema, module guide, report, demo script, defense questions and glossary.
* Added `pytest.ini` so tests can `import src` without extra setup.
* Tests are grouped by module plus `test_workflow_and_demo.py` (acceptance scenario) and `test_app_smoke.py`.
