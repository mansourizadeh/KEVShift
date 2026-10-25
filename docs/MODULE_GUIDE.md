# KEVShift Module Guide (for learning and for your defense)

For every module: the problem it solves, inputs and outputs, how it works, the important functions, how it
connects to the rest, how to test it, and questions a professor may ask.

---

## 0. Core concepts with tiny examples

**CSV** is a text table: one line per row, columns separated by commas.
```
asset_name,cve_id,scan_date,finding_status
web-server-01,CVE-2099-0001,2025-10-01,open
```
pandas reads it into a table; Python's `csv`/pandas treat every cell as plain text.

**JSON** is structured text made of objects `{}` (name/value pairs) and lists `[]`. The KEV feed looks like:
```
{"catalogVersion": "2025.10.15", "count": 1,
 "vulnerabilities": [{"cveID": "CVE-2099-0001", "dateAdded": "2025-10-14"}]}
```
`json.loads(text)` turns it into Python dictionaries and lists.

**SQLite** is a database stored in one file, used through the built-in `sqlite3` module. Tables hold rows;
`SELECT` reads, `INSERT` writes. We always pass values separately: `execute("... WHERE cve_id = ?", (cve,))`
(a *parameterized query*), which prevents SQL injection.

**HTTP request / API:** a program asks a web address for data. `requests.get(url, timeout=30)` sends a GET request;
the answer has a *status code* (200 = OK, 404 = not found, 500 = server error). An **API** is a web address designed
for programs, returning data (usually JSON) instead of a web page.

**CVE normalization:** `"  cve-2024-12345 "` -> `"CVE-2024-12345"` (trim spaces, upper case). We then validate with the
pattern `CVE-` + 4-digit year + `-` + 4 or more digits. Normalizing first means `cve-2024-1` and `CVE-2024-1` are
recognized as the same ID, and exact comparison afterwards is safe.

**Snapshot:** a frozen copy of the KEV catalog at one moment. Comparing snapshot A (1 Oct) with snapshot B (15 Oct)
shows what CISA added in between.

**Transaction:** a group of database changes that succeed or fail together. If the 3rd of 4 writes fails, the first 2
are undone, so the database is never left half-updated. In code: `with conn:`.

**Unit test:** a small function that runs one piece of code with known input and checks the output with `assert`.
```
def test_cve_normalization():
    assert normalize_cve_id(" cve-2099-0001 ") == "CVE-2099-0001"
```

**Change detection:** comparing two sets. `added = set(current) - set(previous)` gives the CVEs new in the current
snapshot; a finding matches when its CVE is in `added`.

---

## 1. validators.py
* **Problem:** every module must agree what a valid CVE ID and date are.
* **Input -> output:** any value -> normalized CVE string or `None`; any value -> `date` or `None`.
* **How:** regular expression with `fullmatch` and `[0-9]` (not `\d`, which would also accept non-ASCII digits such as
  Persian digits). Year must be 1999 or later. Dates must be exactly `YYYY-MM-DD`.
* **Functions:** `normalize_cve_id`, `parse_iso_date`, `clean_asset_name`, `asset_key`.
* **Connects to:** csv_importer, kev_client, epss_client, change_detector.
* **Test:** `python -m pytest tests/test_csv_importer.py -k cve`
* **Professor may ask:** Why `fullmatch` and not `match`? (`match` accepts trailing garbage.) Why `[0-9]`? (see above.)

## 2. csv_importer.py
* **Problem:** a user-supplied CSV is untrusted and often messy.
* **Input -> output:** raw bytes -> `ImportResult` (accepted rows, rejected rows with reasons, duplicates, scan date).
* **How:** decode as UTF-8 (BOM allowed) -> read with pandas as text -> check required columns -> validate each row,
  collecting *all* problems per row -> detect duplicates by (asset, CVE) -> never drop anything silently.
  Whole-file problems (missing column, empty, binary, not UTF-8) raise `CsvFormatError`; row problems never raise.
* **Functions:** `parse_csv_bytes`, `_validate_row`, `decode_csv_bytes`, `sha256_hex`.
* **Connects to:** workflow.import_scan (stores the result), reporting (validation report), app (upload page).
* **Test:** `python -m pytest tests/test_csv_importer.py -v`
* **Professor may ask:** Why not reject the whole file on one bad row? What happens with duplicates that have different
  statuses? (Second row ignored and reported; its status is not used.) How do you prevent CSV injection? (Exports
  prefix risky cells with a quote; uploaded content is never executed.)

## 3. database.py
* **Problem:** keep history permanently and safely.
* **Input -> output:** validated data -> rows; queries -> dataclasses (`ScanRunInfo`, `SnapshotInfo`, `FindingRow`).
* **How:** schema in one string; `connect` turns on foreign keys; writes that touch several tables run in one
  transaction; unique fingerprints (SHA-256) prevent duplicate imports and duplicate snapshots; new data is added, never overwritten.
* **Functions:** `init_schema`, `store_scan_run`, `store_kev_snapshot`, `list_scan_runs`, `list_snapshots`, `get_findings`,
  `get_kev_index`, `add_event`.
* **Connects to:** kev_client and workflow write; workflow and app read. See `DATABASE_SCHEMA.md`.
* **Test:** `python -m pytest tests/test_database.py -v` (includes restart persistence and rollback).
* **Professor may ask:** Why SQLite? Why a UNIQUE hash? What is a foreign key? What does `with conn:` do?
  Why is history never deleted?

## 4. kev_client.py
* **Problem:** get a trustworthy KEV catalog and survive network problems.
* **Input -> output:** URL (or saved bytes) -> validated `KevSnapshot` stored in files and database; `RefreshResult`.
* **How:** `download_kev_json` (timeout, status check, size limit) -> `parse_kev_json` (structure checks, declared count
  equals actual count) -> save raw file atomically -> store in one transaction. Any `KevError` leaves stored data untouched;
  `refresh_kev` then returns the last valid snapshot labelled `cached` with its age, and `is_success` is False.
* **Functions:** `download_kev_json`, `parse_kev_json`, `store_snapshot_bytes`, `refresh_kev`, `kev_status`, `snapshot_age`.
* **Connects to:** database (storage), app (KEV page), demo (loads fixture files through the same validation).
* **Test:** `python -m pytest tests/test_kev_client.py -v` (HTTP is mocked; no internet needed).
* **Professor may ask:** How do you detect an incomplete download? (count mismatch.) Why a timeout? (a hung request would freeze
  the app.) What if CISA is down? How do you know cached data is old?

## 5. change_detector.py
* **Problem:** decide, reproducibly and explainably, which findings matter because of KEV and what changed.
* **Input -> output:** scan runs, findings, current and previous KEV indexes -> list of `ChangeResult` rows.
* **How:** see section 5 of `ARCHITECTURE.md`. Pure functions, deterministic sorting.
* **Functions:** `analyze`, `find_not_observed`, `match_kev`, `diff_catalogs`, `latest_run_per_group`.
* **Connects to:** workflow.run_analysis feeds it; reporting formats its output.
* **Test:** `python -m pytest tests/test_change_detector.py -v`
* **Professor may ask:** Why is "not observed" not "fixed"? Why must scans be in the same comparable group? How is a
  catalog change detected without a new scan? Why no risk score? What are the false-positive/false-negative risks?

## 6. workflow.py
* **Problem:** avoid duplicating "read the database then run the rules" logic.
* **Functions:** `import_scan` (validate, keep the original file, store), `run_analysis` (choose snapshot and predecessor, run rules).
* **Test:** `python -m pytest tests/test_workflow_and_demo.py -v`

## 7. reporting.py
* **Problem:** present and export results.
* **Functions:** `results_to_dataframe`, `filter_results`, `dataframe_to_csv_bytes`, `validation_report_dataframe`, `format_text_report`.
* **Test:** `python -m pytest tests/test_reporting.py -v`
* **Professor may ask:** Why a BOM in the CSV? (so Excel on Windows reads UTF-8 correctly.)

## 8. app.py
* **Problem:** a usable interface. Contains only page drawing and calls into `src/`.
* **How:** sidebar chooses data set and page; each page is a function. Success messages appear only when
  `result.is_success` is true; cached/failed outcomes show warnings or errors.
* **Test:** `python -m pytest tests/test_app_smoke.py -v` (Streamlit's `AppTest` renders every page).

## 9. demo.py
* **Problem:** a repeatable, clearly synthetic scenario for tests and presentation.
* **Run:** `python -m src.demo`. **Test:** the acceptance tests in `tests/test_workflow_and_demo.py`.

## 10. epss_client.py (optional)
* **Problem:** show extra context (probability of exploitation) without replacing KEV.
* **How:** validated API response, cache table, `source` live/cached, `stale` after 2 days.
* **Test:** `python -m pytest tests/test_epss_client.py -v`
* **Professor may ask:** EPSS vs KEV? (EPSS = predicted probability; KEV = documented exploitation.)
