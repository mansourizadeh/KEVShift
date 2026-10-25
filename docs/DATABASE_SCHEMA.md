# KEVShift Database Schema

SQLite file: `data/kevshift.db` (demo: `data/demo/kevshift.db`). Created by `database.init_schema`.
Foreign keys are switched on for every connection (`PRAGMA foreign_keys = ON`). Timestamps are UTC text
(`YYYY-MM-DDTHH:MM:SSZ`), which sort correctly as plain text.

```
scan_runs 1 ---- * findings
kev_snapshots 1 ---- * kev_entries
kev_snapshots 1 ---- * kev_checks
events  -> optionally points at a scan run and/or a snapshot
epss_cache  (independent, optional)
```

## Tables

### scan_runs: one row per imported CSV file
| Column | Purpose |
|---|---|
| id (PK) | Identifier |
| source_filename | Original file name (base name only) |
| file_sha256 (UNIQUE) | Fingerprint of the file content; stops the same file being imported twice |
| stored_path | Where the original file copy is kept (`data/uploads/`) for auditability |
| scan_date | Latest scan_date among accepted rows |
| comparable_group | User label saying which scans may be compared (NULL = unlabelled) |
| imported_at | When the import happened (UTC) |
| rows_total / rows_accepted / rows_rejected / rows_duplicate | Import statistics |

### findings: one row per accepted finding
| Column | Purpose |
|---|---|
| id (PK), scan_run_id (FK -> scan_runs) | Identity and owning import |
| asset_name, cve_id, scan_date, finding_status | The finding itself (CVE normalized, status lower-case) |
| source_row | Row number in the uploaded file, for tracing |
| UNIQUE(scan_run_id, asset_name, cve_id) | One finding per asset/CVE per import |

### kev_snapshots: one row per distinct catalog content
| Column | Purpose |
|---|---|
| id (PK) | Identifier |
| catalog_version, date_released | Metadata from the feed |
| retrieved_at | When this content was first retrieved (UTC) |
| source_url | The official URL, or `synthetic-fixture:` / `uploaded-file:` for offline loads |
| entry_count | Number of entries |
| stored_path | Saved copy of the raw JSON (`data/kev_snapshots/`) |
| content_sha256 (UNIQUE) | Fingerprint; an unchanged feed does not create a second snapshot |

### kev_entries: the vulnerabilities in each snapshot
PRIMARY KEY (snapshot_id, cve_id). Columns: vendor_project, product, vulnerability_name, date_added,
short_description, required_action, due_date, known_ransomware_use. Deleting a snapshot would delete its
entries (ON DELETE CASCADE), but KEVShift never deletes history.

### kev_checks: one row per successful KEV check
Records every successful check (even when the catalog was unchanged): snapshot_id (FK), checked_at, source_url.
The newest row gives "last successful refresh" and the cache age in the dashboard.

### events: audit log
occurred_at, event_type (`scan_imported`, `kev_snapshot_added`, `kev_checked_unchanged`, `kev_refresh_failed`),
optional scan_run_id / snapshot_id, message. Shown in the History page.

### epss_cache: optional EPSS values
cve_id (PK), epss, percentile, score_date, fetched_at. Supplementary only.

## Indexes
`findings(scan_run_id)`, `findings(cve_id)`, `scan_runs(comparable_group, scan_date)`, `kev_entries(cve_id)`,
`kev_snapshots(retrieved_at)`, `kev_checks(checked_at)`, `events(occurred_at)`: they speed up the lookups the
app performs most often.

## Transactions
`store_scan_run` (scan run + findings + event) and `store_kev_snapshot` (snapshot + entries + check + event)
each run inside `with conn:`: either every row is written or none is. A test deliberately breaks an import halfway
and verifies nothing is left behind.

## Reproducing a flag
A flag is a pure function of: the scan runs and findings, the selected snapshot's entries, and the previous
snapshot's entries. All are stored, so `workflow.run_analysis(conn, snapshot_id)` gives the same rows every time.
