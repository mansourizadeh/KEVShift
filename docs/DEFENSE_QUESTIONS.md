# Likely Defense Questions and Accurate Answers

**1. What problem does KEVShift solve?**
A scan report is a snapshot in time, while the KEV catalog changes. KEVShift keeps both histories so it can show that a
previously reported CVE has since been added to KEV, even with no new scan, and explains the finding.

**2. Is it a vulnerability scanner?**
No. It never scans, exploits or authenticates; it analyzes CSV results the user already has.

**3. What is KEV, and what does a KEV match prove?**
CISA's catalog of vulnerabilities with documented exploitation in the wild. A match proves only that exploitation of that
CVE has been documented somewhere. It does not prove that your asset was attacked or is exploitable.

**4. What is the difference between KEV and EPSS?**
KEV: documented exploitation (a fact record). EPSS: a model's estimated probability of exploitation in the next 30 days.
EPSS here is optional, supplementary and never replaces KEV detection.

**5. How do you detect a newly added KEV entry?**
Take the selected snapshot and the snapshot stored just before it; a CVE in the first but not the second is newly added.
Findings are matched to it by exact normalized CVE ID. If no earlier snapshot exists, the row is "First observed KEV
match", not "newly added".

**6. How can the catalog change without a new scan?**
The rules take (latest scan, snapshot, previous snapshot) as independent inputs. Storing a new snapshot changes the
snapshot inputs only. The acceptance test shows the same 1 October scan going from "No KEV match" to "Newly added".

**7. Why not say a missing finding is "fixed"?**
Absence can result from different scan coverage, credentials, configuration, timing or a renamed asset. KEVShift labels it
"Not observed in latest scan", compares only scans in the same user-defined comparable group, and recommends re-scanning
or checking manually. A test asserts the words fixed/remediated/resolved/patched never appear.

**8. How do you make sure matching is exact?**
CVE IDs are normalized, then looked up in a dictionary keyed by the full ID. `CVE-2099-0001` cannot match
`CVE-2099-00011`. Tests and the demo data include this trap.

**9. Why normalize CVE IDs and why `[0-9]` instead of `\d`?**
Normalization (trim, upper case) makes equal IDs compare equal. `\d` matches non-ASCII digits (for example Persian digits),
which are not valid in CVE IDs.

**10. What happens with invalid rows?**
They are rejected with every reason, shown on screen, counted, and downloadable as a validation report. Nothing is silently
discarded and the app does not crash.

**11. What happens with duplicate rows?**
The second occurrence of the same (asset, CVE) in one file is ignored, counted and reported; if its status differed, the
report says so.

**12. Why SQLite and why snapshots?**
SQLite is built into Python, needs no server or admin rights and stores everything in one file. Snapshots (immutable
copies) make results reproducible: the same stored data always produces the same rows.

**13. What is a transaction and where do you use it?**
A group of writes that all succeed or all fail (`with conn:`). Storing a scan run with its findings and storing a snapshot
with its entries are transactions; a test breaks an import halfway and verifies nothing remains.

**14. How do you handle network failure?**
Timeout, status-code check, validation before saving, and fallback to the last valid snapshot. The result object has
`is_success` false for failures, and the UI shows a warning or error, never a success message. The cache age is displayed.

**15. How do you prevent an invalid response from replacing good data?**
The JSON is validated (structure, declared count equals actual count, valid CVE IDs and dates) before any file or row is
written. Duplicate content is detected by SHA-256 and does not create a duplicate snapshot.

**16. Security measures?**
Parameterized SQL, uploaded content never executed, spreadsheet-formula neutralization in exported CSV, upload size limit,
file-name sanitizing, no secrets stored, network limited to two public sources.

**17. Why not compute a risk score?**
An unexplained number invites false confidence. Explicit categories with stated reasons are easier to audit and defend.

**18. What is a "comparable scan"?**
Scans the user labels with the same group (same scope, profile and credentials). Only these are compared for "not
observed". The tool cannot verify comparability itself, which is a stated limitation.

**19. How did you test it?**
128 pytest tests with synthetic fixtures and mocked HTTP, covering validation, parsing, rules, persistence, offline mode,
failed refresh, reproducibility, reports, EPSS and dashboard rendering. Run with `python -m pytest`.

**20. What are the main limitations and future work?**
User-defined comparability, CVE-ID-only matching, asset identity by name, single user. Future: Nessus adapter, CVSS
enrichment, scheduled refresh, asset aliasing.

**21. Which parts are not verified?**
Real CISA downloads were not exercised in the automated tests (mocked on purpose); the live feed structure is assumed to
match the documented fields (`catalogVersion`, `dateReleased`, `count`, `vulnerabilities[].cveID/dateAdded`). Run the
refresh button once with internet to confirm it on your machine before the defense.
