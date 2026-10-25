# Glossary

## Cybersecurity
* **Vulnerability:** a weakness in software or hardware that could be abused.
* **CVE (Common Vulnerabilities and Exposures):** a public ID for a vulnerability, format `CVE-YYYY-NNNN`.
* **KEV (Known Exploited Vulnerabilities):** CISA's catalog of CVEs with documented exploitation in the wild.
* **CISA:** the US Cybersecurity and Infrastructure Security Agency, publisher of KEV.
* **EPSS:** Exploit Prediction Scoring System (FIRST); estimated probability of exploitation soon. Not proof.
* **CVSS:** a severity score of a vulnerability (not implemented here).
* **Asset:** a computer, server or device that appears in a scan.
* **Finding:** one report that an asset has a given CVE.
* **Scanner:** a tool that probes systems for vulnerabilities (KEVShift is not one).
* **Remediation / mitigation:** fixing / reducing the impact of a vulnerability.
* **False positive:** a finding that is a scanner mistake.
* **Accepted risk:** a decision to live with a vulnerability.
* **Exploitation in the wild:** use of a vulnerability in real attacks.
* **Nessus:** a commercial scanner whose CSV export a future adapter could read.

## Programming and data
* **Python:** the programming language used.
* **Module / package:** a Python file / a folder of modules (`src`).
* **Function:** reusable named block of code. **Pure function:** output depends only on its inputs, no side effects.
* **Type hint:** annotation such as `-> str` documenting expected types.
* **Dataclass:** a simple class that just holds data (`models.py`).
* **Regular expression (regex):** a pattern language for matching text (`re` module).
* **CSV:** comma-separated text table. **JSON:** text format of objects and lists.
* **pandas / DataFrame:** library and table type used for CSV work and reports.
* **UTF-8 / BOM:** text encoding / a marker Excel adds at the start of UTF-8 files.
* **API:** a web address designed to be called by programs. **HTTP request/status code:** a message to a server and its
  result number (200 OK, 404 not found, 500 server error). **Timeout:** the longest we wait for an answer.
* **SQLite / SQL:** file database / the language to query it. **Table, row, column:** database structure.
* **Primary key:** unique row identifier. **Foreign key:** a column pointing to a row in another table.
* **UNIQUE constraint:** the database refuses duplicates. **Index:** structure that speeds up lookups.
* **Parameterized query:** SQL with `?` placeholders; values passed separately; prevents SQL injection.
* **Transaction:** all-or-nothing group of database changes. **Rollback:** undo after an error.
* **Hash (SHA-256):** a fingerprint of data; identical data gives the same hash.
* **Atomic write:** write to a temporary file then rename, so a crash never leaves a half-written file.
* **Snapshot:** a frozen copy of the KEV catalog (or data) at one time.
* **Normalization:** converting values to one standard form.
* **Deduplication:** removing repeated entries.
* **Cache:** a saved copy used when fresh data is unavailable. **Stale:** a cache older than the allowed age.
* **Idempotent:** repeating the operation gives the same result (the demo loader is).
* **Mock:** a fake object in tests replacing the internet.
* **Fixture:** prepared test data or setup. **Unit test / pytest / assert:** small automated check / the tool / the check statement.
* **Streamlit:** Python library for local web dashboards. **Virtual environment:** isolated package folder for one project.
* **CSV injection:** a cell starting with `=`, `+`, `-` or `@` that a spreadsheet may run as a formula.
* **SQL injection:** malicious text that changes a query's meaning when pasted into SQL.
* **UTC:** the universal time standard used for stored timestamps.
* **Git / GitHub:** version control tool / website hosting repositories.
